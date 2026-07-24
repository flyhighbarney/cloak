// Package anthropic implements api.Upstream for the Anthropic Messages API.
//
// Wire version pinned to 2023-06-01 (stable). Override per-request via
// AnthropicExt.AnthropicVersion when a newer model requires it.
package anthropic

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"policyd/internal/api"
)

const (
	APIVersion              = api.UpstreamAPIVersion
	DefaultAnthropicVersion = "2023-06-01"
	DefaultMaxTokens        = 1024
)

// Config wires an Anthropic upstream instance.
type Config struct {
	ID         api.UpstreamID
	BaseURL    string
	APIKey     string
	Model      string
	MaxContext int
	CostIn     float64
	CostOut    float64
}

// Adapter satisfies api.Upstream.
type Adapter struct {
	cfg    Config
	client *http.Client

	recentErrors atomic.Int32
	recentTotal  atomic.Int32
}

func New(cfg Config, client *http.Client) *Adapter {
	return &Adapter{cfg: cfg, client: client}
}

func (a *Adapter) APIVersion() string     { return APIVersion }
func (a *Adapter) ID() api.UpstreamID     { return a.cfg.ID }
func (a *Adapter) Kind() api.UpstreamKind { return api.KindAnthropic }
func (a *Adapter) Caps() api.Caps {
	return api.Caps{
		Modalities: api.ModalitySet(0).With(api.ModText).With(api.ModImage),
		Tools:      api.ToolFunctionCalling | api.ToolStrictSchema | api.ToolParallelCalls,
		Streaming:  api.StreamSSE,
		MaxContext: a.cfg.MaxContext,
		JSONMode:   api.JSONFreeform,
		Reasoning:  api.ReasoningHidden,
	}
}

func (a *Adapter) Health(ctx context.Context) api.HealthState {
	total := a.recentTotal.Load()
	if total < 10 {
		return api.HealthHealthy
	}
	errs := a.recentErrors.Load()
	rate := float64(errs) / float64(total)
	switch {
	case rate > 0.5:
		return api.HealthUnavailable
	case rate > 0.1:
		return api.HealthDegraded
	}
	return api.HealthHealthy
}

func (a *Adapter) Send(ctx context.Context, r *api.Request) (*api.Response, error) {
	a.recentTotal.Add(1)
	body, err := a.buildRequestBody(r)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(a.cfg.BaseURL, "/") + "/v1/messages"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		a.recentErrors.Add(1)
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.cfg.APIKey)
	req.Header.Set("anthropic-version", a.anthropicVersion(r))

	resp, err := a.client.Do(req)
	if err != nil {
		a.recentErrors.Add(1)
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %v", api.ErrClientAbort, ctx.Err())
		}
		return nil, fmt.Errorf("%w: %v", api.ErrUnavailable, err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		defer resp.Body.Close()
		a.recentErrors.Add(1)
		return nil, api.ErrRateLimit
	}
	if resp.StatusCode >= 500 {
		defer resp.Body.Close()
		a.recentErrors.Add(1)
		return nil, fmt.Errorf("%w: upstream status %d", api.ErrUnavailable, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		// Avoid echoing the provider's error body — it may include the API
		// key we sent (Anthropic mirrors it in some 401 responses).
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("%w: status %d", api.ErrProvider, resp.StatusCode)
	}

	if r.Mode == api.ModeStreaming {
		return a.readStream(ctx, resp, r)
	}
	return a.readUnary(resp, r)
}

func (a *Adapter) anthropicVersion(r *api.Request) string {
	if ext, ok := r.Extensions.Anthropic(); ok && ext.AnthropicVersion != "" {
		return ext.AnthropicVersion
	}
	return DefaultAnthropicVersion
}

func (a *Adapter) buildRequestBody(r *api.Request) ([]byte, error) {
	model := a.cfg.Model
	system := ""
	maxTok := DefaultMaxTokens
	var temp, topP *float32
	var topK *int
	var stops []string

	if ext, ok := r.Extensions.Anthropic(); ok {
		if ext.Model != "" {
			model = ext.Model
		}
		system = ext.SystemText
		if ext.MaxTokens > 0 {
			maxTok = ext.MaxTokens
		}
		temp = ext.Temperature
		topP = ext.TopP
		topK = ext.TopK
		stops = ext.StopSequences
	}

	// If system wasn't set in ext, pull it from any RoleSystem messages
	// and elide those messages from the wire request.
	var msgs []wireMessage
	for _, m := range r.Messages {
		if m.Role == api.RoleSystem {
			if system == "" {
				system = concatText(m.Parts)
			} else {
				system += "\n" + concatText(m.Parts)
			}
			continue
		}
		msgs = append(msgs, wireMessage{
			Role: roleString(m.Role),
			Content: []wireContentBlock{{
				Type: "text",
				Text: concatText(m.Parts),
			}},
		})
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("%w: no non-system messages", api.ErrConfigInvalid)
	}
	req := wireRequest{
		Model:         model,
		Messages:      msgs,
		System:        system,
		MaxTokens:     maxTok,
		Stream:        r.Mode == api.ModeStreaming,
		Temperature:   temp,
		TopP:          topP,
		TopK:          topK,
		StopSequences: stops,
	}
	return json.Marshal(req)
}

func (a *Adapter) readUnary(resp *http.Response, r *api.Request) (*api.Response, error) {
	defer resp.Body.Close()
	var w wireResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&w); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", api.ErrProvider, err)
	}
	var text strings.Builder
	for _, cb := range w.Content {
		if cb.Type == "text" {
			text.WriteString(cb.Text)
		}
	}
	msg := api.Message{
		Role: api.RoleAssistant,
		Parts: []api.Content{{
			Modality: api.ModText,
			Bytes:    []byte(text.String()),
			Meta:     api.ContentMeta{Origin: api.OriginModelOutput},
		}},
	}
	return &api.Response{
		APIVersion: "v1.0",
		RequestID:  r.ID,
		Mode:       api.ModeUnary,
		Full:       &msg,
		Usage: api.Usage{
			InputTokens:  w.Usage.InputTokens,
			OutputTokens: w.Usage.OutputTokens,
			TotalTokens:  w.Usage.InputTokens + w.Usage.OutputTokens,
		},
		Provider: api.ProviderInfo{Upstream: a.cfg.ID, Kind: api.KindAnthropic, Model: w.Model},
	}, nil
}

// readStream parses Anthropic's typed SSE event stream and projects it into
// canonical Chunk deltas. We only emit text deltas; tool events surface with
// a future T-ANTHRO-TOOLS.
func (a *Adapter) readStream(ctx context.Context, resp *http.Response, r *api.Request) (*api.Response, error) {
	ch := make(chan api.Chunk, 32)
	send := func(c api.Chunk) bool {
		select {
		case ch <- c:
			return true
		case <-ctx.Done():
			return false
		}
	}
	go func() {
		defer resp.Body.Close()
		defer close(ch)
		var seq uint64
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 {
				continue
			}
			// Ignore `event:` lines; the payload is on `data:` and carries `type`.
			if !bytes.HasPrefix(line, []byte("data: ")) {
				continue
			}
			payload := bytes.TrimPrefix(line, []byte("data: "))
			var ev wireStreamEvent
			if err := json.Unmarshal(payload, &ev); err != nil {
				send(api.Chunk{Seq: seq, Err: fmt.Errorf("%w: event decode: %v", api.ErrProvider, err)})
				return
			}
			switch ev.Type {
			case "content_block_delta":
				if ev.Delta == nil || ev.Delta.Type != "text_delta" || ev.Delta.Text == "" {
					continue
				}
				seq++
				if !send(api.Chunk{
					Seq: seq,
					Delta: api.Content{
						Modality: api.ModText,
						Bytes:    []byte(ev.Delta.Text),
						Meta:     api.ContentMeta{Origin: api.OriginModelOutput},
					},
				}) {
					return
				}
			case "message_delta":
				if ev.Delta != nil && ev.Delta.StopReason != "" {
					fr := parseStopReason(ev.Delta.StopReason)
					seq++
					if !send(api.Chunk{Seq: seq, Finish: &fr}) {
						return
					}
				}
			case "message_stop":
				return
			case "message_start", "content_block_start", "content_block_stop", "ping":
				// Ignore — no canonical mapping needed for Phase 1.
			}
		}
		if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
			send(api.Chunk{Err: fmt.Errorf("%w: stream read: %v", api.ErrUnavailable, err)})
		}
	}()
	return &api.Response{
		APIVersion: "v1.0",
		RequestID:  r.ID,
		Mode:       api.ModeStreaming,
		Chunks:     ch,
		Provider:   api.ProviderInfo{Upstream: a.cfg.ID, Kind: api.KindAnthropic, Model: a.cfg.Model},
	}, nil
}

// -------- helpers --------

func concatText(parts []api.Content) string {
	var b strings.Builder
	for _, p := range parts {
		if p.Modality == api.ModText {
			b.Write(p.Bytes)
		}
	}
	return b.String()
}

func roleString(r api.Role) string {
	switch r {
	case api.RoleAssistant:
		return "assistant"
	}
	// Anthropic Messages API allows only user and assistant.
	return "user"
}

func parseStopReason(s string) api.FinishReason {
	switch s {
	case "end_turn":
		return api.FinishStop
	case "max_tokens":
		return api.FinishLength
	case "stop_sequence":
		return api.FinishStop
	case "tool_use":
		return api.FinishToolCalls
	}
	return api.FinishUnknown
}
