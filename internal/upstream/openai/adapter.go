// Package openai implements api.Upstream for OpenAI Chat Completions.
//
// Wire version: 2024-08-06 (Chat Completions v1). Newer response formats
// (Responses API) will land as a separate adapter.
package openai

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
	"time"

	"policyd/internal/api"
)

const APIVersion = api.UpstreamAPIVersion

// Config wires an OpenAI upstream instance.
type Config struct {
	ID         api.UpstreamID
	BaseURL    string
	APIKey     string
	Model      string
	MaxContext int
	CostIn     float64 // dollars per 1K input tokens
	CostOut    float64 // dollars per 1K output tokens
}

// Adapter satisfies api.Upstream.
type Adapter struct {
	cfg    Config
	client *http.Client

	// Health is tracked as a coarse counter of recent successes/failures.
	recentErrors atomic.Int32
	recentTotal  atomic.Int32
	lastCheck    atomic.Int64
}

// New returns an OpenAI adapter with a policy-hardened HTTP client.
func New(cfg Config, client *http.Client) *Adapter {
	return &Adapter{cfg: cfg, client: client}
}

func (a *Adapter) APIVersion() string   { return APIVersion }
func (a *Adapter) ID() api.UpstreamID   { return a.cfg.ID }
func (a *Adapter) Kind() api.UpstreamKind { return api.KindOpenAI }
func (a *Adapter) Caps() api.Caps {
	return api.Caps{
		Modalities: api.ModalitySet(0).With(api.ModText),
		Tools:      api.ToolFunctionCalling | api.ToolStrictSchema | api.ToolParallelCalls,
		Streaming:  api.StreamSSE,
		MaxContext: a.cfg.MaxContext,
		JSONMode:   api.JSONStrictSchema,
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
	url := strings.TrimRight(a.cfg.BaseURL, "/") + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		a.recentErrors.Add(1)
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")

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
		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		return nil, fmt.Errorf("%w: status %d: %s", api.ErrProvider, resp.StatusCode, string(buf))
	}

	if r.Mode == api.ModeStreaming {
		return a.readStream(ctx, resp, r)
	}
	return a.readUnary(resp, r)
}

func (a *Adapter) buildRequestBody(r *api.Request) ([]byte, error) {
	model := a.cfg.Model
	if ext, ok := r.Extensions.OpenAI(); ok && ext.Model != "" {
		model = ext.Model
	}
	msgs := make([]wireMessage, 0, len(r.Messages))
	for _, m := range r.Messages {
		msgs = append(msgs, wireMessage{
			Role:    roleString(m.Role),
			Content: concatText(m.Parts),
		})
	}
	req := wireRequest{
		Model:    model,
		Messages: msgs,
		Stream:   r.Mode == api.ModeStreaming,
	}
	if ext, ok := r.Extensions.OpenAI(); ok {
		req.Temperature = ext.Temperature
		req.TopP = ext.TopP
		req.MaxTokens = ext.MaxTokens
		req.Stop = ext.Stop
	}
	return json.Marshal(req)
}

func (a *Adapter) readUnary(resp *http.Response, r *api.Request) (*api.Response, error) {
	defer resp.Body.Close()
	var w wireResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&w); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", api.ErrProvider, err)
	}
	if len(w.Choices) == 0 {
		return nil, fmt.Errorf("%w: empty choices", api.ErrProvider)
	}
	msg := api.Message{
		Role: parseRole(w.Choices[0].Message.Role),
		Parts: []api.Content{{
			Modality: api.ModText,
			Bytes:    []byte(w.Choices[0].Message.Content),
			Meta:     api.ContentMeta{Origin: api.OriginModelOutput},
		}},
	}
	return &api.Response{
		APIVersion: "v1.0",
		RequestID:  r.ID,
		Mode:       api.ModeUnary,
		Full:       &msg,
		Usage: api.Usage{
			InputTokens:  w.Usage.PromptTokens,
			OutputTokens: w.Usage.CompletionTokens,
			TotalTokens:  w.Usage.TotalTokens,
		},
		Provider: api.ProviderInfo{Upstream: a.cfg.ID, Kind: api.KindOpenAI, Model: w.Model},
	}, nil
}

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
			if !bytes.HasPrefix(line, []byte("data: ")) {
				continue
			}
			payload := bytes.TrimPrefix(line, []byte("data: "))
			if bytes.Equal(payload, []byte("[DONE]")) {
				return
			}
			var w wireStreamChunk
			if err := json.Unmarshal(payload, &w); err != nil {
				send(api.Chunk{Seq: seq, Err: fmt.Errorf("%w: chunk decode: %v", api.ErrProvider, err)})
				return
			}
			seq++
			if len(w.Choices) == 0 {
				continue
			}
			delta := w.Choices[0].Delta.Content
			out := api.Chunk{
				Seq: seq,
				Delta: api.Content{
					Modality: api.ModText,
					Bytes:    []byte(delta),
					Meta:     api.ContentMeta{Origin: api.OriginModelOutput},
				},
			}
			if w.Choices[0].FinishReason != "" {
				fr := parseFinishReason(w.Choices[0].FinishReason)
				out.Finish = &fr
			}
			if !send(out) {
				return
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
		Provider:   api.ProviderInfo{Upstream: a.cfg.ID, Kind: api.KindOpenAI, Model: a.cfg.Model},
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
	case api.RoleSystem:
		return "system"
	case api.RoleAssistant:
		return "assistant"
	case api.RoleTool:
		return "tool"
	}
	return "user"
}

func parseRole(s string) api.Role {
	switch s {
	case "system":
		return api.RoleSystem
	case "assistant":
		return api.RoleAssistant
	case "tool":
		return api.RoleTool
	}
	return api.RoleUser
}

func parseFinishReason(s string) api.FinishReason {
	switch s {
	case "stop":
		return api.FinishStop
	case "length":
		return api.FinishLength
	case "tool_calls":
		return api.FinishToolCalls
	case "content_filter":
		return api.FinishContentFilter
	}
	return api.FinishUnknown
}

// LastCheck records when Health was last consulted; used by tests.
func (a *Adapter) LastCheck() time.Time { return time.Unix(a.lastCheck.Load(), 0) }
