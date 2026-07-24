// Package http is the OpenAI-shaped HTTP transport. Accepts requests,
// resolves the virtual key to a Principal, translates ingress wire to
// canonical Request, dispatches to Engine, translates the canonical
// Response back to OpenAI wire.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"policyd/internal/api"
	"policyd/internal/auth"
	"policyd/internal/obs/log"
	"policyd/internal/obs/meter"
)

const APIVersion = api.TransportAPIVersion

// Config wires the transport.
type Config struct {
	Listen         string
	AdminListen    string
	MaxBodyBytes   int64
	RequestTimeout time.Duration
	Auth           *auth.Store
	Logger         *log.Logger
	Meter          api.Meter
	MetricsHandler http.Handler // for /metrics on the admin listener
	AdminHandler   http.Handler // for /admin on the admin listener (optional)
}

// Transport implements api.Transport.
type Transport struct {
	cfg     Config
	server  *http.Server
	admin   *http.Server
	engine  api.Engine
}

func New(cfg Config) *Transport {
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 4 << 20
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 30 * time.Second
	}
	return &Transport{cfg: cfg}
}

func (t *Transport) Name() string       { return "http" }
func (t *Transport) APIVersion() string { return APIVersion }

// Serve binds both the traffic and admin ports and runs until ctx is done.
func (t *Transport) Serve(ctx context.Context, engine api.Engine) error {
	t.engine = engine

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat/completions", t.handleChat)
	mux.HandleFunc("/v1/messages", t.handleMessages)
	mux.HandleFunc("/healthz", t.handleHealth)

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/healthz", t.handleHealth)
	if t.cfg.MetricsHandler != nil {
		adminMux.Handle("/metrics", t.cfg.MetricsHandler)
	}
	if t.cfg.AdminHandler != nil {
		adminMux.Handle("/admin", t.cfg.AdminHandler)
		adminMux.Handle("/admin/", t.cfg.AdminHandler)
	}

	t.server = &http.Server{
		Addr:              t.cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	t.admin = &http.Server{
		Addr:              t.cfg.AdminListen,
		Handler:           adminMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		ln, err := net.Listen("tcp", t.cfg.Listen)
		if err != nil {
			errCh <- fmt.Errorf("bind traffic %s: %w", t.cfg.Listen, err)
			return
		}
		t.cfg.Logger.Info("transport.listening", log.Fields{"addr": ln.Addr().String(), "kind": "traffic"})
		if err := t.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	go func() {
		defer wg.Done()
		ln, err := net.Listen("tcp", t.cfg.AdminListen)
		if err != nil {
			errCh <- fmt.Errorf("bind admin %s: %w", t.cfg.AdminListen, err)
			return
		}
		t.cfg.Logger.Info("transport.listening", log.Fields{"addr": ln.Addr().String(), "kind": "admin"})
		if err := t.admin.Serve(ln); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.server.Shutdown(shutCtx)
	_ = t.admin.Shutdown(shutCtx)
	wg.Wait()
	return nil
}

// -------- Handlers --------

func (t *Transport) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (t *Transport) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	principal, ok := t.authenticate(w, r)
	if !ok {
		return
	}
	body, ok := t.readBody(w, r)
	if !ok {
		return
	}
	var inReq inRequest
	if err := json.Unmarshal(body, &inReq); err != nil {
		t.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if inReq.Model == "" || len(inReq.Messages) == 0 {
		t.writeError(w, http.StatusBadRequest, "invalid_request", "missing model or messages")
		return
	}

	canonReq, err := t.toCanonical(inReq, principal)
	if err != nil {
		t.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Enforce request timeout.
	ctx, cancel := context.WithTimeout(r.Context(), t.cfg.RequestTimeout)
	defer cancel()
	ctx = log.WithRequestID(ctx, string(canonReq.ID))
	ctx = log.WithEndpoint(ctx, "/v1/chat/completions")

	t.cfg.Meter.Counter(meter.MetricRequestsTotal, api.Dims{
		meter.DimMode: canonReq.Mode.String(),
	}).Inc()

	resp, err := t.engine.Handle(ctx, canonReq)
	if err != nil {
		t.cfg.Logger.WarnCtx(ctx, "engine.error", log.Fields{"err": err.Error()})
		t.writeError(w, statusForError(err), errorClass(err), err.Error())
		return
	}

	if resp.Mode == api.ModeStreaming {
		t.writeStream(w, r, ctx, resp)
	} else {
		t.writeUnary(w, resp)
	}
}

// authenticate accepts either Authorization: Bearer <key> (OpenAI-style)
// or x-api-key: <key> (Anthropic-style). Both must be sk-gw-* virtual keys.
func (t *Transport) authenticate(w http.ResponseWriter, r *http.Request) (api.Principal, bool) {
	key := auth.ExtractBearer(r.Header.Get("Authorization"))
	if key == "" {
		key = r.Header.Get("x-api-key")
	}
	if key == "" {
		t.writeError(w, http.StatusUnauthorized, "unauthorized", "missing api key")
		return api.Principal{}, false
	}
	p, err := t.cfg.Auth.Resolve(key, time.Now())
	if err != nil {
		t.cfg.Meter.Counter(meter.MetricAuthFailuresTotal, api.Dims{}).Inc()
		t.writeError(w, http.StatusUnauthorized, "unauthorized", "invalid key")
		return api.Principal{}, false
	}
	return p, true
}

func (t *Transport) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, t.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.writeError(w, http.StatusRequestEntityTooLarge, "request_too_large", err.Error())
		return nil, false
	}
	return body, true
}

func (t *Transport) toCanonical(in inRequest, p api.Principal) (*api.Request, error) {
	mode := api.ModeUnary
	if in.Stream {
		mode = api.ModeStreaming
	}
	messages := make([]api.Message, 0, len(in.Messages))
	for i, m := range in.Messages {
		text, err := extractContent(m.Content)
		if err != nil {
			return nil, fmt.Errorf("message[%d]: %v", i, err)
		}
		messages = append(messages, api.Message{
			Role: parseRole(m.Role),
			Parts: []api.Content{{
				Modality: api.ModText,
				Bytes:    []byte(text),
				Meta:     api.ContentMeta{Origin: api.OriginUserInput},
			}},
		})
	}
	req := &api.Request{
		APIVersion: "v1.0",
		Principal:  p,
		Mode:       mode,
		Messages:   messages,
	}
	req.Extensions.SetOpenAI(&api.OpenAIExt{
		Model:       in.Model,
		Temperature: in.Temperature,
		TopP:        in.TopP,
		MaxTokens:   in.MaxTokens,
		Stop:        in.Stop,
	})
	return req, nil
}

// extractContent handles the OpenAI content shape which may be a plain
// string or an array of typed parts. Phase 1 supports strings only.
func extractContent(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	// Try array of {type,text}.
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Type == "text" {
				b.WriteString(p.Text)
			} else {
				return "", fmt.Errorf("unsupported content part type %q in Phase 1", p.Type)
			}
		}
		return b.String(), nil
	}
	return "", errors.New("content must be a string or array of text parts")
}

func (t *Transport) writeUnary(w http.ResponseWriter, resp *api.Response) {
	if resp.Full == nil {
		t.writeError(w, http.StatusInternalServerError, "internal", "empty response")
		return
	}
	text := concatText(resp.Full.Parts)
	out := outResponse{
		ID:      "policyd-" + string(resp.RequestID),
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   resp.Provider.Model,
		Choices: []outChoice{{
			Index: 0,
			Message: outChoiceMessage{
				Role:    "assistant",
				Content: text,
			},
			FinishReason: "stop",
		}},
		Usage: outUsage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (t *Transport) writeStream(w http.ResponseWriter, r *http.Request, ctx context.Context, resp *api.Response) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.writeError(w, http.StatusInternalServerError, "internal", "streaming unsupported by writer")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	for chunk := range resp.Chunks {
		if chunk.Err != nil {
			// Emit a final error event and stop.
			payload, _ := json.Marshal(map[string]string{"error": chunk.Err.Error()})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
			return
		}
		out := outStreamChunk{
			ID:      "policyd-" + string(resp.RequestID),
			Object:  "chat.completion.chunk",
			Created: time.Now().Unix(),
			Model:   resp.Provider.Model,
			Choices: []outStreamChoice{{
				Index: 0,
				Delta: outStreamDelta{
					Content: string(chunk.Delta.Bytes),
				},
			}},
		}
		if chunk.Finish != nil {
			out.Choices[0].FinishReason = chunk.Finish.String()
		}
		buf, err := json.Marshal(out)
		if err != nil {
			return
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", buf); err != nil {
			return
		}
		flusher.Flush()
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
	_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func (t *Transport) writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"type":    code,
			"message": msg,
		},
	})
}

// -------- helpers --------

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

func concatText(parts []api.Content) string {
	var b strings.Builder
	for _, p := range parts {
		if p.Modality == api.ModText {
			b.Write(p.Bytes)
		}
	}
	return b.String()
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, api.ErrAuthFailed):
		return http.StatusUnauthorized
	case errors.Is(err, api.ErrPolicyBlocked), errors.Is(err, api.ErrDLPRedaction):
		return http.StatusForbidden
	case errors.Is(err, api.ErrBudgetExceeded):
		return http.StatusPaymentRequired
	case errors.Is(err, api.ErrRateLimit):
		return http.StatusTooManyRequests
	case errors.Is(err, api.ErrUnavailable), errors.Is(err, api.ErrProvider):
		return http.StatusBadGateway
	case errors.Is(err, api.ErrConfigInvalid), errors.Is(err, api.ErrCapMismatch):
		return http.StatusBadRequest
	case errors.Is(err, api.ErrClientAbort):
		return 499 // client closed request
	}
	return http.StatusInternalServerError
}

func errorClass(err error) string {
	switch {
	case errors.Is(err, api.ErrAuthFailed):
		return "unauthorized"
	case errors.Is(err, api.ErrPolicyBlocked):
		return "policy_blocked"
	case errors.Is(err, api.ErrBudgetExceeded):
		return "budget_exceeded"
	case errors.Is(err, api.ErrRateLimit):
		return "rate_limit"
	case errors.Is(err, api.ErrUnavailable):
		return "upstream_unavailable"
	case errors.Is(err, api.ErrProvider):
		return "provider_error"
	}
	return "internal"
}
