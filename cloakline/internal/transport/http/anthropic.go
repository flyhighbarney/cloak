package http

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"cloakline/internal/api"
	"cloakline/internal/obs/log"
	"cloakline/internal/obs/meter"
)

// handleMessages is the Anthropic Messages API-shaped ingress.
// Path: POST /v1/messages
func (t *Transport) handleMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"type":"error","error":{"type":"method_not_allowed"}}`, http.StatusMethodNotAllowed)
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
	var in antInRequest
	if err := json.Unmarshal(body, &in); err != nil {
		t.writeAntError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	if in.Model == "" || len(in.Messages) == 0 {
		t.writeAntError(w, http.StatusBadRequest, "invalid_request_error", "missing model or messages")
		return
	}
	if in.MaxTokens <= 0 {
		t.writeAntError(w, http.StatusBadRequest, "invalid_request_error", "max_tokens is required and must be > 0")
		return
	}

	canonReq, err := t.antToCanonical(in, principal)
	if err != nil {
		t.writeAntError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), t.cfg.RequestTimeout)
	defer cancel()
	ctx = log.WithRequestID(ctx, string(canonReq.ID))
	ctx = log.WithEndpoint(ctx, "/v1/messages")

	t.cfg.Meter.Counter(meter.MetricRequestsTotal, api.Dims{
		meter.DimMode: canonReq.Mode.String(),
	}).Inc()

	resp, err := t.engine.Handle(ctx, canonReq)
	if err != nil {
		t.cfg.Logger.WarnCtx(ctx, "engine.error", log.Fields{"err": err.Error(), "shape": "anthropic"})
		t.writeAntError(w, statusForError(err), antErrorType(err), err.Error())
		return
	}

	if resp.Mode == api.ModeStreaming {
		t.writeAntStream(w, r, ctx, resp)
	} else {
		t.writeAntUnary(w, resp)
	}
}

// antToCanonical translates an Anthropic Messages request into the canonical
// Request. `system` (string or blocks) and `messages` (with string or
// block-array content) are both accepted. AnthropicExt is populated so the
// upstream adapter can round-trip provider-specific fields.
func (t *Transport) antToCanonical(in antInRequest, p api.Principal) (*api.Request, error) {
	mode := api.ModeUnary
	if in.Stream {
		mode = api.ModeStreaming
	}
	systemText, err := extractAntTextField(in.System)
	if err != nil {
		return nil, fmt.Errorf("system: %v", err)
	}
	messages := make([]api.Message, 0, len(in.Messages)+1)
	if systemText != "" {
		messages = append(messages, api.Message{
			Role: api.RoleSystem,
			Parts: []api.Content{{
				Modality: api.ModText,
				Bytes:    []byte(systemText),
				Meta:     api.ContentMeta{Origin: api.OriginSystem},
			}},
		})
	}
	for i, m := range in.Messages {
		text, err := extractAntTextField(m.Content)
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
	req.Extensions.SetAnthropic(&api.AnthropicExt{
		Model:         in.Model,
		SystemText:    systemText,
		MaxTokens:     in.MaxTokens,
		Temperature:   in.Temperature,
		TopP:          in.TopP,
		TopK:          in.TopK,
		StopSequences: in.StopSequences,
	})
	return req, nil
}

// extractAntTextField accepts a JSON value that is either a string OR an
// array of `{type: "text", text: "..."}` blocks (Anthropic allows both).
func extractAntTextField(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	// Fall back to array of typed blocks.
	var blocks []antInContentBlock
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Type == "text" {
				b.WriteString(blk.Text)
			} else {
				return "", fmt.Errorf("unsupported content block type %q in Phase 1", blk.Type)
			}
		}
		return b.String(), nil
	}
	return "", errors.New("must be a string or array of text blocks")
}

// writeAntUnary emits the Anthropic unary response shape.
func (t *Transport) writeAntUnary(w http.ResponseWriter, resp *api.Response) {
	if resp.Full == nil {
		t.writeAntError(w, http.StatusInternalServerError, "api_error", "empty response")
		return
	}
	text := concatText(resp.Full.Parts)
	out := antOutResponse{
		ID:    "cloakline-" + string(resp.RequestID),
		Type:  "message",
		Role:  "assistant",
		Model: resp.Provider.Model,
		Content: []antOutContentBlock{{
			Type: "text",
			Text: text,
		}},
		StopReason: "end_turn",
		Usage: antOutUsage{
			InputTokens:  resp.Usage.InputTokens,
			OutputTokens: resp.Usage.OutputTokens,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// writeAntStream synthesizes Anthropic's typed SSE event sequence:
//
//	message_start → content_block_start → content_block_delta* →
//	content_block_stop → message_delta → message_stop
//
// We buffer nothing — each canonical chunk becomes one content_block_delta
// event on the wire.
func (t *Transport) writeAntStream(w http.ResponseWriter, r *http.Request, ctx context.Context, resp *api.Response) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.writeAntError(w, http.StatusInternalServerError, "api_error", "streaming unsupported by writer")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	msgID := "cloakline-" + string(resp.RequestID)

	writeEvent := func(name string, payload any) bool {
		buf, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, buf); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}

	// 1. message_start
	if !writeEvent("message_start", antEvMessageStart{
		Type: "message_start",
		Message: antEvMessageStartM{
			ID:    msgID,
			Type:  "message",
			Role:  "assistant",
			Model: resp.Provider.Model,
			Usage: antOutUsage{},
		},
	}) {
		return
	}

	// 2. content_block_start (index 0)
	if !writeEvent("content_block_start", antEvContentBlockStart{
		Type:  "content_block_start",
		Index: 0,
		ContentBlock: antOutContentBlock{
			Type: "text",
			Text: "",
		},
	}) {
		return
	}

	// 3. content_block_delta events per chunk.
	stopReason := "end_turn"
	var lastUsage antOutUsage
	for chunk := range resp.Chunks {
		if chunk.Err != nil {
			// Emit the error as a text-ish message and terminate cleanly.
			_ = writeEvent("error", map[string]any{
				"type":  "error",
				"error": map[string]string{"type": "api_error", "message": chunk.Err.Error()},
			})
			return
		}
		if chunk.Finish != nil {
			stopReason = antStopReason(*chunk.Finish)
			if chunk.Usage != nil {
				lastUsage = antOutUsage{
					InputTokens:  chunk.Usage.InputTokens,
					OutputTokens: chunk.Usage.OutputTokens,
				}
			}
			continue
		}
		if len(chunk.Delta.Bytes) == 0 {
			continue
		}
		if !writeEvent("content_block_delta", antEvContentBlockDelta{
			Type:  "content_block_delta",
			Index: 0,
			Delta: antEvTextDelta{
				Type: "text_delta",
				Text: string(chunk.Delta.Bytes),
			},
		}) {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}

	// 4. content_block_stop
	if !writeEvent("content_block_stop", antEvContentBlockStop{
		Type:  "content_block_stop",
		Index: 0,
	}) {
		return
	}

	// 5. message_delta with terminal stop_reason + usage
	if !writeEvent("message_delta", antEvMessageDelta{
		Type:  "message_delta",
		Delta: antEvMessageDeltaD{StopReason: stopReason},
		Usage: lastUsage,
	}) {
		return
	}

	// 6. message_stop
	_ = writeEvent("message_stop", antEvMessageStop{Type: "message_stop"})
}

// writeAntError emits an Anthropic-shaped error envelope.
func (t *Transport) writeAntError(w http.ResponseWriter, status int, kind, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "error",
		"error": map[string]string{
			"type":    kind,
			"message": msg,
		},
	})
}

// antErrorType projects canonical errors into Anthropic's error-type vocabulary.
func antErrorType(err error) string {
	switch {
	case errors.Is(err, api.ErrAuthFailed):
		return "authentication_error"
	case errors.Is(err, api.ErrPolicyBlocked), errors.Is(err, api.ErrDLPRedaction), errors.Is(err, api.ErrDLPBlocked):
		return "permission_error"
	case errors.Is(err, api.ErrBudgetExceeded):
		return "billing_error"
	case errors.Is(err, api.ErrRateLimit):
		return "rate_limit_error"
	case errors.Is(err, api.ErrUnavailable), errors.Is(err, api.ErrProvider):
		return "overloaded_error"
	case errors.Is(err, api.ErrConfigInvalid), errors.Is(err, api.ErrCapMismatch):
		return "invalid_request_error"
	}
	return "api_error"
}

func antStopReason(f api.FinishReason) string {
	switch f {
	case api.FinishLength:
		return "max_tokens"
	case api.FinishToolCalls:
		return "tool_use"
	case api.FinishStop:
		return "end_turn"
	}
	return "end_turn"
}

