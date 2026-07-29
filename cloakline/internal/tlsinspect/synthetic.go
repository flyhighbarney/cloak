package tlsinspect

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// The confirmation prompt cloakline renders as if the AI said it.
// Wording chosen so it's obvious this is not the real model.
const confirmPromptText = "🛡️ cloakline noticed what looks like a real password or card number in your message.\n\n" +
	"Reply with:\n" +
	"  y        — send this message through unmodified\n" +
	"  n        — cancel; cloakline will forget the flagged content\n" +
	"  session  — send this AND let future high-risk pastes through unmasked for the next hour\n\n" +
	"You have 60 seconds. If you don't answer, cloakline assumes cancel (safe default) and the flagged content is zeroized from memory. " +
	"Nothing about the flagged text has been logged or persisted."

// isConfirmSupportedHost reports whether the request host is one
// cloakline can synthesise a valid confirmation response for.
// Only these hosts enter the y/n confirmation flow.
func isConfirmSupportedHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	// Strip an optional :port suffix.
	if i := strings.IndexByte(h, ':'); i > 0 {
		h = h[:i]
	}
	switch h {
	case "api.anthropic.com", "api.openai.com":
		return true
	}
	return false
}

// writeSyntheticResponse dispatches to the correct format based on host.
func writeSyntheticResponse(w http.ResponseWriter, host string, wantStream bool, model, text string) error {
	h := strings.ToLower(host)
	if strings.HasPrefix(h, "api.openai.com") {
		return writeSyntheticOpenAIResponse(w, wantStream, model, text)
	}
	return writeSyntheticAnthropicResponse(w, wantStream, model, text)
}

// writeSyntheticAnthropicResponse writes a fake assistant reply
// directly to the HTTP response, formatted so Claude Code renders it
// inline like any other model output. The writer honours the client's
// stream=true flag when set — if so, emits the six-event SSE sequence
// Anthropic uses; otherwise emits a single JSON message.
//
// This function short-circuits the upstream call. It is only used by
// the confirmation state machine.
func writeSyntheticAnthropicResponse(w http.ResponseWriter, wantStream bool, model, text string) error {
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}
	msgID := fmt.Sprintf("msg_cloakline_%d", time.Now().UnixNano())

	if !wantStream {
		return writeSyntheticJSON(w, msgID, model, text)
	}
	return writeSyntheticSSE(w, msgID, model, text)
}

func writeSyntheticJSON(w http.ResponseWriter, id, model, text string) error {
	payload := map[string]any{
		"id":            id,
		"type":          "message",
		"role":          "assistant",
		"model":         model,
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Cloakline-Origin", "synthetic")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(payload)
}

func writeSyntheticSSE(w http.ResponseWriter, id, model, text string) error {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Cloakline-Origin", "synthetic")
	w.WriteHeader(http.StatusOK)

	f, _ := w.(http.Flusher)
	send := func(event string, data map[string]any) error {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return err
		}
		if f != nil {
			f.Flush()
		}
		return nil
	}

	if err := send("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id":    id,
			"type":  "message",
			"role":  "assistant",
			"model": model,
			"usage": map[string]any{"input_tokens": 0, "output_tokens": 0},
		},
	}); err != nil {
		return err
	}
	if err := send("content_block_start", map[string]any{
		"type":          "content_block_start",
		"index":         0,
		"content_block": map[string]any{"type": "text", "text": ""},
	}); err != nil {
		return err
	}
	if err := send("content_block_delta", map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	}); err != nil {
		return err
	}
	if err := send("content_block_stop", map[string]any{
		"type":  "content_block_stop",
		"index": 0,
	}); err != nil {
		return err
	}
	if err := send("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn"},
		"usage": map[string]any{"output_tokens": 0},
	}); err != nil {
		return err
	}
	return send("message_stop", map[string]any{"type": "message_stop"})
}

// requestWantsStream inspects a JSON request body and reports whether
// stream=true was set. Small and forgiving — if we can't parse, we
// assume non-stream (safer default).
func requestWantsStream(body []byte) bool {
	var probe struct {
		Stream bool `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return false
	}
	return probe.Stream
}

// writeSyntheticOpenAIResponse produces a fake assistant reply in
// OpenAI Chat Completions shape. Codex and other OpenAI-SDK clients
// render it inline the same way Claude Code does with Anthropic.
func writeSyntheticOpenAIResponse(w http.ResponseWriter, wantStream bool, model, text string) error {
	if model == "" {
		model = "gpt-4o-mini"
	}
	id := fmt.Sprintf("chatcmpl-cloakline-%d", time.Now().UnixNano())
	created := time.Now().Unix()

	if !wantStream {
		payload := map[string]any{
			"id":      id,
			"object":  "chat.completion",
			"created": created,
			"model":   model,
			"choices": []map[string]any{
				{
					"index":         0,
					"finish_reason": "stop",
					"message": map[string]any{
						"role":    "assistant",
						"content": text,
					},
				},
			},
			"usage": map[string]any{"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Cloakline-Origin", "synthetic")
		w.WriteHeader(http.StatusOK)
		return json.NewEncoder(w).Encode(payload)
	}

	// SSE variant. OpenAI streams `data: {json}\n\n` chunks, terminated
	// with `data: [DONE]\n\n`.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Cloakline-Origin", "synthetic")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	send := func(chunk map[string]any) error {
		b, err := json.Marshal(chunk)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return err
		}
		if f != nil {
			f.Flush()
		}
		return nil
	}
	// One chunk with the full text, then a stop, then [DONE].
	if err := send(map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{"role": "assistant", "content": text},
		}},
	}); err != nil {
		return err
	}
	if err := send(map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": "stop",
		}},
	}); err != nil {
		return err
	}
	if _, err := fmt.Fprint(w, "data: [DONE]\n\n"); err != nil {
		return err
	}
	if f != nil {
		f.Flush()
	}
	return nil
}

// extractModel best-effort pulls the requested model out of the
// request body so the synthetic response can echo it. Falls back to
// a sane default if parsing fails.
func extractModel(body []byte) string {
	var probe struct {
		Model string `json:"model"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return ""
	}
	return strings.TrimSpace(probe.Model)
}
