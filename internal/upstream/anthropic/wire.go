package anthropic

// Wire types for Anthropic Messages API. Pinned via `anthropic-version` header.
// Docs: https://docs.anthropic.com/en/api/messages

// -------- request --------

type wireContentBlock struct {
	Type string `json:"type"` // "text" for Phase 1
	Text string `json:"text,omitempty"`
}

type wireMessage struct {
	Role    string             `json:"role"` // "user" | "assistant"
	Content []wireContentBlock `json:"content"`
}

type wireRequest struct {
	Model         string        `json:"model"`
	Messages      []wireMessage `json:"messages"`
	System        string        `json:"system,omitempty"`
	MaxTokens     int           `json:"max_tokens"`
	Stream        bool          `json:"stream,omitempty"`
	Temperature   *float32      `json:"temperature,omitempty"`
	TopP          *float32      `json:"top_p,omitempty"`
	TopK          *int          `json:"top_k,omitempty"`
	StopSequences []string      `json:"stop_sequences,omitempty"`
}

// -------- unary response --------

type wireUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type wireResponse struct {
	ID         string             `json:"id"`
	Type       string             `json:"type"` // "message"
	Role       string             `json:"role"` // "assistant"
	Content    []wireContentBlock `json:"content"`
	Model      string             `json:"model"`
	StopReason string             `json:"stop_reason"`
	Usage      wireUsage          `json:"usage"`
}

// -------- streaming events --------
//
// Anthropic SSE streams a sequence of typed events, each on its own event/data
// line pair. We only extract text deltas and terminal usage here; other event
// types (input_json_delta for tool calls) surface with T-ANTHRO-TOOLS.

type wireStreamEvent struct {
	Type  string             `json:"type"`
	Index int                `json:"index,omitempty"`
	Delta *wireStreamDelta   `json:"delta,omitempty"`
	Usage *wireUsage         `json:"usage,omitempty"`
	Message *wireStreamMsgHead `json:"message,omitempty"` // on message_start
}

type wireStreamDelta struct {
	Type       string `json:"type"`                  // "text_delta" | "input_json_delta" | ...
	Text       string `json:"text,omitempty"`        // for text_delta
	StopReason string `json:"stop_reason,omitempty"` // on message_delta terminal
}

type wireStreamMsgHead struct {
	ID    string    `json:"id"`
	Model string    `json:"model"`
	Usage wireUsage `json:"usage"`
}
