package http

import "encoding/json"

// -------- Anthropic-shaped ingress (Messages API) --------

type antInContentBlock struct {
	Type string `json:"type"` // "text" for Phase 1
	Text string `json:"text,omitempty"`
}

type antInMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"` // string or array of blocks
}

type antInRequest struct {
	Model         string         `json:"model"`
	Messages      []antInMessage `json:"messages"`
	System        json.RawMessage `json:"system,omitempty"` // string or array of blocks
	MaxTokens     int            `json:"max_tokens"`
	Stream        bool           `json:"stream,omitempty"`
	Temperature   *float32       `json:"temperature,omitempty"`
	TopP          *float32       `json:"top_p,omitempty"`
	TopK          *int           `json:"top_k,omitempty"`
	StopSequences []string       `json:"stop_sequences,omitempty"`
}

// -------- Anthropic-shaped egress --------

type antOutContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type antOutUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type antOutResponse struct {
	ID         string               `json:"id"`
	Type       string               `json:"type"` // "message"
	Role       string               `json:"role"` // "assistant"
	Model      string               `json:"model"`
	Content    []antOutContentBlock `json:"content"`
	StopReason string               `json:"stop_reason"`
	Usage      antOutUsage          `json:"usage"`
}

// -------- Streaming event payloads (Anthropic-shaped) --------

type antEvMessageStart struct {
	Type    string             `json:"type"` // "message_start"
	Message antEvMessageStartM `json:"message"`
}

type antEvMessageStartM struct {
	ID    string      `json:"id"`
	Type  string      `json:"type"`
	Role  string      `json:"role"`
	Model string      `json:"model"`
	Usage antOutUsage `json:"usage"`
}

type antEvContentBlockStart struct {
	Type         string             `json:"type"`
	Index        int                `json:"index"`
	ContentBlock antOutContentBlock `json:"content_block"`
}

type antEvContentBlockDelta struct {
	Type  string          `json:"type"` // "content_block_delta"
	Index int             `json:"index"`
	Delta antEvTextDelta  `json:"delta"`
}

type antEvTextDelta struct {
	Type string `json:"type"` // "text_delta"
	Text string `json:"text"`
}

type antEvContentBlockStop struct {
	Type  string `json:"type"` // "content_block_stop"
	Index int    `json:"index"`
}

type antEvMessageDelta struct {
	Type  string             `json:"type"` // "message_delta"
	Delta antEvMessageDeltaD `json:"delta"`
	Usage antOutUsage        `json:"usage"`
}

type antEvMessageDeltaD struct {
	StopReason string `json:"stop_reason"`
}

type antEvMessageStop struct {
	Type string `json:"type"` // "message_stop"
}
