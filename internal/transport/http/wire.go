package http

// Wire types for the OpenAI-shaped ingress. Kept local so we can evolve
// ingress independently of the outbound OpenAI adapter.

import "encoding/json"

type inMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type inRequest struct {
	Model       string      `json:"model"`
	Messages    []inMessage `json:"messages"`
	Stream      bool        `json:"stream,omitempty"`
	Temperature *float32    `json:"temperature,omitempty"`
	TopP        *float32    `json:"top_p,omitempty"`
	MaxTokens   *int        `json:"max_tokens,omitempty"`
	Stop        []string    `json:"stop,omitempty"`
}

type outChoiceMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type outChoice struct {
	Index        int              `json:"index"`
	Message      outChoiceMessage `json:"message"`
	FinishReason string           `json:"finish_reason,omitempty"`
}

type outUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type outResponse struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Choices []outChoice `json:"choices"`
	Usage   outUsage    `json:"usage"`
}

type outStreamDelta struct {
	Role    string `json:"role,omitempty"`
	Content string `json:"content,omitempty"`
}

type outStreamChoice struct {
	Index        int            `json:"index"`
	Delta        outStreamDelta `json:"delta"`
	FinishReason string         `json:"finish_reason,omitempty"`
}

type outStreamChunk struct {
	ID      string            `json:"id"`
	Object  string            `json:"object"`
	Created int64             `json:"created"`
	Model   string            `json:"model"`
	Choices []outStreamChoice `json:"choices"`
}
