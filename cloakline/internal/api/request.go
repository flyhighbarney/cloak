package api

import "encoding/json"

// Mode distinguishes unary vs streaming execution.
type Mode uint8

const (
	ModeUnary     Mode = 1
	ModeStreaming Mode = 2
)

func (m Mode) String() string {
	switch m {
	case ModeUnary:
		return "unary"
	case ModeStreaming:
		return "streaming"
	}
	return "unknown"
}

// ModeSet is a small bitset of Mode values used by Stage.Modes.
type ModeSet uint8

func (s ModeSet) Has(m Mode) bool { return s&ModeSet(1<<uint(m)) != 0 }
func ModesOf(ms ...Mode) ModeSet {
	var out ModeSet
	for _, m := range ms {
		out |= ModeSet(1 << uint(m))
	}
	return out
}

// Role is a message role in a multi-turn conversation.
type Role uint8

const (
	RoleUnknown   Role = 0
	RoleSystem    Role = 1
	RoleUser      Role = 2
	RoleAssistant Role = 3
	RoleTool      Role = 4
)

// Message is one turn in a conversation. Parts carries the modality-tagged
// payload; Role is who is speaking.
type Message struct {
	Role  Role
	Parts []Content
}

// ToolDecl is a tool that the model may call.
type ToolDecl struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

// ProviderExt carries typed provider-specific extensions. Only upstream
// adapters read/write these; stages and router must not.
type ProviderExt struct {
	openai    *OpenAIExt
	anthropic *AnthropicExt
}

func (e *ProviderExt) OpenAI() (*OpenAIExt, bool)      { return e.openai, e.openai != nil }
func (e *ProviderExt) Anthropic() (*AnthropicExt, bool) { return e.anthropic, e.anthropic != nil }
func (e *ProviderExt) SetOpenAI(x *OpenAIExt)          { e.openai = x }
func (e *ProviderExt) SetAnthropic(x *AnthropicExt)    { e.anthropic = x }

// OpenAIExt holds OpenAI-specific request fields not in the common core.
type OpenAIExt struct {
	Model            string
	Temperature      *float32
	TopP             *float32
	FrequencyPenalty *float32
	PresencePenalty  *float32
	Seed             *int
	MaxTokens        *int
	Stop             []string
	User             string
	LogitBias        map[string]float32
	ResponseFormat   string // "" | "json_object" | "json_schema"
}

// AnthropicExt holds Anthropic Messages API-specific fields.
// max_tokens is required by the Anthropic API; the adapter enforces this.
type AnthropicExt struct {
	Model         string
	SystemText    string
	MaxTokens     int
	Temperature   *float32
	TopP          *float32
	TopK          *int
	StopSequences []string
	// AnthropicVersion overrides the default `anthropic-version` header
	// (leave empty to use the adapter's pinned default).
	AnthropicVersion string
}

// Request is the canonical inbound representation. Small common core;
// provider-specific fields live in Extensions.
type Request struct {
	APIVersion string
	ID         RequestID
	Session    SessionID
	Principal  Principal
	Mode       Mode
	Messages   []Message
	Tools      []ToolDecl
	Extensions ProviderExt
}

// Response is the canonical outbound representation. Exactly one of
// Full or Chunks is non-nil.
type Response struct {
	APIVersion string
	RequestID  RequestID
	Mode       Mode
	Full       *Message      // unary only
	Chunks     <-chan Chunk  // streaming only
	Usage      Usage         // unary: final; streaming: cumulative up to now
	Provider   ProviderInfo
}

// Chunk is one streaming delta. The channel closes exactly once; a chunk with
// a non-nil Err is terminal.
type Chunk struct {
	Seq    uint64
	Delta  Content
	Usage  *Usage
	Finish *FinishReason
	Err    error
}

// FinishReason mirrors OpenAI's finish_reason semantics.
type FinishReason uint8

const (
	FinishUnknown       FinishReason = 0
	FinishStop          FinishReason = 1
	FinishLength        FinishReason = 2
	FinishToolCalls     FinishReason = 3
	FinishContentFilter FinishReason = 4
	FinishClientAbort   FinishReason = 5
	FinishError         FinishReason = 6
)

func (f FinishReason) String() string {
	switch f {
	case FinishStop:
		return "stop"
	case FinishLength:
		return "length"
	case FinishToolCalls:
		return "tool_calls"
	case FinishContentFilter:
		return "content_filter"
	case FinishClientAbort:
		return "client_abort"
	case FinishError:
		return "error"
	}
	return "unknown"
}

// Usage carries token counts.
type Usage struct {
	InputTokens  int
	OutputTokens int
	TotalTokens  int
}

// ProviderInfo identifies which upstream served the response.
type ProviderInfo struct {
	Upstream UpstreamID
	Kind     UpstreamKind
	Model    string
}
