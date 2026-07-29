package api

import "context"

// UpstreamKind identifies the provider family. Fixed set — new kinds require
// interface consideration (not just adapter code).
type UpstreamKind string

const (
	KindOpenAI    UpstreamKind = "openai"
	KindAnthropic UpstreamKind = "anthropic"
	KindOllama    UpstreamKind = "ollama"
	KindVLLM      UpstreamKind = "vllm"
	KindBedrock   UpstreamKind = "bedrock"
	KindGemini    UpstreamKind = "gemini"
	KindMock      UpstreamKind = "mock" // testing
)

// Upstream is a provider adapter.
type Upstream interface {
	APIVersion() string
	ID() UpstreamID
	Kind() UpstreamKind
	Caps() Caps
	Health(ctx context.Context) HealthState
	Send(ctx context.Context, r *Request) (*Response, error)
}
