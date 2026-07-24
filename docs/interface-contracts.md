# Interface Contracts

These are the load-bearing Go interfaces. They live in `internal/api/`. Nothing in that package may import any other project package — it is a leaf.

Every interface carries an explicit `APIVersion` string. Implementations declare which versions they support; the composition root refuses to wire an implementation whose declared version is not in the composition root's compatibility table. Silent skips are not allowed.

Version format: `vN.M` where `N` is the major version (breaking-change gate) and `M` is the minor (additive-only). See [versioning.md](versioning.md) for negotiation rules.

## Principal

Identity for every request. Not a string, not a map — a typed value.

```go
type Principal struct {
    APIVersion    string        // "v1.0"
    TenantID      TenantID
    KeyID         KeyID         // the virtual key's stable identifier
    Scopes        []Scope       // e.g. Scope{"chat:read", "chat:stream"}
    BudgetRef     BudgetRef     // reference into budgets map; empty = unlimited (dev only)
    RoutingPolicy PolicyRef     // reference to a compiled CEL policy
    Expiry        time.Time     // zero = never
    AuditID       AuditID       // stable per-key ID for audit trails
    Metadata      map[string]string // free-form, no security semantics
}
```

**Rationale.** Virtual keys will inevitably grow scopes, budgets, tenant IDs, routing overrides. Modeling them as `map[string]string` guarantees a painful refactor. The typed field is cheap now.

**Contract.** A `Principal` is immutable once resolved. Any change requires a new resolution against the auth store.

## Content — modality-tagged payload atom

```go
type Modality uint8

const (
    ModText Modality = iota + 1
    ModImage
    ModAudio
    ModVideo
    ModPDF
    ModArchive
    ModOffice
    ModUnknown
)

type Content struct {
    Modality Modality
    Bytes    []byte           // raw
    Meta     ContentMeta      // typed metadata; not map[string]any
}

type ContentMeta struct {
    MIME       string
    Filename   string
    Dimensions *Dim        // image/video only; nil otherwise
    Duration   time.Duration // audio/video only
    Language   string        // ISO-639 hint when known
    Origin     ContentOrigin // UserInput | RetrievedRAG | ToolOutput | ModelOutput
}
```

**Rationale.** `Origin` is critical for cross-turn injection defenses: retrieved content and tool outputs need stricter guardrails than user input. Modeling it explicitly on the content atom means the guardrail stage does not have to infer origin from parent structure.

## Request — canonical, small core

```go
type Mode uint8
const (
    ModeUnary Mode = iota + 1
    ModeStreaming
)

type Request struct {
    APIVersion string
    ID         RequestID          // ULID; server-generated on ingress
    Session    SessionID          // stable across a conversation; server-generated if client omits
    Principal  Principal
    Mode       Mode
    Parts      []Content          // ordered, multi-modal
    Tools      []ToolDecl
    Extensions ProviderExt        // typed provider-specific extensions
}

type ToolDecl struct {
    Name        string
    Description string
    Schema      json.RawMessage    // JSON schema of arguments
}

type ProviderExt struct {
    openai    *OpenAIExt
    anthropic *AnthropicExt
    // additive-only; adding a field is a minor version bump
}

func (e ProviderExt) OpenAI() (*OpenAIExt, bool)      { return e.openai, e.openai != nil }
func (e ProviderExt) Anthropic() (*AnthropicExt, bool) { return e.anthropic, e.anthropic != nil }
```

**Rationale.** The core stays small. Provider-specific bloat lives behind typed accessors that only upstream adapters call. If a stage or router touches `ext.OpenAI()`, that's a design smell — flag in code review.

## Response

```go
type Response struct {
    APIVersion string
    RequestID  RequestID
    Mode       Mode
    Full       *Message          // Unary; nil for Streaming
    Chunks     <-chan Chunk      // Streaming; nil for Unary
    Usage      Usage             // may be a running total for streams
    Provider   ProviderInfo      // which upstream served this
}

type Chunk struct {
    Seq       uint64
    Delta     Content            // the incremental content (usually ModText)
    Usage     *Usage             // set on final chunk if the provider reports it
    Finish    *FinishReason      // set on final chunk
    Err       error              // set only on abnormal termination
}
```

**Contract.** For streaming, the channel is closed exactly once. A non-nil `Chunk.Err` is the terminal chunk. Callers must drain the channel to allow cleanup.

## Stage — DAG node

```go
type StageID string
type SignalName string

type Stage interface {
    APIVersion() string
    ID() StageID
    Requires() []StageID
    Produces() []SignalName
    Modes() ModeSet          // {Unary}, {Streaming}, or {Unary, Streaming}
    Run(ctx context.Context, r *Request, bus SignalBus) error
}

type SignalBus interface {
    Set(name SignalName, value any) error
    Get(name SignalName) (any, bool)
}
```

**Contract.**
- `Run` may mutate `r.Parts` in place, but must not mutate `r.Principal` or `r.Extensions`.
- `Run` must not read from a signal it did not declare in `Requires` (checked at boot when possible; asserted at runtime).
- `Run` must not write a signal it did not declare in `Produces`.
- If `Run` returns a non-nil error, the request fails; downstream stages are cancelled.
- `Run` must respect `ctx.Done()`.

## Extractor — modality decomposition

```go
type Extractor interface {
    APIVersion() string
    Handles(m Modality) bool
    Extract(ctx context.Context, in Content) ([]Content, error)
}
```

**Contract.** An extractor may fan out (PDF → text + images) or fan in (archive → many contents). The stage that runs extractors composes them by dispatching on `in.Modality`.

## Router — pure function over a snapshot

```go
type Router interface {
    APIVersion() string
    Select(ctx context.Context, r *Request, snap RouteSnapshot) (RouteDecision, error)
}

type RouteSnapshot struct {
    TakenAt time.Time
    Health  map[UpstreamID]HealthState
    Caps    map[UpstreamID]Caps
    Budgets BudgetView         // read-only projection
    Queues  map[UpstreamID]QueueDepth
    History RecentDecisions
}

type RouteDecision struct {
    Upstream UpstreamID
    Reason   string             // human-readable trace
    Trace    []PolicyRuleID     // ordered list of policies that fired
}
```

**Contract.** `Select` MUST be a pure function of `(r, snap)`. No live queries. No wall-clock reads other than through `snap.TakenAt`. No goroutine spawning. This is enforced by convention and by property tests that fuzz `snap` and assert determinism.

## Caps — typed capability set

```go
type Caps struct {
    Modalities  ModalitySet         // bitset of Modality values
    Tools       ToolCaps            // FunctionCalling | StrictSchema | ParallelCalls
    Streaming   StreamCaps          // None | SSE | WebSocketFrames
    MaxContext  int                 // tokens
    JSONMode    JSONModeCaps        // None | Freeform | StrictSchema
    Reasoning   ReasoningCaps       // None | Hidden | Exposed
}
```

**Rationale.** Booleans (`supportsTools bool`) don't survive the second provider. Typed sets let a policy express "streaming with SSE and strict JSON schema" without ambiguity.

## Upstream — provider adapter

```go
type Upstream interface {
    APIVersion() string
    ID() UpstreamID
    Kind() UpstreamKind
    Caps() Caps
    Health(ctx context.Context) HealthState
    Send(ctx context.Context, r *Request) (*Response, error)
}
```

**Contract.**
- `Send` translates canonical → provider wire → canonical.
- `Send` MUST NOT retry non-idempotent completions on 5xx once a byte has been streamed to the client.
- `Health` is called by the `Snapshotter`, not by the router; it may be cached.
- `Send` returns typed errors: `ErrRateLimit`, `ErrUnavailable`, `ErrClientAbort`, `ErrProvider`, etc. Untyped errors are a bug.

## Transport — how requests arrive

```go
type Transport interface {
    Name() string
    APIVersion() string
    Serve(ctx context.Context, engine Engine) error
}

type Engine interface {
    Handle(ctx context.Context, r *Request) (*Response, error)
}
```

**Contract.** A transport is responsible for:
- Deserializing wire format → canonical `Request`.
- Serializing canonical `Response` → wire format (including SSE framing).
- Extracting the virtual key and calling `auth` before forwarding.
- Emitting `stage.ingress` and `stage.egress` telemetry events.

Transports do NOT run policy. They call `engine.Handle` and return whatever comes back.

## SessionVault — stream-scoped state machine

```go
type SessionID string
type Pseudonym string
type PIIKind string

type VaultState uint8
const (
    VaultOpen VaultState = iota + 1
    VaultStreaming
    VaultDraining
    VaultClosed
    VaultFailed
)

type SessionVault interface {
    APIVersion() string
    Begin(ctx context.Context, sid SessionID) error
    Tokenize(ctx context.Context, sid SessionID, kind PIIKind, plaintext string) (Pseudonym, error)
    Restore(ctx context.Context, sid SessionID, p Pseudonym) (string, error)
    Transition(ctx context.Context, sid SessionID, to VaultState) error
    Close(ctx context.Context, sid SessionID, outcome Outcome) error
}
```

**Contract.**
- `Tokenize` in `VaultOpen` or `VaultStreaming` only; error otherwise.
- `Restore` in `VaultStreaming` or `VaultDraining` only.
- `Close` zeroizes the backing buffer for the pseudonym map.
- No pseudonym escapes the session boundary. Reuse across sessions is a bug.
- On process death, the map is gone. In-flight streams die cleanly; no partially-de-anonymized bytes are emitted (the transport guarantees this by refusing to write chunks whose vault has entered `VaultFailed`).

## Meter — telemetry

```go
type Meter interface {
    Counter(n MetricName, dims Dims) Counter
    Histogram(n MetricName, dims Dims) Histogram
    Gauge(n MetricName, dims Dims) Gauge
}

type MetricName string  // defined as constants in internal/obs/meter/names.go; no other allowed
type Dims map[DimKey]string
type DimKey string      // constants; no free-form strings
```

**Contract.** All metric names are constants. All dimension keys are constants. Free-form strings at emission sites cause a lint failure. See [telemetry.md](telemetry.md) for the vocabulary.

## PolicyEngine — CEL

```go
type PolicyEngine interface {
    APIVersion() string
    Compile(source string) (Policy, error)
    Eval(ctx context.Context, p Policy, env PolicyEnv) (PolicyResult, error)
}

type Policy interface {
    ID() PolicyRuleID
    RequiredEnvKeys() []string  // for boot-time cross-check against PolicyEnv schema
}
```

See [policy-language.md](policy-language.md) for the CEL environment.

## Errors

Every interface uses typed errors from `internal/api/errs.go`:

```go
var (
    ErrRateLimit       = errors.New("upstream rate limited")
    ErrUnavailable     = errors.New("upstream unavailable")
    ErrClientAbort     = errors.New("client aborted request")
    ErrProvider        = errors.New("provider error")
    ErrPolicyBlocked   = errors.New("blocked by policy")
    ErrBudgetExceeded  = errors.New("budget exceeded")
    ErrCapMismatch     = errors.New("no upstream matches required capabilities")
    ErrDLPRedaction    = errors.New("DLP rejected content")
    ErrVaultState      = errors.New("vault state machine violation")
    ErrVersionMismatch = errors.New("component API version incompatible")
)
```

Wrapping is via `fmt.Errorf("...: %w", err, ErrX)`. Callers use `errors.Is`.

## Versioning Enforcement

At composition-root startup:

1. Read the compatibility table (constants) declaring the supported `APIVersion` per interface.
2. For each registered implementation, call `impl.APIVersion()`.
3. If not compatible: panic with a structured message naming the interface, impl, expected range, and actual value.

There is no "just skip it" path.
