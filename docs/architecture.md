# Architecture

## Three Planes

```
┌───────────────────────────────────────────────────────────────────────────┐
│                        TRANSPORT PLANE                                    │
│  HTTP/JSON  │  SSE  │  WebSocket  │  MCP (JSON-RPC)  │  SDK  │  CLI       │
│  (adapters convert wire ↔ canonical Request/Response)                     │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │
                               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                      POLICY ENGINE CORE                                   │
│                                                                           │
│                     ┌───────────────────────┐                             │
│                     │   DAG SCHEDULER       │                             │
│                     │                       │                             │
│    Request ────────►│  Normalize            │                             │
│                     │      │                │                             │
│                     │      ▼                │                             │
│                     │  ExtractModalities    │ (fanout, concurrent)        │
│                     │   ┌──┼──┐             │                             │
│                     │   ▼  ▼  ▼             │                             │
│                     │  Text Image Audio     │                             │
│                     │   └──┼──┘             │                             │
│                     │      ▼                │                             │
│                     │  DLP  ─┐              │ (parallel with Guard)       │
│                     │        │              │                             │
│                     │  Guard ┘              │                             │
│                     │      │                │                             │
│                     │      ▼                │                             │
│                     │  Reassemble           │                             │
│                     │      │                │                             │
│                     │      ▼                │                             │
│                     │  Router (pure fn)     │ (uses immutable Snapshot)   │
│                     │      │                │                             │
│                     └──────┼────────────────┘                             │
│                            ▼                                              │
│                     Upstream Adapter                                      │
│                                                                           │
│   (For streaming: SessionVault state machine runs alongside the DAG,      │
│    de-anonymizing chunks on the return path.)                             │
└──────────────────────────────┬────────────────────────────────────────────┘
                               │
                               ▼
┌───────────────────────────────────────────────────────────────────────────┐
│                       UPSTREAM PLANE                                      │
│  OpenAI  │  Anthropic  │  Ollama  │  vLLM  │  Bedrock  │  Gemini  │  ...  │
└───────────────────────────────────────────────────────────────────────────┘
```

Three planes, three abstractions, each replaceable independently.

## Why a DAG, Not a Linear Pipeline

The blueprint's linear pipeline (`ingress → DLP → guard → router → upstream`) forces stages to run sequentially even when they don't depend on each other. Under load, this is the difference between 90ms and 30ms total overhead.

Once modalities enter the picture, the linear model breaks entirely. A PDF request needs text extraction, image extraction, and OCR — each independently runnable — before DLP can even start. A linear pipeline serializes what should be parallel.

**Rules for the DAG scheduler:**

- Every `Stage` declares its `Requires([]StageID)` (predecessors) and `Produces([]Signal)` (annotations added to the shared `SignalBus`).
- Stages with no unresolved dependency run immediately, concurrently.
- Stages that only read signals from earlier stages fan out.
- A stage that fails the request short-circuits: dependent stages that produce blocking signals fail with the request; independent stages already running are cancelled via `context.Context`.
- The graph is validated at boot: cycles refuse to load, unreachable stages refuse to load, unresolved signal names refuse to load.

**Default pipeline graph (Phase 0):**

```
Normalize
   └► ExtractText
        └► DLP.Tier1
             └► Reassemble
                  └► Router
                       └► UpstreamCall
                            └► DeAnonymize (streaming: per-chunk)
```

Phase 0 is nearly linear because we only have one modality extractor and one DLP tier. The DAG shape earns its keep the moment a second detector, guardrail, or extractor exists.

## Why Snapshot-Based Routing

The router in the blueprint queries health, budgets, capabilities, and queue depth live from other subsystems. This creates hidden bidirectional coupling: the router depends on every subsystem, and every subsystem knows it may be queried at any moment. Testing is impossible; behavior is non-deterministic.

**Instead:** at the point routing runs, an upstream call captures a `RouteSnapshot` — an immutable value containing everything the router might need. The router is a pure function `(Request, Snapshot) → RouteDecision`.

Properties this gives us:

- **Determinism.** Same input → same decision. Property tests are trivial.
- **Replayability.** Persist the snapshot with the audit log; a past routing decision can be re-derived exactly.
- **Testability.** Fuzzing the snapshot doesn't require standing up health, budget, and capability subsystems.
- **Decoupling.** The router imports snapshot types, not subsystem code.

Snapshot capture happens in a dedicated `Snapshotter` component that reads health/caps/budgets and produces the immutable value. That component *is* allowed to have live dependencies — because it does not encode any routing logic.

## Streaming as a First-Class Mode

Every `Stage` declares whether it operates on `Unary`, `Streaming`, or `Both`. The scheduler chooses the correct execution mode per request. A stage that has not been explicitly annotated as streaming-capable refuses to run in a streaming context.

Streaming introduces state — specifically the token vault, which must map pseudonyms back to originals on the return path. The `SessionVault` runs a state machine (`Open → Streaming → Draining → Closed | Failed`) keyed to the request ID. Restart during `Streaming` fails the stream cleanly and never emits a partially-de-anonymized chunk.

Buffering on the return path is bounded. If the client cannot consume as fast as the upstream produces, the buffer fills to a configured cap and then applies backpressure to the upstream reader (Go's `io.Reader` on the response body). No unbounded growth.

## Modality-First Content Model

A `Content` value carries `{Modality, Bytes, Meta}`. An `Extractor` takes one `Content` and produces zero or more `Content`s of the same or different modality. This lets a PDF extractor emit both text and images; an archive extractor emit multiple documents; an audio extractor emit text (via ASR) plus retained audio.

DLP and Guard stages operate on `Content`, not raw request bodies. They dispatch on modality. Text DLP runs regex; image DLP (deferred) will run OCR then text DLP; audio DLP (deferred) will run ASR then text DLP.

The Reassemble stage is the mirror of Extract: it takes the (possibly mutated) `Content` list back to the final canonical `Request` before the upstream call.

## Small Common Core, Typed Provider Extensions

The canonical `Request` holds only fields every non-trivial provider exposes: modality-tagged parts, tools, message roles. Provider-specific fields (Anthropic's `system` top-level string, OpenAI's `logit_bias`, Bedrock's SigV4 metadata) live in a `ProviderExt` map keyed by a typed `ProviderKey`. Accessors are typed — `ext.OpenAI()`, `ext.Anthropic()` — not `map[string]any`.

Consequence: the router and stages operate on the common core. Only upstream adapters read/write provider extensions. This prevents the god-struct bloat that kills every canonical-model design.

## Config as Compiled IR

Configuration lives in domain-split files: `providers.yaml`, `principals.yaml`, `policies.cel`, `pipeline.yaml`. At boot, all four are parsed, validated, cross-referenced, and compiled into an internal representation with a content hash. The IR is what the running engine holds; the source files are inputs, not runtime state.

Invalid config fails at boot — never at request time. Malformed YAML, unknown fields, CEL syntax errors, DAG cycles, and unresolved cross-references all refuse to load with actionable messages.

The config hash is exported as a metric so that operators can detect drift between instances or between deploys.

## Latency SLOs Belong to Payload Classes

The blueprint states latency budgets as fixed constants (`T_DLP ≤ 15ms`). This doesn't survive contact with reality: a 200-byte prompt and a 200KB prompt are not the same problem.

SLOs are stated per payload class in `slos.md`. Overhead is a function of payload size, modality, and stage graph. The engine records overhead per stage per request; SLO violations surface as metrics.

## Module Boundaries

| Directory | Owns | Depends on |
|---|---|---|
| `internal/api/` | Canonical types (`Request`, `Response`, `Principal`, `Content`, `Caps`, `Stage`, `Router`, `Transport`, `Upstream`, `Vault`, `Meter`). | Nothing else in the project. Pure types. |
| `internal/engine/` | DAG scheduler, signal bus, execution modes. | `api`. |
| `internal/policy/cel/` | CEL compiler, typed policy environment. | `api`, `cel-go`. |
| `internal/stage/*` | Stage implementations (Normalize, Extract, DLP, Reassemble). | `api`. |
| `internal/router/cel/` | CEL-driven router. | `api`, `policy/cel`. |
| `internal/upstream/*` | Provider adapters. | `api`, `httpclient`. |
| `internal/transport/*` | Transport adapters (HTTP first). | `api`, `engine`. |
| `internal/auth/` | Virtual key → `Principal` resolution. | `api`. |
| `internal/vault/session/` | Stream-scoped vault state machine. | `api`. |
| `internal/httpclient/` | SSRF-hardened HTTP client. | (stdlib only) |
| `internal/obs/log/` | Redacting structured logger. | (stdlib only) |
| `internal/obs/meter/` | `Meter` implementation over Prometheus. | `api`, `prometheus/client_golang`. |
| `internal/config/` | YAML+CEL loader, validator, IR compiler. | `api`, `policy/cel`. |
| `cmd/cloakline/` | Composition root. Wires everything. | Everything above. |

`internal/api/` never imports anything else in the project. If a change to `api` would require it to import a lower package, the design is wrong.

## Failure Modes

- **Panic in a stage** → recovered by the scheduler; the request fails with a structured error; independent stages are cancelled; no shared state is left in an inconsistent state (because there is no shared mutable state — signals are per-request).
- **Upstream 5xx** → adapter returns a typed error; router *does not* automatically retry non-idempotent completions.
- **Upstream connection error before first byte** → adapter may retry once with backoff; router logs the retry attempt in the audit path.
- **Upstream disconnect mid-stream** → stream fails; SessionVault transitions to `Failed`; client sees an error, not truncated content.
- **Client disconnect** → `context.Context` cancellation propagates upstream; the outbound request is aborted so we don't get charged for tokens the client will never see.
- **Config reload** → not supported in Phase 0. Restart the process.
- **Component version mismatch** → refuses to register at boot. Startup fails loudly.
