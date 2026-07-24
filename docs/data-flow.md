# Data Flow Support Matrix

Every combination of `{transport} × {modality} × {mode} × {upstream}` is either **supported**, **planned** (tripwire named), or **unsupported by design**. If a client submits a combination not listed as supported, the transport returns a structured error naming the missing cell. No silent fallthrough.

## Legend

- ✅ Supported in Phase 0.
- 🕓 Planned; blocked on the named tripwire in [tripwires.md](tripwires.md).
- ❌ Unsupported by design. Rationale required.

## Matrix

### Transport = HTTP/JSON

| Modality | Mode | Upstream: OpenAI | Ollama | Anthropic | Bedrock | Gemini |
|---|---|---|---|---|---|---|
| Text | Unary | ✅ | 🕓 T-OLLAMA | ✅ | 🕓 T-BEDROCK | 🕓 T-GEMINI |
| Text | Streaming (SSE) | ✅ | 🕓 T-OLLAMA | ✅ | 🕓 T-BEDROCK | 🕓 T-GEMINI |
| Image (base64 in JSON) | Unary | 🕓 T-DLP-VISION | 🕓 T-DLP-VISION | 🕓 T-DLP-VISION | 🕓 T-DLP-VISION | 🕓 T-DLP-VISION |
| Image | Streaming | 🕓 T-DLP-VISION | 🕓 T-DLP-VISION | 🕓 T-DLP-VISION | 🕓 T-DLP-VISION | 🕓 T-DLP-VISION |
| Audio (base64) | Unary | 🕓 T-AUDIO | 🕓 T-AUDIO | ❌ (see below) | 🕓 T-AUDIO | 🕓 T-AUDIO |
| Audio | Streaming | ❌ (use WebSocket) | ❌ | ❌ | ❌ | ❌ |
| Video | any | 🕓 T-VIDEO | 🕓 T-VIDEO | 🕓 T-VIDEO | 🕓 T-VIDEO | 🕓 T-VIDEO |
| PDF | Unary | 🕓 T-PDF | 🕓 T-PDF | 🕓 T-PDF | 🕓 T-PDF | 🕓 T-PDF |
| Archive (zip/tar) | any | ❌ (see below) | ❌ | ❌ | ❌ | ❌ |
| Office (docx/xlsx/pptx) | Unary | 🕓 T-OFFICE | 🕓 T-OFFICE | 🕓 T-OFFICE | 🕓 T-OFFICE | 🕓 T-OFFICE |

### Transport = WebSocket (Realtime)

| Modality | Mode | Upstream: OpenAI Realtime | Ollama | Anthropic |
|---|---|---|---|---|
| Text | Streaming | 🕓 T-REALTIME | ❌ | ❌ |
| Audio | Streaming (framed PCM) | 🕓 T-REALTIME | ❌ | ❌ |

### Transport = MCP (JSON-RPC over stdio or HTTP)

| Direction | Type | Support |
|---|---|---|
| Client → Server | `tools/list` | 🕓 T-MCP |
| Client → Server | `tools/call` | 🕓 T-MCP |
| Client → Server | `resources/read` | 🕓 T-MCP |
| Server → Client (notification) | any | 🕓 T-MCP |

MCP is a peer transport, not a "gateway feature." When it lands, tool arguments pass through DLP and guardrail stages exactly like chat messages.

### Transport = SDK (in-process)

| Case | Support |
|---|---|
| Go call directly to `engine.Handle` | ✅ (this is how transports call it; also usable as a library) |
| Language bindings (Python/TS) | 🕓 T-SDK |

### Transport = CLI

| Case | Support |
|---|---|
| `cloak chat` interactive | 🕓 T-CLI |
| `cloak audit tail` | 🕓 T-CLI |

## Rationale for the ❌ Cells

### Audio streaming over HTTP/JSON
HTTP/JSON is the wrong shape. Audio streaming needs binary framing and low-latency bidirectional flow. When we want audio streaming, WebSocket transport lands and this cell is not filled — WebSocket cell fills instead.

### Audio to Anthropic (unary)
Anthropic's Messages API does not accept audio as of the reference date. The upstream adapter would have to transcode via a third service — that's not a policy engine's job. If Anthropic adds audio, this becomes a planned cell.

### Archives (zip/tar)
An archive is not a modality — it is a container. The Extractor for archives (deferred) unpacks and produces multiple `Content` entries per contained file. The Extractor is the point where archives become supported; the raw archive itself is never sent to an upstream.

### Video
Deferred entirely. Frame-by-frame DLP is expensive and out of scope. The tripwire is a customer with a video-processing workflow.

## Currently supported cells

1. **HTTP/JSON × Text × Unary × OpenAI** (via `/v1/chat/completions`)
2. **HTTP/JSON × Text × Streaming (SSE) × OpenAI** (via `/v1/chat/completions` with `stream: true`)
3. **HTTP/JSON × Text × Unary × Anthropic** (via `/v1/messages`) — added by T-ANTHRO
4. **HTTP/JSON × Text × Streaming (SSE) × Anthropic** (via `/v1/messages` with `stream: true`) — added by T-ANTHRO

Everything else fails with a structured error naming the missing cell and pointing to the relevant tripwire.

## Cross-Cutting Behavior

Regardless of cell, every supported request path executes the same DAG (with modality-appropriate stages). This is the guarantee that makes the matrix maintainable: cells are (transport, modality, mode, upstream) combinations, not custom code paths.

### The single unified path

```
Wire (transport-specific)
    ↓ Deserialize
Request (canonical)
    ↓ Auth: virtual key → Principal
    ↓ Engine.Handle
DAG execution:
    Normalize
    → ExtractModalities (per-modality extractors)
    → DLP × modality (per-modality DLP stages)
    → Guard × modality (per-modality guard stages)
    → Reassemble
    → Router (pure fn of RouteSnapshot)
    → Upstream.Send
    → (streaming) SessionVault de-anonymization per chunk
Response (canonical)
    ↓ Serialize
Wire (transport-specific)
```

The matrix says which cells this path is wired for. The path itself is one implementation.

## Adding a New Cell

To fill a planned (🕓) cell:

1. Identify the tripwire that fires — record it.
2. If a new stage is required (e.g. image DLP), implement it against the `Stage` interface with its own `APIVersion`.
3. If a new extractor is required (e.g. PDF), implement `Extractor`.
4. If a new upstream is required (e.g. Anthropic), implement `Upstream`.
5. If a new transport is required (e.g. WebSocket), implement `Transport`.
6. Update this matrix — flip 🕓 to ✅ — and update the composition root's registration.
7. Update `tripwires.md` to record that the tripwire fired.

No cell fills without corresponding matrix and tripwire updates.
