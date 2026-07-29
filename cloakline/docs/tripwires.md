# Tripwires

The scope discipline principle: **do not build a feature until a specific, observable signal forces it.**

This document lists every deferred feature and the tripwire that fires when it moves from "not now" to "now." A tripwire is a *specific* signal — not "when it seems useful." Reviewed quarterly.

## Format

Each entry has:
- **Tripwire ID** — a stable identifier.
- **Feature deferred.**
- **Signal that fires the tripwire** — what specifically must be observed.
- **Estimated effort** — rough size (S/M/L/XL) once the tripwire fires.
- **Prep required** — what interfaces or hooks Phase 0 leaves in place so this feature can slot in without a rewrite.
- **Blocking dependencies** — other tripwires that must fire first.

---

## Upstream Adapters

### T-OLLAMA — Ollama upstream adapter
- **Feature:** Local-model routing via Ollama's HTTP API.
- **Signal:** User configures a local model in `providers.yaml` or requests local escalation for cost reasons.
- **Effort:** M (1–2 weeks).
- **Prep in Phase 0:** `Upstream` interface exists; `UpstreamKind` enum has `Ollama`; `Caps` model has `MaxContext` and modality fields; SSRF client whitelists loopback for explicit local models.
- **Blocks:** T-COMPLEXITY-ROUTER.

### T-ANTHRO — Anthropic upstream adapter **FIRED: 2026-07-23**
- **Feature:** Send requests to `api.anthropic.com` Messages API + expose `/v1/messages` ingress.
- **Signal:** User requests Claude routing (their target list included Claude API + Claude Code).
- **Effort:** M (delivered in one session — canonical types made translation straightforward).
- **Prep in Phase 0:** `ProviderExt.Anthropic()` typed accessor was defined; canonical `Request.Parts` carries origin metadata that Anthropic's `system` field needs.
- **What shipped:**
  - `internal/upstream/anthropic/` — full Messages API adapter, unary + SSE with typed event stream projection.
  - `internal/transport/http/anthropic.go` — `/v1/messages` ingress with `x-api-key` header auth; synthesizes Anthropic's message_start → content_block_delta → message_stop event sequence on the return path.
  - `configs/providers.yaml` + `configs/policies.yaml` — commented Anthropic stanza and routing policy ready to uncomment.
- **Blocks:** None.

### T-BEDROCK — AWS Bedrock upstream adapter
- **Feature:** SigV4-signed calls to Bedrock; per-model wrapper handling.
- **Signal:** User requests Bedrock routing.
- **Effort:** L (SigV4 + per-model wrappers).
- **Prep in Phase 0:** None specific; `httpclient` package is designed to accept a `RequestSigner` interface (added when this tripwire fires).
- **Blocks:** T-ANTHRO (share Anthropic-on-Bedrock wrapper).

### T-GEMINI — Google Gemini upstream adapter
- **Signal:** User requests Gemini routing.
- **Effort:** M–L.
- **Prep:** `ProviderExt.Gemini()` accessor to be added.

---

## Transports

### T-REALTIME — WebSocket transport for Realtime APIs
- **Feature:** WebSocket transport; framed audio/text bidirectional streaming.
- **Signal:** User adopts OpenAI Realtime API or an equivalent.
- **Effort:** XL (bidirectional streaming, audio framing, session management all new).
- **Prep in Phase 0:** `Transport` interface is a peer of HTTP; `Mode` includes `Streaming`; `SessionVault` state machine already handles long-lived sessions.
- **Blocks:** T-AUDIO.

### T-MCP — MCP transport
- **Feature:** JSON-RPC over stdio and HTTP; tool-call inspection.
- **Signal:** User wires an MCP server, OR the first user asks about MCP compatibility in an issue.
- **Effort:** L.
- **Prep in Phase 0:** Content model has `Origin=ToolOutput`; `ToolDecl` type exists in canonical `Request`.
- **Blocks:** T-MCP-SAFETY.

### T-SDK — Language bindings (Python/TypeScript)
- **Feature:** Native Python and TypeScript SDKs that call the engine in-process (via CGO/FFI) or over the HTTP transport with typed clients.
- **Signal:** 5+ users ask for a native SDK.
- **Effort:** M (over HTTP) or XL (in-process).
- **Prep:** None specific; the HTTP transport is already OpenAI-compatible, so existing SDKs work with base URL swap.

### T-CLI — `cloak` CLI
- **Feature:** Interactive chat, audit tailing, key management CLI.
- **Signal:** 3+ operators ask for CLI-based key rotation.
- **Effort:** M.
- **Prep:** None specific.

---

## DLP Tiers

### T-DLP-TIER2 — Entropy + secret-pattern DLP
- **Feature:** Sliding-window Shannon entropy + known-secret patterns (AWS keys, GitHub tokens, private keys).
- **Signal:** First reported API-key leak, OR user requests secret-scanning capability.
- **Effort:** M.
- **Prep in Phase 0:** `Stage` interface accepts a Tier-2 impl without engine changes; `finding_kind` telemetry dimension already supports new categories.

### T-DLP-TIER3 — Local NER-based DLP
- **Feature:** Local named-entity recognition (spaCy via subprocess or ONNX NER model) for names, addresses, locations.
- **Signal:** First reported PII leak beyond the regex classes.
- **Effort:** L (model selection, packaging, latency tuning).
- **Prep:** `Detector.Kind()` values include `NER`; latency SLOs already anticipate a 30–50ms class.

### T-DLP-VISION — Vision / OCR DLP
- **Feature:** Image → OCR → text DLP.
- **Signal:** Screenshot-heavy workflow observed, OR user reports PII in image payload leaked.
- **Effort:** L (OCR engine, throughput vs latency trade-off).
- **Prep in Phase 0:** `Modality.ModImage` exists; `Extractor` interface can decompose images.

### T-DLP-AUDIO — Audio DLP
- **Feature:** ASR → text DLP for audio payloads.
- **Signal:** T-REALTIME fires, OR user submits audio via HTTP with the ask.
- **Effort:** XL.
- **Prep:** `Modality.ModAudio`; `ContentMeta.Duration`.

---

## Guardrails

### T-GUARD-INJECT — Prompt injection classifier
- **Feature:** ONNX classifier (Prompt-Guard, Electra-small) as a `Guardrail` stage.
- **Signal:** Third injection incident logged, OR first tool-plane compromise, OR compliance conversation requires it.
- **Effort:** M.
- **Prep in Phase 0:** DAG runs stages in parallel — a guardrail stage slots in beside DLP without pipeline changes; latency budget accommodates 2.5ms class.

---

## Router

### T-COMPLEXITY-ROUTER — Complexity scoring + multi-policy router
- **Feature:** The blueprint's 9-policy engine with candidate/filter/score/tiebreak/dispatch.
- **Signal:** Two or more upstreams registered AND cost differential > 5x.
- **Effort:** L.
- **Prep in Phase 0:** `Router` interface is snapshot-based (pure function); adding policies means adding CEL rules and expanding `RouteSnapshot`.
- **Blocks:** T-OLLAMA (needed for meaningful routing).

### T-CACHE — Semantic response cache
- **Feature:** Local semantic cache for repeated prompts.
- **Signal:** Cost > $1k/month per team OR repeated identical prompts observed on the DLP metric stream.
- **Effort:** L.
- **Prep:** Response is a canonical type; caching hooks at `Engine.Handle` boundary.

---

## Enforcement

### T-BUDGET — Budget enforcement
- **Feature:** Pre-flight budget checks, `max_tokens` capping, 402 on exhaustion.
- **Signal:** First bill above a user's soft cap OR first user request for cost caps.
- **Effort:** M.
- **Prep in Phase 0:** `Principal.BudgetRef` field exists; `BudgetView` in `RouteSnapshot` is defined.

### T-LOOP-PROTECT — Recursive loop protection
- **Feature:** Fingerprint-based agent-loop detection; auto-kill.
- **Signal:** First runaway agent incident (unexpected cost spike traced to a client-side loop).
- **Effort:** M.
- **Prep:** Per-session request history is retained in `SessionVault` metadata.

---

## Persistence

### T-KEYVAULT-KEYRING — Cross-platform native keyring **PARTIALLY FIRED: 2026-07-24**
- **Feature:** Store user-supplied API keys via the OS-native credential store on all three desktop platforms (Windows Credential Manager / macOS Keychain / Linux Secret Service).
- **Fired for:** Windows only (DPAPI-encrypted files under `%LOCALAPPDATA%\cloakline\keys\`, direct syscall — no external dep). Shipped alongside dashboard-managed keys and `cloak launch`.
- **Waiver rationale:** The OS keyring is not a database — the OS owns the secret lifecycle. Single-user, per-machine only; no sync, no export. This is the smallest possible T-PERSIST-adjacent surface. Non-Windows platforms fall back to the in-memory backend until a native implementation lands.
- **Signal for macOS / Linux:** first user report on either platform.
- **Effort remaining:** S (macOS Keychain via `security` CLI or Go binding; Linux Secret Service via `dbus`).

### T-PERSIST — Any persistence layer
- **Feature:** Move state from in-memory to a durable store (SQLite first, then Postgres).
- **Signal:** Multi-node deployment demand, OR audit-replay requirement, OR resident-state exceeds 100 MB, OR restart-loss becomes a customer complaint.
- **Effort:** XL (touches every stateful subsystem).
- **Prep in Phase 0:** All state accessed through interfaces (`SessionVault`, `BudgetStore`, `AuditSink`) — none read a Go map directly at call sites; adding a persistent implementation should not require API changes.

### T-AUDIT-CHAIN — Hash-chained audit log
- **Feature:** Tamper-evident append-only audit log with per-entry hash chain.
- **Signal:** Regulated buyer engagement (GDPR / HIPAA / EU AI Act reference), OR first compliance audit.
- **Effort:** M.
- **Prep in Phase 0:** `AuditSink` interface with a `Write(entry AuditEntry)` method; JSONL implementation for local development.

---

## Enterprise Surface

### T-SSO — SSO integration (Okta / Entra ID)
- **Signal:** Named enterprise conversation asks for it.
- **Effort:** L.
- **Prep:** `Principal` has `TenantID`; auth is pluggable behind an interface.

### T-SIEM — SIEM connector
- **Signal:** Enterprise deployment demands centralized security telemetry.
- **Effort:** M (per SIEM target).
- **Prep:** All security-relevant events flow through the `AuditSink` interface; SIEM sinks slot in.

### T-ADMIN-UI — Web administrative console
- **Feature:** React-based console for DLP rules, budgets, key rotation, dashboards.
- **Signal:** >3 config-change requests from the same operator in a month.
- **Effort:** XL.
- **Prep:** Reserved URL space at `/admin/*`.

### T-CONFIG-SIGN — Signed config bundles
- **Feature:** Config source must carry a signature verified at boot.
- **Signal:** First governance incident (verbose logs in prod, DLP disabled), OR enterprise ask.
- **Effort:** M.
- **Prep:** Config compiles to a hashed IR — signing wraps the IR hash.

---

## Deployment

### T-DARK — zrok / OpenZiti dark-endpoint mode
- **Feature:** Outbound-only overlay networking.
- **Signal:** Cross-machine deployment demand or user requests "no listening ports."
- **Effort:** M.
- **Prep:** `Transport` interface allows outbound-initiating transports.

### T-HA — Multi-node / HA deployment
- **Signal:** First customer runs > 1 gateway instance in production.
- **Effort:** XL (state coordination, session affinity).
- **Prep:** All state is per-request or in explicit interfaces; global mutable state is disallowed by design.
- **Blocks:** T-PERSIST.

---

## Content / Modality Extensions

### T-PDF — PDF extractor
- **Signal:** User submits a PDF payload OR uses a client that inlines PDF content.
- **Effort:** M.

### T-OFFICE — Office document extractor (docx/xlsx/pptx)
- **Signal:** User submits an Office document payload.
- **Effort:** M.

### T-VIDEO — Video extractor + DLP
- **Signal:** Customer workflow involves video (rare).
- **Effort:** XL.
- **Prep:** `Modality.ModVideo` exists.

### T-AUDIO — Audio unary DLP
- **Signal:** T-DLP-AUDIO fires, OR user submits audio via HTTP.
- **Effort:** L.

---

## Safety

### T-MCP-SAFETY — MCP tool-argument safety
- **Feature:** Per-tool argument schema validation, path-traversal prevention, shell-metachar rejection.
- **Signal:** T-MCP fires. **Must land in the same release.**
- **Effort:** M.
- **Prep:** Guardrail interface already applies to `Content` with `Origin=ToolOutput`.

---

## Review Cadence

Every quarter:
1. Walk through this document.
2. For any deferred feature, ask: has the tripwire signal been observed?
3. If yes: schedule implementation, update the matrix in `data-flow.md`, note the trigger date here.
4. If no: leave the entry as-is.
5. If a tripwire needs revision (signal too vague, too aggressive, too conservative): edit here with a note explaining the change.

## Deprecation

When a tripwire fires and a feature ships:
1. Mark the entry with `**FIRED:** YYYY-MM-DD`.
2. Move a summary to a `history` section at the end of this file.
3. Update `data-flow.md` and `interface-contracts.md` accordingly.

No entry is ever deleted — kept for institutional memory.

---

## History (fired tripwires)

- **2026-07-23 — T-ANTHRO fired.** Anthropic Messages API adapter + `/v1/messages` ingress shipped. Extended `Principal` auth to accept `x-api-key` alongside `Authorization: Bearer`. Providers can now be `kind: anthropic` in `providers.yaml`.
