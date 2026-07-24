# Telemetry

All metrics flow through the `Meter` interface. Metric names and dimension keys are constants declared in `internal/obs/meter/names.go`. Emission sites reference the constants — free-form strings at emission sites cause a compile-time failure (via a linter rule) and are grounds for immediate review rejection.

## Why Fixed Vocabulary

Every gateway that let stages export their own metrics ended up with name collisions, exploding cardinality, and dashboards that stopped rendering. Fixing the vocabulary up front trades a small amount of emission friction for long-term navigability.

## Metric Names

### Request lifecycle

| Name | Type | Description |
|---|---|---|
| `policyd_requests_total` | Counter | One per request, incremented on ingress. |
| `policyd_requests_in_flight` | Gauge | Currently executing. |
| `policyd_request_duration_seconds` | Histogram | Total time from ingress to final byte to client. |
| `policyd_request_bytes_in` | Histogram | Bytes read from the client. |
| `policyd_request_bytes_out` | Histogram | Bytes written to the client (streaming: cumulative). |

### Stage-level

| Name | Type | Description |
|---|---|---|
| `policyd_stage_duration_seconds` | Histogram | Per-stage wall time. |
| `policyd_stage_errors_total` | Counter | Failures per stage. |
| `policyd_stage_skipped_total` | Counter | Stages skipped due to short-circuit. |

### DLP

| Name | Type | Description |
|---|---|---|
| `policyd_dlp_findings_total` | Counter | Redaction events by kind. |
| `policyd_dlp_scan_duration_seconds` | Histogram | Per-scan time. |
| `policyd_vault_active_sessions` | Gauge | Session vaults in `Streaming` state. |

### Routing

| Name | Type | Description |
|---|---|---|
| `policyd_route_decisions_total` | Counter | Decisions by chosen upstream and policy. |
| `policyd_route_no_candidate_total` | Counter | Policy returned no upstream. |
| `policyd_route_policy_eval_seconds` | Histogram | CEL evaluation time. |

### Upstream

| Name | Type | Description |
|---|---|---|
| `policyd_upstream_requests_total` | Counter | Requests sent to each upstream. |
| `policyd_upstream_errors_total` | Counter | Errors by upstream and error class. |
| `policyd_upstream_duration_seconds` | Histogram | Upstream RTT (unary) or TTFB (streaming). |
| `policyd_upstream_health` | Gauge | 1=healthy, 0=unavailable; per upstream. |
| `policyd_upstream_tokens_in_total` | Counter | Input tokens billed by upstream. |
| `policyd_upstream_tokens_out_total` | Counter | Output tokens billed by upstream. |

### Streaming

| Name | Type | Description |
|---|---|---|
| `policyd_stream_ttfb_seconds` | Histogram | Time-to-first-byte for streaming responses. |
| `policyd_stream_chunk_count` | Histogram | Chunks per stream. |
| `policyd_stream_backpressure_events_total` | Counter | Times the return-path buffer hit its cap. |

### Auth

| Name | Type | Description |
|---|---|---|
| `policyd_auth_failures_total` | Counter | Failed key resolutions by reason. |
| `policyd_auth_key_expiries_total` | Counter | Requests rejected due to expired key. |

### Governance / integrity

| Name | Type | Description |
|---|---|---|
| `policyd_config_hash` | Gauge | Current config content hash as a floating-point-encoded value (see caveat below). |
| `policyd_config_load_timestamp_seconds` | Gauge | Unix time of last successful config load. |
| `policyd_component_version` | Gauge | Info metric: dimensions carry the interface name, impl name, version. Value always 1. |

*Caveat on `policyd_config_hash`*: Prometheus gauges are floats. We emit the low 52 bits of the SHA-256 hash. This is not intended to be reversed — it exists to detect config drift across instances (same hash → same config).

## Dimension Vocabulary

All allowed dimension keys, as constants in `names.go`:

| Key | Meaning | Cardinality budget |
|---|---|---|
| `tenant` | `Principal.TenantID` | Low (< 1000 tenants) |
| `principal` | `Principal.KeyID` (not the key itself) | Medium (< 10,000 keys) |
| `stage` | `Stage.ID()` | Fixed (< 30) |
| `outcome` | `success` \| `client_error` \| `policy_blocked` \| `upstream_error` \| `timeout` \| `panic` | Fixed (< 10) |
| `upstream` | `Upstream.ID()` | Fixed (< 30) |
| `upstream_kind` | `Upstream.Kind()` | Fixed (< 20) |
| `route_policy` | `PolicyRuleID` | Low (< 100) |
| `mode` | `unary` \| `streaming` | Fixed (2) |
| `modality` | `text` \| `image` \| ... | Fixed (< 10) |
| `finding_kind` | `ssn` \| `credit_card` \| `email` \| ... | Fixed (< 50) |
| `error_class` | `rate_limit` \| `unavailable` \| `client_abort` \| `provider` \| `unknown` | Fixed (< 10) |
| `component` | Interface name, for `policyd_component_version` | Fixed (< 30) |
| `impl` | Implementation name, for `policyd_component_version` | Low (< 100) |
| `version` | Version string, for `policyd_component_version` | Low |

**Explicitly forbidden dimension keys:**

- `request_id` — unbounded cardinality. Belongs in logs, not metrics.
- `prompt` / any content substring — leak vector and unbounded cardinality.
- `api_key` — leak vector.
- `user` / `email` — leak vector; use `principal` instead.
- `path` / `url` — unbounded.

The linter rule blocks any call site that references a dimension key not in `names.go`.

## Cardinality Budget

Total series across the process should stay under **50,000**. This budget is monitored by a self-check metric (`policyd_metric_cardinality`) emitted every 60s that counts distinct series and warns at 40,000, refuses new dimension combinations at 50,000.

Rationale: a single-node Prometheus scrape at 15s interval can absorb 50k series without pain; above that we start paying with scrape time and dashboard latency.

## Redaction Coupling with Logs

Every DLP finding emitted as a metric (`policyd_dlp_findings_total{finding_kind="ssn"}`) must NOT be accompanied by a log line containing the plaintext. The linter also flags any `log.*` call that references a symbol tainted with `plaintext` naming (crude but effective).

## Histograms

Latency histograms use exponential buckets: `0.001s, 0.002s, 0.005s, 0.01s, 0.025s, 0.05s, 0.1s, 0.25s, 0.5s, 1s, 2.5s, 5s, 10s, 30s`.
Size histograms use: `128, 512, 2K, 8K, 32K, 128K, 512K, 2M, 8M`.

These bucket boundaries are constants shared across all size/duration histograms.

## Composition-Root Wiring

At `cmd/policyd/main.go` startup:

1. Construct one Prometheus registry.
2. Register all metrics from `names.go` with default (empty) dimension values.
3. Verify at boot that every `MetricName` constant is registered and every registered metric corresponds to a constant. Missing on either side is a build failure.
4. Expose `/metrics` on the admin port (separate from the traffic port).

## Extending

To add a new metric or dimension:

1. Add the constant to `names.go`.
2. Add a row to this document.
3. Register in the composition root.
4. Emit at the call site.

Skipping this document is grounds for review rejection. This document is the source of truth.
