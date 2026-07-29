# Service Level Objectives

SLOs are stated per **payload class**, not as fixed constants. Overhead scales with payload size, modality, and the number of stages in the DAG. The blueprint's "`T_DLP ≤ 15ms`" collapses under any real workload.

Each SLO here has:
- The class it applies to.
- The **target** (p95 unless stated otherwise).
- The **measurement method** (which metric).
- The **error budget** (what fraction of requests may miss it before we investigate).

## Payload Classes

| Class | Definition |
|---|---|
| S — Short text | Single text part, ≤ 8 KB total. |
| M — Medium text | Single text part, 8–64 KB. |
| L — Long text | Single text part, > 64 KB. |
| MM — Multimodal | ≥ 2 modalities or an image ≥ 128 KB. |
| STREAM-S | Streaming variant of Short text. |
| STREAM-M | Streaming variant of Medium text. |
| STREAM-L | Streaming variant of Long text. |

Phase 0 implements classes S, M, L, STREAM-S, STREAM-M (all text). L and STREAM-L exist as SLOs but degrade gracefully; MM is deferred.

## Latency SLOs

### Gateway overhead (excludes upstream RTT)

Measured as `cloakline_request_duration_seconds - cloakline_upstream_duration_seconds`.

| Class | Target (p95) | Target (p99) | Error budget |
|---|---|---|---|
| S | 20 ms | 40 ms | 1% |
| M | 60 ms | 120 ms | 1% |
| L | 200 ms | 500 ms | 2% |
| MM | (deferred; TBD) | — | — |
| STREAM-S | 25 ms overhead pre-TTFB | 50 ms | 1% |
| STREAM-M | 50 ms overhead pre-TTFB | 100 ms | 1% |
| STREAM-L | 150 ms overhead pre-TTFB | 300 ms | 2% |

Overhead-per-stage sub-SLOs (also p95):

| Stage | S | M | L |
|---|---|---|---|
| Normalize | 1 ms | 2 ms | 5 ms |
| ExtractText | 1 ms | 3 ms | 10 ms |
| DLP.Tier1 (regex) | 3 ms | 15 ms | 60 ms |
| Reassemble | 1 ms | 2 ms | 5 ms |
| Router (CEL) | 2 ms | 2 ms | 2 ms |

These sum to less than the class target — the remaining budget covers scheduler overhead, snapshot capture, and jitter.

### Streaming-specific

| Metric | Class | Target (p95) |
|---|---|---|
| Time to first byte to client | STREAM-S | Upstream TTFB + 25 ms |
| Time to first byte to client | STREAM-M | Upstream TTFB + 50 ms |
| Chunk-to-chunk overhead | any streaming | ≤ 3 ms per chunk |

The "chunk-to-chunk overhead" is what the vault de-anonymization and any streaming DLP add per chunk. If this creeps above the target, buffering will accumulate and client-visible latency will suffer.

## Reliability SLOs

### Success rate

Measured as `cloakline_requests_total{outcome="success"} / cloakline_requests_total`, over a 30-day rolling window.

| Outcome class | Target |
|---|---|
| Excluding client errors (4xx-equivalent) | ≥ 99.5% |
| Including client errors | ≥ 95% (informational; largely user-controlled) |

### Availability

`cloakline` availability is defined as: `/healthz` returns 200. Target: **99.9%** monthly on a single instance (single-node deployment; no HA in Phase 0).

Excluded from the availability window: operator-initiated restarts (config change, upgrade).

### Correctness invariants (binary; violation = incident)

These are not statistical SLOs — they are properties that must hold on every request. Any violation is a P1 incident.

| Invariant | How enforced |
|---|---|
| Real cloud API keys never appear in logs or metrics. | Redacting logger + log-audit test in CI. |
| Vault pseudonyms never leak across sessions. | Vault is session-scoped; property test. |
| No partially-de-anonymized response bytes ever reach the client. | Vault state machine + transport gates chunk writes on `VaultStreaming` state. |
| `Router.Select` is deterministic on `(request, snapshot)`. | Property test. |
| DAG execution respects `Requires` / `Produces` declarations. | Runtime assertion + boot-time validation. |
| Component version mismatch fails at boot. | Composition-root assertion. |
| Malformed config never leaves the engine in a partial-load state. | Config compiles to IR fully or not at all. |

## Measurement Method

Every SLO here has a query on the exposed Prometheus metrics. Example queries live in `docs/slos-queries.md` (deferred; created when the first Grafana dashboard is defined).

For Phase 0, the acceptance test suite includes:
- A load test that fires 1000 requests each of classes S and M against a mock upstream and asserts p95 overhead against these SLOs.
- A streaming test that measures per-chunk overhead against a mock chunk-generator and asserts the ≤3 ms/chunk target.

## Error Budget Policy

If a class exceeds its error budget over the rolling window:

1. **Investigate before implementing new features in the affected code path.** New DLP tiers, new stages, new routing policies — all paused for that path until the budget is restored.
2. **Post a mitigation note in the release notes** for the next version.
3. **Update the SLO** only if the target was demonstrably unrealistic — not to make a failing system look green.

## What SLOs Are NOT

- Not marketing promises. These are internal targets.
- Not per-tenant guarantees (Phase 0 is single-tenant in practice).
- Not applicable to the deferred deployments (multi-node, cross-region). Those will get their own SLO doc when the tripwire fires.

## Adding a New SLO

- New stage → new sub-SLO row per class.
- New class (e.g. MM when vision lands) → new column across every table.
- Update the acceptance test suite to include the new class/stage.

SLOs move together with implementation, not after.
