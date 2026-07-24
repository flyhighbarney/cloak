# Policy Language

Policies are expressed in [CEL (Common Expression Language)](https://github.com/google/cel-spec), embedded via `cel-go` (Apache-2.0). CEL is:

- Sandboxed. Cannot spawn goroutines, allocate arbitrary memory, or call arbitrary Go.
- Statically typed. Bad references fail to compile.
- Deterministic. Same environment → same result.
- Fast. Compiled once at boot; evaluated in microseconds.

Nothing in a CEL policy can escape the sandbox to make network calls, read files, or read wall-clock time (only the snapshot's frozen `taken_at` is exposed).

## Where Policies Are Used

| Where | Purpose | Result type |
|---|---|---|
| Routing | Given a request and a snapshot, choose an upstream and a reason. | `RouteVerdict` |
| DLP (future tier) | Given content, decide whether to redact and how. | `DLPVerdict` |
| Budget (future) | Given a request estimate and budgets, allow or reject. | `BudgetVerdict` |
| Auth attribute | Compute derived attributes on a `Principal` from raw key state. | `PrincipalAttrs` |

Phase 0 exposes only the routing environment. Others are stubs.

## Routing Environment

CEL programs used for routing see the following variables (typed; compile-time checked):

```
request  RequestView          // read-only view of the canonical Request
snapshot SnapshotView         // read-only view of RouteSnapshot at request time
principal PrincipalView       // read-only view of Principal
```

### RequestView fields

```
request.id                    string
request.mode                  string        // "unary" | "streaming"
request.modalities            list<string>  // ["text"] for phase 0
request.parts_count           int
request.total_bytes           int           // sum of all parts' Bytes length
request.text_char_count       int           // 0 for non-text
request.has_tools             bool
request.tool_names            list<string>
```

Deliberately omitted from routing env: raw prompt bytes. Routing does not read content — that would tie policies to prompt shape and defeat the point.

### PrincipalView fields

```
principal.tenant_id           string
principal.scopes              list<string>
principal.routing_policy_id   string
principal.metadata            map<string,string>
```

### SnapshotView fields

```
snapshot.taken_at             timestamp
snapshot.candidates           list<UpstreamView>

// per candidate:
upstream.id                   string
upstream.kind                 string        // "openai" | "ollama" | ...
upstream.health               string        // "healthy" | "degraded" | "cold" | "unavailable"
upstream.caps.modalities      list<string>
upstream.caps.streaming       string        // "sse" | "ws" | "none"
upstream.caps.max_context     int
upstream.caps.tools           list<string>
upstream.caps.json_mode       string
upstream.caps.reasoning       string
upstream.queue_depth          int
upstream.est_cost_per_1k_in   double
upstream.est_cost_per_1k_out  double
upstream.recent_error_rate    double        // 0.0–1.0 over recent window
```

### Return type

A routing policy returns a `RouteVerdict`:

```
RouteVerdict {
  upstream_id: string,      // must be in snapshot.candidates
  reason: string,           // human-readable
  score: double,            // optional; higher = more preferred (for tie-breaking across policies)
}
```

If a policy raises or returns `null`, the router logs the failure and falls through to the next policy in the principal's chain. If no policy in the chain returns a valid verdict, the request fails with `ErrCapMismatch`.

## Built-in Functions

CEL's standard library, plus these injected helpers:

```
matches_modality(u, mods)  bool     // u.caps.modalities covers all mods
supports_streaming(u)      bool     // u.caps.streaming != "none"
supports_tools(u)          bool     // len(u.caps.tools) > 0
cheapest(candidates)       upstream // lowest est_cost_per_1k_in
warmest_local(candidates)  upstream // health=="healthy" and kind not in ["openai","anthropic","gemini"]
```

Adding a helper is a minor version bump on the policy env. Removing or changing a signature is a major version bump. See [versioning.md](versioning.md).

## Example: The Phase 0 Routing Policy

Only one policy is required for Phase 0: pick the first OpenAI candidate that is healthy and supports the requested mode.

```cel
// policies.cel — "openai-default-v1"
request.mode == "streaming"
  ? snapshot.candidates
      .filter(u, u.kind == "openai"
                && u.health == "healthy"
                && supports_streaming(u))
      .map(u, RouteVerdict{
        upstream_id: u.id,
        reason: "openai + streaming + healthy",
      })[0]
  : snapshot.candidates
      .filter(u, u.kind == "openai" && u.health == "healthy")
      .map(u, RouteVerdict{
        upstream_id: u.id,
        reason: "openai + healthy",
      })[0]
```

## Config File Structure

```yaml
# policies.cel is a plain text file of CEL, one policy per stanza.

policies:
  - id: openai-default-v1
    api_version: v1.0
    kind: routing
    expression: |
      # ... the CEL above ...

  - id: dlp-tier1-default-v1
    api_version: v1.0
    kind: dlp
    expression: |
      # deferred; stub for Phase 0
      DLPVerdict{ action: "redact_ssn", pattern: "ssn" }
```

## Guarantees

- **Determinism.** Two evaluations with the same `(request, snapshot, principal)` produce the same verdict. Property-tested.
- **No I/O.** Compile-time enforced by the restricted environment.
- **Bounded execution.** CEL evaluations are constrained by `cel-go`'s configurable cost budget; each policy has a max cost of 10,000 units (typical route policy is under 200).
- **Typed.** Reference to an undefined field fails compilation.
- **Versioned.** Environment has a version; policies declare which env version they compile against.

## What CEL Is Deliberately Not Used For

- Business logic that requires wall-clock reads, network calls, or persistent state.
- Anything involving raw request bodies. Content-level decisions live in stage code (Go).
- Anything performance-critical on the streaming path per chunk (stage code instead).

## When to Escape CEL

If a routing decision needs data the environment does not expose, the correct move is:

1. Add the field to the environment (minor version bump if additive).
2. Update `RouteSnapshot` in `internal/api/` to carry the field.
3. Update the `Snapshotter` to populate it.

The wrong move is adding a Go escape hatch. If you find yourself calling into Go from a policy, the environment is missing something and should be extended.
