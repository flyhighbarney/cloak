# Diagnosis: proxy self-loop → Windows socket exhaustion

## Symptom (from the log dump)

Thousands of these, in three phases:

1. `tlsinspect.passthrough_failed ... "err":"... context canceled"` — for
   `api.anthropic.com` on `/api/claude_code/settings`, `/policy_limits`, `/api/hello`.
2. `http: TLS handshake error from 127.0.0.1:62568: ... wsarecv: An established
   connection was aborted by the software in your host machine.`
3. The smoking gun:
   `dial tcp 127.0.0.1:443: connectex: Only one usage of each socket address
   (protocol/network address/port) is normally permitted.` → `status 502`,
   `msg":"tlsinspect.forward_failed"`.

## Root cause: cloakline forwards to itself

Chain of events:

1. `cloak setup` writes `127.0.0.1 api.anthropic.com` into the hosts file so Claude
   Code's HTTPS traffic is redirected into cloakline's listener.
   See `cmd/cloak/cmd_setup.go:199`.
2. That hosts entry is **machine-wide** — it also applies to cloakline's own process.
3. When cloakline forwards a request upstream it builds `https://api.anthropic.com/...`
   and sends it with a **plain `http.Client` that has no custom resolver/transport**:
   - client: `internal/tlsinspect/forward.go:161`
   - used in `Handle` at `internal/tlsinspect/forward.go:301`
   - used in `forwardPassthrough` at `internal/tlsinspect/forward.go:377`
   - used in `forwardBody` at `internal/tlsinspect/forward.go:431`
4. So `api.anthropic.com` resolves back to `127.0.0.1` and cloakline **connects to its
   own listener**. Every forwarded request is an infinite loop.

No port is set on the upstream URL, so it defaults to 443 → `127.0.0.1:443`, which is
cloakline's own listener → clean self-loop.

### Why the specific errors appear

- **`context canceled`**: the loop hangs; Claude Code times out and cancels the request.
  The hundreds of near-identical lines are one stuck burst, not many separate failures.
- **`wsarecv ... connection aborted`**: looped TLS connections tearing down.
- **`Only one usage of each socket address`**: Windows **ephemeral-port exhaustion**
  (`WSAEADDRINUSE`). The self-dial loop consumed the entire outbound port range dialing
  `127.0.0.1:443` over and over.

## Why the existing SSRF dialer does not already fix this

`internal/httpclient/ssrf.go:70` has a hardened dialer, but:
- `forwardClient` in `forward.go` does **not** use it — it's a bare `http.Client`.
- Even if it did, that dialer resolves via the **OS resolver**, so it would also get
  `127.0.0.1` — and then *block* it as a loopback SSRF target. Either way, forwarding
  breaks.

## The fix (not yet applied)

Give `forwardClient` a `Transport` whose `DialContext` resolves the **real** upstream IP,
bypassing the hosts-file redirect. Shared by `Handle`, `forwardPassthrough`, and
`forwardBody`.

### Options compared

**1. Bootstrap DNS (query 1.1.1.1 / 8.8.8.8 directly)**
- Attach a custom `net.Resolver` whose internal dial goes to a fixed public DNS server
  over UDP:53, so lookups never consult the OS hosts file.
- Pros: small change, no new dependencies, uses stdlib only. Fixes the loop directly.
- Cons: depends on outbound UDP/53 being open (some corp networks block it); the DNS
  answer itself isn't authenticated (a local attacker who can already edit your hosts
  file is out of scope, so this is acceptable here).

**2. DNS-over-HTTPS (DoH)**
- Resolve `api.anthropic.com` via a DoH JSON endpoint (Cloudflare/Google) over HTTPS:443,
  then dial the returned IP.
- Pros: works where UDP/53 is blocked; the lookup is encrypted and integrity-protected,
  so it resists local DNS tampering.
- Cons: more code, an HTTP round-trip per (cached) resolution, and a bootstrap
  chicken-and-egg — you still need an IP for the DoH host itself (usually hardcoded).
  Heavier than needed for the actual bug.

**3. Pin upstream IPs in config**
- Operator sets the real `api.anthropic.com` IP(s) in cloakline's config; the forward
  dialer connects straight to those, skipping DNS entirely.
- Pros: fully deterministic, no runtime resolver, easiest to reason about and test.
- Cons: Anthropic's IPs rotate (they're behind a CDN), so pinned IPs go stale and require
  manual maintenance; brittle for a shipped product.

### Recommendation

Option **1 (bootstrap DNS)** is the right default: it's the smallest change that removes
the loop, has no new deps, and matches the threat model (if someone can rewrite your
hosts file, DoH buys little). Option 2 is a reasonable upgrade if UDP/53 blocking turns
out to be common in the field. Option 3 should be avoided for a product due to CDN IP
rotation.

## Status — FIXED

Implemented **Option 1 (bootstrap DNS)**, which preserves the project's core
concept: transparent hosts-file interception stays exactly as-is; the user never
has to reconfigure Claude Code. Only cloakline's *own* outbound dial now bypasses
the hosts file.

What changed:

- **New `internal/tlsinspect/resolver.go`**:
  - `bootstrapResolver` resolves upstream hostnames via DNS-over-HTTPS to servers
    addressed by IP literal (`1.1.1.1`, `8.8.8.8`). IP literals are never run
    through the hosts file, so the bootstrap query can't be poisoned by our own
    redirect. DoH over 443 also works where UDP/53 is blocked.
  - Answers are cached for the DNS TTL (min 30s) — one lookup per host per window.
  - `parseRoutable` guard rejects any loopback/unspecified answer, so a poisoned
    DNS reply can never re-form the self-loop.
  - `newForwardTransport` wraps dialing so the destination is resolved to a real
    IP and dialed directly.
- **`internal/tlsinspect/forward.go`**: `forwardClient` now uses that transport.
- **`internal/tlsinspect/resolver_test.go`**: locks in IP-literal passthrough,
  loopback rejection, and cache-hit behavior (all offline).

Verification: `go build ./...`, `go vet ./internal/tlsinspect/`, and
`go test ./...` all pass.

- [x] Root cause identified and confirmed against source.
- [x] Fix implemented (bootstrap DNS, philosophy preserved).
- [x] Build + vet + full test suite green.
