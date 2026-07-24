# Product Checklist — Solo-Founder, $0-Budget MVP

This is the checklist a solo technical founder with no funding can execute against to ship a sellable AI Security Gateway. Every item has a **pass condition** — objective, checkable, no hand-waving.

**Assumptions baked in:**
- One person doing everything (code, ops, sales, support).
- No paid infrastructure until first paying customer covers it.
- Zero dependencies on external SaaS with monthly minimums.
- Product must be demoable end-to-end within 15 minutes of a prospect's first hello.

**Rules of thumb:**
- If a checklist item requires >2 people to complete: cut it.
- If a checklist item costs >$0/mo before revenue: cut it, defer it, or find a free-tier substitute.
- If you cannot demonstrate the pass condition to a customer in <60 seconds: rewrite the item.

---

## Part 1 — MVP Product Specification

The minimum feature set required to say "we have a product." Each item is a hard gate on shipping.

### 1.1 Gateway core

- [ ] **OpenAI wire compatibility.** Any OpenAI SDK works by changing `base_url` and nothing else.
  - Pass: `openai-python` and `openai-node` official SDKs both complete a `chat.completions.create()` call through the gateway against real OpenAI.
- [ ] **Streaming support.** Server-Sent Events pass through with first-chunk latency < 500 ms overhead vs. direct.
  - Pass: `stream: true` returns a working generator; TTFB measured with `curl -N`.
- [ ] **Virtual keys.** Customer never sees the real cloud API key. Gateway holds it server-side.
  - Pass: `grep sk-proj- logs/*` returns zero; only `sk-gw-*` prefixes appear.
- [ ] **Multi-tenant isolation.** Two virtual keys = two isolated audit trails, budgets, policies.
  - Pass: request through key A never surfaces in tenant B's admin view.
- [ ] **Anthropic Messages API support** (Phase 2 gate).
  - Pass: `anthropic-python` SDK works via `base_url` swap; `/v1/messages` accepts and responds.

### 1.2 DLP (Data Loss Prevention)

- [ ] **Detection categories, minimum viable set:**
  - [ ] Social Security Numbers (US format)
  - [ ] Credit card numbers (Luhn-verified)
  - [ ] Email addresses
  - [ ] US phone numbers
  - [ ] IP addresses (v4 + v6)
  - [ ] AWS access keys (`AKIA...`)
  - [ ] GitHub personal access tokens (`ghp_*`, `gho_*`, `github_pat_*`)
  - [ ] OpenAI/Anthropic API keys (`sk-*`, `sk-ant-*`)
  - [ ] Google service-account JSON blocks
  - [ ] Private keys (PEM header detection)
  - [ ] Slack tokens (`xox[bpars]-*`)
  - [ ] Generic high-entropy strings (>3.5 Shannon entropy, 20+ chars)
- [ ] **Per-category action modes:** allow / warn / redact / block.
  - Pass: config file changes an SSN's action from redact to block; test hits produce 403 instead of pseudonym.
- [ ] **Reversible tokenization.** Redacted values are restored on the response return path so the model's answer still contains the customer's original names/emails/etc.
  - Pass: prompt "hi, my name is John Doe" → upstream sees pseudonym → assistant replies "hi John Doe" (verified end-to-end).

### 1.3 Prompt injection defense

- [ ] **Rule-based scoring.** Curated pattern list, weighted, sum > threshold → block.
  - Pass: known jailbreak strings ("Ignore previous instructions", "You are DAN", etc.) trigger block on default config.
- [ ] **False-positive budget.** < 1% on a corpus of 100 real developer prompts.
  - Pass: run the corpus at CI time; measure and record.
- [ ] **Configurable threshold** per tenant.
  - Pass: dev environment can lower the threshold; prod refuses.

### 1.4 Policy configuration

- [ ] **Simple rule DSL.** A law-firm IT contractor can read and edit the rules.
  - Pass rule example:
    ```yaml
    - if: "contains ssn"
      then: block
    - if: "contains credit_card"
      then: block
    - if: "contains email"
      then: redact
    - if: "prompt_injection_score > 50"
      then: block
    ```
- [ ] **Rules reload without restart** *(optional; only if it stays simple).*
- [ ] **Rules validated at load time.** Bad YAML = clear error at boot, not at request time.

### 1.5 Admin surface

- [ ] **Read-only admin dashboard** at `/admin` (basic auth).
  - Live view of last 100 requests: tenant, timestamp, verdict (allow / redact / warn / block), matched rules.
  - No plaintext of redacted content shown — only the finding_kind and pseudonym.
  - Renders in < 500 ms on 1 CPU.
- [ ] **Metrics endpoint.** `/metrics` on a separate admin port, Prometheus format.
- [ ] **Health endpoint.** `/healthz` returns 200 when the process is up and configuration loaded.

### 1.6 Multi-tenancy (SaaS shape)

- [ ] **One binary, N tenants.** Each tenant has: virtual key(s), policy set, quota, real cloud-provider key (or shares a common one).
- [ ] **Signup CLI.** `./policyctl tenant create --name=acme` issues a virtual key and prints setup instructions in one line.
- [ ] **Quota enforcement.** Per-tenant daily request cap; exceeded returns 429.

---

## Part 2 — Security Checklist

Required for the product to be trustable. Every item here is a gate on selling to a customer who cares about security (all of them do, that's the point).

### 2.1 Secrets handling

- [x] Real cloud API keys never appear in logs. Default log redaction covers `Authorization`, `x-api-key`, and any header matching `(?i)(key|token|secret|cookie|auth)`. **Automated grep test in CI: not yet wired.**
- [x] Real cloud API keys never appear in metrics or dimension labels. Fixed dimension vocabulary in `internal/obs/meter/names.go`.
- [x] Real cloud API keys are read from environment variables only; never from git-tracked files. Config loader refuses `api_key: ...` inline in `providers.yaml`.
- [x] Virtual keys are stored hashed (SHA-256) in `auth.Store`; plaintext accepted only during registration.
- [x] Authorization header value is redacted in every log line (`<redacted len=N sha256-first-8=XXXX>`).
- [x] Any header matching `(?i)(key|token|secret|cookie|auth)` is redacted in logs.
- [x] `.gitignore` prevents accidental commit of `.env`, `.env.*`, `*.pem`, `*.key`, `*_rsa`, `*_ed25519`, `credentials.json`.

### 2.2 Outbound network safety

- [ ] SSRF-hardened HTTP client (already implemented — see `internal/httpclient/ssrf.go`).
  - [ ] Scheme allowlist (default `https`; `http` only for declared local upstreams).
  - [ ] Refuses `169.254.0.0/16` (cloud metadata endpoints).
  - [ ] Refuses `127.0.0.0/8` and `::1` unless upstream is declared local.
  - [ ] Refuses RFC1918 (`10/8`, `172.16/12`, `192.168/16`) and CGNAT (`100.64/10`) unless whitelisted.
  - [ ] DNS resolves once per connection; refuses to reconnect to a different IP (blocks DNS rebinding).
  - [ ] Refuses cross-host redirects; max 3 same-host redirects.
- [ ] No outbound HTTP CONNECT proxy discovery from environment (`HTTPS_PROXY` etc. are ignored unless explicitly configured).

### 2.3 Ingress hardening

- [ ] Request body size cap (default 4 MiB); returns 413.
- [ ] JSON nesting depth cap (32); rejects deeper.
- [ ] YAML config file size cap (128 KB); YAML `KnownFields(true)`; no aliases.
- [ ] HTTP timeouts:
  - [ ] `ReadHeaderTimeout` 5 s
  - [ ] `IdleTimeout` 60 s
  - [ ] Request timeout (unary) 30 s
  - [ ] Streaming inactivity timeout 60 s
- [ ] Per-IP connection cap (100 concurrent).
- [ ] Panic recovery around every handler; panic returns 500 with a request ID; does not corrupt shared state.
- [ ] TLS terminated by Caddy (Let's Encrypt) in the deployment recipe; the Go binary listens on localhost only when behind Caddy.

### 2.4 Auth

- [ ] Virtual keys prefixed with `sk-gw-` (recognizable, distinctive for secret scanners).
- [ ] Constant-time key comparison.
- [ ] Expired keys refused with 401.
- [ ] Missing / malformed `Authorization` returns 401 with a stable error shape.
- [ ] `x-api-key` header supported for Anthropic-style ingress (Phase 2).

### 2.5 Governance invariants

- [ ] `env: prod` in config refuses to boot with `security: dev` or `security: permissive`.
- [ ] `env: prod` refuses to boot with `LOG_LEVEL=debug`.
- [ ] Inline API keys in providers.yaml refused at boot; must reference env vars.
- [ ] Config hash exported as a metric so drift between instances is detectable.
- [ ] Config change requires process restart (Phase 0 — no hot reload).

### 2.6 Data at rest and in flight

- [ ] TLS 1.2+ only on the public listener (Caddy default).
- [ ] No persistence in Phase 0 — nothing at rest. Vault is in-memory, per-session, zeroized on close.
- [ ] Audit log optional; if enabled, written to JSONL append-only file with strict permissions.
- [ ] Backups (when persistence lands): encrypted at rest with a customer-provided key.

### 2.7 Third-party risk

- [ ] Every Go dependency has a permissive license (Apache-2.0 / MIT / BSD).
  - Pass: `go-licenses check ./...` returns 0 non-permissive matches.
- [ ] Dependency count is minimal:
  - Pass: `go list -m all | wc -l` < 25.
- [ ] `govulncheck ./...` returns clean in CI.
- [ ] Container base image is distroless (`gcr.io/distroless/static-debian12:nonroot`).
- [ ] Container runs as non-root.
- [ ] No shell in the container image.

---

## Part 3 — Testing Checklist

Evidence that the product is complete and has no known security flaws. Each item is a test that either exists in the repo or must be added before shipping.

### 3.1 Unit tests

- [ ] `httpclient/ssrf_test.go` — every allow/deny rule has a case.
- [ ] `dlptier1/dlp_test.go` — every finding kind:
  - [ ] Positive: known-good pattern matches.
  - [ ] Luhn negative: 16-digit non-card doesn't match.
  - [ ] Action = redact: text mutated, pseudonym returned.
  - [ ] Action = block: `ErrDLPBlocked` returned.
  - [ ] Action = allow: text unchanged, no finding.
  - [ ] Action = warn: pseudonym returned, warnings signal populated.
- [ ] `injection_test.go` — top-20 jailbreak strings from an open corpus all score above threshold.
- [ ] `vault/session_test.go` — state machine transitions: illegal transitions return error; Close zeroizes.
- [ ] `obs/log_test.go` — redaction, sanitization, level filter.
- [ ] `auth/keys_test.go` — expiry, unknown key, prefix enforcement, constant-time.
- [ ] `router/cel_test.go` — determinism property test (same input → same output over 1000 random snapshots).
- [ ] `config/config_test.go` — every governance invariant refuses to boot on violation.
- [ ] `engine/dag_test.go` — cycle detection, level ordering, mode enforcement.

### 3.2 Integration tests

- [ ] End-to-end unary against a mock upstream (`httptest.Server`) that echoes the request body.
  - Pass: submit `"my ssn is 123-45-6789"` → upstream receives `"my ssn is [SSN_1_xxx]"` → response reaches client as `"...123-45-6789"` (de-anonymized).
- [ ] End-to-end streaming with SSE.
  - Pass: mock upstream streams 20 chunks; all 20 arrive at client in order; vault opens/drains/closes cleanly.
- [ ] Block path.
  - Pass: SSN present with `action: block` → client sees 403 with error body; upstream never called.
- [ ] Auth failures.
  - Pass: missing/expired/malformed key → 401.
- [ ] Body too large.
  - Pass: 5 MiB body → 413.

### 3.3 Security tests (must-run before every release)

- [ ] **SSRF regression suite.** Fire requests at the SSRF client with:
  - [ ] `http://169.254.169.254/` — refused.
  - [ ] `http://10.0.0.1/` — refused (unless AllowPrivate).
  - [ ] `http://127.0.0.1/` — refused (unless AllowLoopback).
  - [ ] `http://[::1]/` — refused (unless AllowLoopback).
  - [ ] `http://[fe80::1]/` — refused.
  - [ ] Redirect chain crossing hosts — refused.
  - [ ] Loop of 4+ same-host redirects — refused.
  - [ ] DNS rebinding attempt (test resolver returns public IP first, then link-local) — pinned to first IP.
- [ ] **Log leak audit.**
  - [ ] Grep logs of the integration test suite for `sk-proj-`, `sk-ant-`, `AKIA`, `ghp_` — must be zero hits.
  - [ ] Grep logs for `123-45-6789` (planted SSN in test suite) — must be zero hits.
- [ ] **Config fuzz.** Feed the loader:
  - [ ] Billion-laughs YAML (should refuse).
  - [ ] Deep nesting (>16) — refused.
  - [ ] Unknown fields — refused.
  - [ ] CEL syntax error in policy — refused with actionable message.
- [ ] **Governance boot invariants.**
  - [ ] `env: prod` + `security: dev` — refuses to boot.
  - [ ] `env: prod` + `LOG_LEVEL=debug` — refuses to boot.
  - [ ] Inline `api_key: sk-...` in providers.yaml — refuses to boot.
- [ ] **Race detector clean.** `go test -race ./...` — must pass.
- [ ] **`govulncheck`** clean before release tag.

### 3.4 Manual verification (pre-launch)

- [ ] Fire a Cursor / Continue / OpenAI-SDK request against a fresh deploy, no code changes needed except `base_url`.
- [ ] Trigger every DLP category from a browser via curl and verify:
  - [ ] Action = redact → upstream sees pseudonym.
  - [ ] Action = block → 403 with clear message.
- [ ] Kill the process mid-stream — client sees a clean error, not truncated content.
- [ ] Restart the process — new requests succeed within 3 seconds.
- [ ] `docker run` on a fresh machine with no config changes → dev key works.

### 3.5 Ongoing (post-launch weekly)

- [ ] `govulncheck` on Monday morning.
- [ ] Review flagged-request log for false positives / true negatives.
- [ ] Manual test one prompt-injection payload from a recent CVE / jailbreak repo.
- [ ] Verify config hash matches across all running instances.

---

## Part 4 — Hosting & Operations Checklist (Solo, $0 Budget)

Every item costs $0/mo until first paying customer.

### 4.1 Infrastructure (before revenue)

- [ ] **Domain.** One `.dev` or `.app` domain (~$12/yr — the only unavoidable cost).
- [ ] **DNS.** Cloudflare free tier.
- [ ] **VPS.** Oracle Cloud Always Free (2 ARM VMs, 24 GB RAM total, forever free) OR Fly.io free tier OR a Hetzner CX11 (€4/mo — the second unavoidable cost if you want reliability).
  - Pass: `ssh` in, run `docker-compose up`, gateway responds on TLS.
- [ ] **TLS.** Caddy auto-provisions Let's Encrypt cert. Zero config.
- [ ] **Observability.** Grafana Cloud free tier (10k series, 14-day retention). Set up as a Prometheus scrape target of the gateway's `/metrics`.
- [ ] **Uptime monitoring.** BetterStack free tier or UptimeRobot free tier — one monitor on `/healthz`.
- [ ] **Error tracking.** Sentry free tier (5k events/mo) OR just structured logs to Grafana Loki free tier.
- [x] **Git hosting.** GitHub free — [github.com/flyhighbarney/policyd](https://github.com/flyhighbarney/policyd) (private).
- [x] **`.gitignore` in place.** Excludes `.env`, private keys (`*.pem`, `*.key`, `*_rsa`, `*_ed25519`), build artifacts, IDE files, OS junk. Only `.env.example` is tracked.
- [ ] **CI.** GitHub Actions free tier (2000 min/mo — plenty). Not yet wired.
- [ ] **Container registry.** GitHub Container Registry free for public images. Not yet wired.

### 4.2 Deployment recipe

- [ ] Docker Compose file in repo: `caddy`, `policyd`, one shared volume for config.
- [ ] `.env.example` file listing every env var (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `ADMIN_PASSWORD`, `DOMAIN`).
- [ ] `deploy.sh` — one command that a founder runs on a fresh VPS: pulls latest image, restarts container.
- [ ] Rollback: previous image tag kept; `deploy.sh --rollback` reverts.

### 4.3 Operations (solo-runnable)

- [ ] Runbook (`docs/runbook.md`) covering:
  - [ ] "How do I add a customer?" — one command.
  - [ ] "How do I rotate a customer's key?" — one command.
  - [ ] "How do I see what happened during an incident?" — grep + admin view.
  - [ ] "Customer says their block is a false positive — how do I disable a rule for them?" — YAML edit + restart.
- [ ] Alerting:
  - [ ] `/healthz` fails for > 60 s → email you.
  - [ ] Error rate > 5% over 5 min → email you.
- [ ] Backup: `providers.yaml` and `principals.yaml` synced to a private GitHub repo daily via a cron.

### 4.4 Legal / trust (before first customer)

- [ ] Privacy policy (free template — auto-generated from termsfeed.com or similar). Say honestly: "we relay prompts to OpenAI/Anthropic; we redact PII before relay; we retain audit metadata only; we do not train on your data."
- [ ] Terms of service.
- [ ] `SECURITY.md` in the repo with a security contact email.
  - Repo lives at [github.com/flyhighbarney/policyd](https://github.com/flyhighbarney/policyd) (private) — add before flipping public.
- [ ] A public status page (statuspage.io free? Grafana `stat panels` shared publicly?).

### 4.5 Support surface

- [ ] Support email that goes to your inbox.
- [ ] Response SLA you can actually meet solo (e.g., "24 hours business days" — not "2 hours 24/7").
- [ ] FAQ page covering top-10 anticipated questions.

---

## Part 5 — Go-To-Market Readiness (Bare Minimum to Sell)

Not directly "product," but a solo founder needs these to convert the product into revenue. Otherwise you're building a hobby.

- [ ] Landing page with:
  - [ ] One-sentence description ("Use AI without exposing your company's private information.")
  - [ ] 3 bullet features (DLP, prompt-injection defense, drop-in OpenAI compat).
  - [ ] Screenshot / GIF of the admin view catching an SSN.
  - [ ] Signup form (email + company). Free-tier default.
- [ ] Demo video (Loom, 3 minutes max) showing the drop-in swap and a redaction.
- [ ] Pricing page. Two tiers only:
  - [ ] **Free:** 1000 requests/mo, community support, one virtual key.
  - [ ] **Team ($49/mo):** 50,000 requests/mo, email support, unlimited virtual keys, per-key policies.
- [ ] Payment collection: Stripe (no monthly minimum, only per-transaction fees).
- [ ] One case study — even if it's your own: "how [my consultancy] uses [gateway] to stop client-code leaking to ChatGPT."
- [ ] A single outbound channel: LinkedIn or cold email to a target list of 100 firms in your ICP.

---

## Cost Ledger

Everything above, priced honestly:

| Item | Cost / mo |
|---|---|
| Domain (`.dev`) | $1 (amortized) |
| VPS (Hetzner CX11 or Oracle free) | $0–$5 |
| Cloudflare DNS | $0 |
| Caddy + Let's Encrypt | $0 |
| Grafana Cloud (metrics) | $0 |
| GitHub, GH Actions, GHCR | $0 |
| BetterStack (uptime) | $0 |
| Sentry (errors) | $0 |
| Stripe (payments) | $0 fixed |
| **Total before revenue** | **$1–$6 / mo** |

If any line grows past $10/mo before a customer pays, revisit.

---

## Done Definition

The MVP is done when **all Part 1 items are checked, all Part 2 items are checked, and all Part 3.1–3.4 items are checked.** Part 4 and Part 5 gate *launch*, not *completion of the product*.

If a checkbox in Parts 1–3 cannot be honestly checked, the product is not ready. There are no "we'll fix that after launch" carve-outs for security items in Part 2 — those are what you're selling.

## Priority Order (First Six Weeks, Solo)

Week 1: Part 1.1 + 1.2 (verify what's built; add missing DLP categories).
Week 2: Part 1.3 (rule-based injection detection); Part 3.1 + 3.2 (fill test gaps).
Week 3: Part 1.4 + 1.5 (rule DSL + admin dashboard).
Week 4: Part 1.6 (multi-tenancy) + Part 4.1 + 4.2 (deploy recipe).
Week 5: Part 2 audit + Part 3.3 (security tests; fix everything that surfaces).
Week 6: Part 4.3 + 4.4 + Part 5 (ops, legal, landing page). Launch.
