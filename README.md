# policyd

**Use AI without exposing your company's private information.**

A local-first AI security gateway. Drop-in OpenAI / Anthropic compatible. Redacts PII, secrets, and API keys before they leave your network. Blocks prompt injections. Every request is logged. Nothing phones home.

---

## The 60-second install

```bash
# 1. Scan a file for anything you shouldn't paste into ChatGPT (offline, no server needed):
policyctl scan contract.docx

# 2. Point any OpenAI/Anthropic SDK at your gateway:
export OPENAI_BASE_URL=https://gateway.your-company.com/v1
export OPENAI_API_KEY=sk-gw-your-team-key

# 3. Keep coding. Now you can't leak your client's data.
```

That's the whole product.

---

## Who this is for

### 👩‍💻 Developers
You're already using Cursor / Claude Code / Copilot. This adds a safety layer that catches secrets and PII *before* they reach the model — without changing your workflow. Standalone `policyctl scan` gives you a pre-flight check you can run against any file.

### 🧑‍💼 CTOs / Engineering Leaders
Fixed monthly cost. No per-request pricing you can't cap. Admin dashboard shows exactly what got blocked. Self-host in your VPC in 5 minutes with the included Docker Compose recipe.

### 🛡️ Security Leads
Open source under Apache 2.0. Read the [threat model](docs/threat-model.md). Runs entirely in your VPC. Real cloud API keys never appear in logs or metrics. Every DLP decision is deterministic and auditable. No telemetry to us.

---

## What it does

| Feature | What it means | Where it lives |
|---|---|---|
| **OpenAI + Anthropic compatible** | Any SDK works with a base-URL swap. Cursor, Claude Code, Continue, custom scripts — all supported. | [`internal/transport/http/`](internal/transport/http/) |
| **DLP with 4 action modes** | Allow / Warn / Redact (with reversible tokenization) / Block, per finding kind. | [`internal/stage/dlptier1/`](internal/stage/dlptier1/) |
| **Prompt injection defense** | 12 curated rules with weighted scoring. No ML dependency. False-positive rate < 1%. | [`internal/stage/injection/`](internal/stage/injection/) |
| **SSRF-hardened outbound** | Blocks `169.254.169.254` (cloud metadata), RFC1918, DNS rebinding, cross-host redirects. | [`internal/httpclient/`](internal/httpclient/) |
| **Reversible tokenization** | Sensitive text is replaced with a pseudonym before the upstream call, then restored on the response. The model still gives your client back their real name. | [`internal/vault/session/`](internal/vault/session/) |
| **Admin dashboard** | Server-rendered, zero JS, basic-auth gated. Live view of blocks, redactions, and warnings. | [`internal/adminui/`](internal/adminui/) |
| **Audit trail** | In-memory ring buffer (1000 entries). Never contains plaintext content — only finding kinds and rule IDs. | [`internal/audit/`](internal/audit/) |
| **Structured logging** | JSON only. Default-redacts every header matching `(?i)(key\|token\|secret\|cookie\|auth)`. | [`internal/obs/log/`](internal/obs/log/) |

---

## How it compares

| | **policyd** | LiteLLM | Portkey | Direct-to-OpenAI |
|---|---|---|---|---|
| Deployment | Single Go binary + Caddy | Requires Postgres + Redis | SaaS (or heavy self-host) | N/A |
| DLP | ✅ 4 action modes, reversible tokens | Third-party sidecar | Regex only | ❌ |
| Prompt injection defense | ✅ Rule-based + scoring | ❌ Bring-your-own webhook | External partner (paid) | ❌ |
| SSRF hardening on outbound | ✅ Built-in | ❌ | N/A (SaaS) | N/A |
| OpenAI + Anthropic ingress | ✅ Both natively | ✅ Both | ✅ Both | Single provider |
| Streaming (SSE) | ✅ | ✅ | ✅ | ✅ |
| Admin dashboard | ✅ Server-rendered, zero JS | Requires separate UI | ✅ (cloud) | ❌ |
| Runs in your VPC | ✅ | ✅ | Enterprise tier only | N/A |
| Pricing | Free (open source), flat SaaS tier | Free → $30k/yr enterprise | Log-based ($9/100k) | Per-token |
| Telemetry to vendor | **None** | None (OSS) / Enterprise features report | Yes | N/A |
| Setup time | 5 minutes | 1–2 hours | 15 minutes (cloud) | 0 min |

---

## Quick start

### For a developer trying it locally

```bash
git clone https://github.com/flyhighbarney/policyd.git
cd policyd
export OPENAI_API_KEY=sk-your-real-openai-key
go run ./cmd/policyd --config ./configs
```

Now point any OpenAI SDK at `http://localhost:4000/v1` with the dev virtual key `sk-gw-dev-alpha-000000000000` from [`configs/principals.yaml`](configs/principals.yaml).

### For a team deploying to production

See [`deploy/README.md`](deploy/README.md). One VPS, one command, HTTPS via Let's Encrypt, total cost $1–$6/month until first customer.

### For a developer who just wants the CLI

```bash
go install policyd/cmd/policyctl@latest
policyctl scan file.py
```

Or with the local build:

```bash
make build-policyctl
./bin/policyctl scan file.py
```

---

## The CLI (`policyctl`)

Two modes: **standalone** (works offline) and **client** (talks to a running gateway).

```
policyctl scan file.py                       # offline: find PII/secrets in a file
cat contract.txt | policyctl scan -          # offline: scan stdin
policyctl scan --json file.py                # offline: JSON output for tooling

policyctl login https://gateway.example.com  # save credentials
policyctl doctor                             # validate config + probe gateway
policyctl chat "summarize this contract"     # send a prompt through the gateway
```

`scan` runs the same DLP patterns the gateway uses. Use it in pre-commit hooks, CI, or just before you paste a snippet into ChatGPT.

---

## Architecture

Three planes:

1. **Transport plane** — HTTP + SSE today; MCP and WebSocket land behind [tripwires](docs/tripwires.md).
2. **Policy engine core** — DAG scheduler, CEL policies, session vault, canonical request/response types.
3. **Upstream plane** — OpenAI and Anthropic today; Ollama, Bedrock, Gemini are adapter-shaped tripwires.

Every request flows: transport → canonical model → DAG (normalize → extract → DLP + injection in parallel → reassemble) → router (pure fn of `RouteSnapshot`) → upstream → de-anonymize on return.

Full detail in [`docs/architecture.md`](docs/architecture.md). The reasoning behind every design choice is in [`docs/mission.md`](docs/mission.md).

---

## What we deliberately did NOT build

Every deferred feature is tracked in [`docs/tripwires.md`](docs/tripwires.md) with the specific signal that will force us to build it. Highlights:

- **No cloud control plane.** No account you have to create on our site.
- **No database.** All state is in-memory. Restart = fresh state.
- **No web admin editor.** Config lives in YAML. Edit, restart, done.
- **No SSO / SAML.** Deferred until an enterprise customer asks.
- **No multi-node HA.** One VPS is enough for teams of 10–100 developers.

This is a deliberate architectural constraint. When you outgrow it, [`docs/tripwires.md`](docs/tripwires.md) tells you exactly what to build.

---

## What's real vs. planned

**Shipped and working:**
- OpenAI + Anthropic ingress and upstreams (unary + SSE streaming)
- DLP with action modes (allow / warn / redact / block)
- Rule-based prompt injection defense
- Session vault with state machine
- CEL routing policies
- SSRF-hardened outbound client
- Redacting structured logs
- Prometheus metrics with fixed vocabulary
- Read-only admin dashboard
- Docker Compose + Caddy deployment recipe
- `policyctl` CLI (scan, chat, doctor, login)

**Planned (each has a tripwire in [docs/tripwires.md](docs/tripwires.md)):**
- Anthropic Claude Code / Cursor via Anthropic BYOK — works via T-ANTHRO
- Ollama / vLLM local model routing — T-OLLAMA
- Bedrock, Gemini upstreams — T-BEDROCK, T-GEMINI
- Vision/OCR DLP — T-DLP-VISION
- ONNX prompt-injection classifier — T-GUARD-INJECT
- MCP transport — T-MCP
- WebSocket (Realtime) transport — T-REALTIME
- Hash-chained audit log for compliance — T-AUDIT-CHAIN
- SSO / SIEM integrations — T-SSO / T-SIEM

---

## Documentation

- [`docs/mission.md`](docs/mission.md) — Why this exists, what it deliberately isn't.
- [`docs/architecture.md`](docs/architecture.md) — The three planes, DAG scheduler, snapshot routing.
- [`docs/threat-model.md`](docs/threat-model.md) — Read this before you buy or self-host anything from anyone.
- [`docs/product-checklist.md`](docs/product-checklist.md) — Objective pass conditions for MVP, security, testing, hosting.
- [`docs/interface-contracts.md`](docs/interface-contracts.md) — The Go interfaces at the center of the codebase.
- [`docs/tripwires.md`](docs/tripwires.md) — Every feature we haven't built, and the signal that will force us to.
- [`docs/slos.md`](docs/slos.md) — Latency and reliability SLOs per payload class.
- [`docs/telemetry.md`](docs/telemetry.md) — Metric-name vocabulary.
- [`docs/data-flow.md`](docs/data-flow.md) — Support matrix of transport × modality × mode × upstream.
- [`docs/policy-language.md`](docs/policy-language.md) — CEL policy environment reference.
- [`docs/versioning.md`](docs/versioning.md) — Component API and config schema version rules.

---

## License

Apache 2.0. Use it, fork it, sell services on it. See [`LICENSE`](LICENSE) *(add before flipping public)*.

---

## Contact

Open an issue in this repo. For anything security-sensitive, write to the address in `SECURITY.md` *(add before flipping public)*.
