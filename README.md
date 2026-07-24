# policyd

Local-first, transport-agnostic **AI policy enforcement engine** that exposes an OpenAI-compatible HTTP gateway.

See [docs/mission.md](docs/mission.md) for what this project is (and is not).

## Status

Delivered so far:
- Policy engine core (DAG scheduler, canonical types, CEL policies).
- HTTP+SSE transport with **OpenAI-compatible** `/v1/chat/completions` and **Anthropic-compatible** `/v1/messages`.
- OpenAI upstream adapter (Chat Completions, unary + streaming).
- **Anthropic** upstream adapter (Messages API, unary + typed SSE event stream).
- Tier-1 DLP stage (SSN, credit-card with Luhn, email) with reversible tokenization via a session-scoped vault.
- **DLP action modes:** allow / warn / redact / block, per finding kind.
- **Rule-based prompt-injection detection** with 12 curated patterns + scored blocking.
- CEL-driven routing (snapshot-based, deterministic).
- SSRF-hardened outbound HTTP client.
- Default-redacting structured logs.
- Prometheus metrics with a fixed vocabulary.

Everything else is deferred — see [docs/tripwires.md](docs/tripwires.md).

## Requirements

- Go 1.22+
- (Optional) Docker for containerized runs.

## Configure

Edit YAML under `configs/`:

- `pipeline.yaml` — listen ports, env/security markers, request limits.
- `providers.yaml` — upstream declarations; API keys come from environment, never inline.
- `principals.yaml` — virtual keys (`sk-gw-*`) mapped to tenants/scopes.
- `policies.yaml` — CEL routing policies.

Set the real cloud API key in the environment referenced by `providers.yaml`:

```bash
export OPENAI_API_KEY=sk-...      # your real OpenAI key
```

## Run

```bash
go run ./cmd/policyd --config ./configs
```

The engine binds `:4000` for traffic and `:4001` for `/healthz` + `/metrics`.

Point any OpenAI SDK at it:

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:4000/v1",
    api_key="sk-gw-dev-alpha-000000000000",   # virtual key from principals.yaml
)
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello!"}],
)
print(resp.choices[0].message.content)
```

Or any Anthropic SDK (Claude API, Claude Code):

```python
from anthropic import Anthropic

client = Anthropic(
    base_url="http://localhost:4000",         # note: no /v1 suffix; SDK adds it
    api_key="sk-gw-dev-alpha-000000000000",   # same virtual key
)
resp = client.messages.create(
    model="claude-3-5-sonnet-20241022",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello!"}],
)
print(resp.content[0].text)
```

For Claude Code specifically:

```bash
export ANTHROPIC_BASE_URL=http://localhost:4000
export ANTHROPIC_API_KEY=sk-gw-dev-alpha-000000000000
claude
```

## Test

```bash
go test ./...
go test -race ./...
```

## Build

```bash
make build         # produces ./bin/policyd
make docker        # distroless container image
```

## Layout

```
cmd/policyd/         # composition root
internal/api/        # canonical types (leaf package)
internal/engine/     # DAG scheduler
internal/transport/  # HTTP+SSE adapter
internal/upstream/   # provider adapters (OpenAI)
internal/stage/      # DAG nodes (normalize, extract, dlp, reassemble)
internal/router/     # CEL router
internal/policy/     # CEL runtime
internal/vault/      # session vault
internal/auth/       # virtual-key → Principal
internal/config/     # YAML loader + IR
internal/httpclient/ # SSRF-hardened outbound client
internal/obs/        # structured logging + Prometheus metrics
configs/             # sample configuration
docs/                # Phase 0 architecture, threat model, SLOs, tripwires
```

## Non-goals (Phase 1)

- No web admin UI.
- No persistence (all state is in-memory or config-file).
- No SSO, SIEM, or hash-chained audit log.
- No MCP or WebSocket transport.
- No prompt-injection classifier or Tier-2/3 DLP.
- No budget enforcement, loop protection, or semantic cache.

Each of these is tracked in [docs/tripwires.md](docs/tripwires.md) with the specific signal that will force it to land.
