# Deployment — Solo Founder Quickstart

Deploy `cloakline` on a single small VPS with auto-HTTPS. Total cost: **$0–$6/month** until first customer.

## What you get

- **HTTPS** at `https://your-domain.com` — Let's Encrypt cert auto-provisioned by Caddy.
- **OpenAI-compatible** endpoint at `https://your-domain.com/v1/chat/completions`.
- **Anthropic-compatible** endpoint at `https://your-domain.com/v1/messages`.
- **Admin dashboard** at `https://your-domain.com/admin` (basic-auth gated) — live view of what got blocked, redacted, allowed.
- **Prometheus metrics** at `https://your-domain.com/metrics` (basic-auth gated).
- **Public health check** at `https://your-domain.com/healthz`.
- **One command to deploy or update:** `./deploy.sh`.

## Prerequisites

- A **VPS** with root SSH. Recommended options:
  - [Oracle Cloud Always Free](https://www.oracle.com/cloud/free/) — 2 ARM VMs, 24 GB RAM total, forever free.
  - [Hetzner CX22](https://www.hetzner.com/cloud) — ~€4/mo, Frankfurt / Ashburn.
  - [Fly.io](https://fly.io) — free tier available.
- A **domain name** (~$12/yr). Any TLD works. Cheapest reliable: Cloudflare Registrar or Porkbun.
- An **A record** on your domain pointing to the VPS's public IP.

## Install prerequisites on the VPS (one-time)

Ubuntu 22.04 / 24.04:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"    # log out and back in after this
```

Verify:

```bash
docker version
docker compose version
```

## First deployment

```bash
git clone https://github.com/YOU/cloakline.git
cd cloakline/deploy
cp .env.example .env
```

Edit `.env`:

```bash
DOMAIN=gateway.your-domain.com
ADMIN_EMAIL=you@your-domain.com
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...    # optional if you're only routing OpenAI
```

Generate the admin password hash for the `/metrics` endpoint:

```bash
docker run --rm caddy:2-alpine caddy hash-password
# enter a password when prompted
# copy the hash into .env as ADMIN_PASSWORD_HASH (keep the single quotes)
```

If the script isn't executable yet (repo cloned on Windows, etc.):

```bash
chmod +x deploy.sh
```

Deploy:

```bash
./deploy.sh
```

First run takes ~60 seconds while Let's Encrypt issues the TLS certificate. Subsequent deploys are ~10 seconds.

## Verify it works

```bash
# Public health check — no auth
curl https://gateway.your-domain.com/healthz

# Actual traffic through OpenAI ingress (using the dev virtual key)
curl https://gateway.your-domain.com/v1/chat/completions \
  -H "Authorization: Bearer sk-gw-dev-alpha-000000000000" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role":"user","content":"say hi"}]
  }'
```

## Point your tools at it

### OpenAI SDKs
```bash
export OPENAI_BASE_URL=https://gateway.your-domain.com/v1
export OPENAI_API_KEY=sk-gw-your-tenant-key
```

### Anthropic SDKs
```bash
export ANTHROPIC_BASE_URL=https://gateway.your-domain.com
export ANTHROPIC_API_KEY=sk-gw-your-tenant-key
```

### Claude Code
```bash
export ANTHROPIC_BASE_URL=https://gateway.your-domain.com
export ANTHROPIC_API_KEY=sk-gw-your-tenant-key
claude
```

### Cursor (BYOK mode)
Settings → Models → Custom OpenAI Base URL: `https://gateway.your-domain.com/v1`

## Day-to-day

| What | Command |
|---|---|
| Update after a code change | `git pull && ./deploy.sh` |
| See logs | `./deploy.sh --logs` |
| Check status | `./deploy.sh --status` |
| Roll back to previous image | `./deploy.sh --rollback` |
| Restart cloakline only | `docker compose restart cloakline` |
| Restart Caddy only | `docker compose restart caddy` |

## Add a customer

Edit `configs/principals.yaml`, add a stanza:

```yaml
- key: sk-gw-acme-law-000000000000
  tenant_id: acme-law
  key_id: acme-law-prod
  scopes: [chat:read, chat:stream]
  budget_ref: default
  routing_policy: openai-default-v1
  expiry_unix: 0
```

Then:

```bash
./deploy.sh    # picks up the config change on restart
```

Send them the key and the base URL. That's it.

## What's NOT included

- **No database.** State is in-memory. Restart = fresh state (budgets, health counters). Backups aren't needed for state, only for config.
- **No web admin.** The admin dashboard is deferred (see [docs/tripwires.md](../docs/tripwires.md) → T-ADMIN-UI). For now, edit YAML, redeploy.
- **No multi-node.** One VPS. If you outgrow it, that's the tripwire for T-HA.
- **No SLA management.** You are the SLA. Watch `/healthz`.

## Backups

The only stateful files are `configs/*.yaml`. Push them (encrypted) to a private git repo daily. Example crontab:

```
0 4 * * * cd /home/deploy/cloakline && git add configs/ && git commit -m "config snapshot $(date -Iseconds)" && git push
```

## Cost ledger

| Item | Monthly |
|---|---|
| Hetzner CX22 (or Oracle Free) | $0–$5 |
| Domain (`.dev`, amortized) | $1 |
| Let's Encrypt | $0 |
| GitHub (private repo) | $0 |
| Grafana Cloud free tier (scrape `/metrics`) | $0 |
| **Total** | **$1–$6** |

If any line grows past $10/mo before first paying customer, revisit.

## Security posture in this deployment

- `cloakline` binds only inside the docker network. Public traffic must traverse Caddy.
- Caddy terminates TLS with Let's Encrypt; automatic renewals.
- `/metrics` is basic-auth-gated (never exposed unauthenticated).
- Cloud API keys are held in `.env` on the VPS, injected as env vars. Never in git, never in logs.
- Docker containers run as non-root (via the distroless base image).
- `cloakline`'s SSRF-hardened outbound client blocks metadata endpoints (`169.254.169.254`) even if a config regression tries to reach them.

See [../docs/threat-model.md](../docs/threat-model.md) for the complete threat model.

## Troubleshooting

**Cert didn't provision.** Check that ports 80 and 443 are open on the VPS firewall, and that `DOMAIN` resolves to this VPS. `./deploy.sh --logs` will show Caddy's ACME output.

**Client gets 401.** Confirm the virtual key matches an entry in `configs/principals.yaml` and hasn't expired. Grep the logs (redacted key hash appears in `auth.failures` log lines).

**Streaming stalls or buffers.** Confirm the Caddyfile has `flush_interval -1` on the reverse_proxy directive for `/v1/*` (it does, by default in this recipe).

**Refuses to boot with "governance invariant".** You set `env: prod` in `pipeline.yaml` and either `security` is not `strict` or `LOG_LEVEL=debug`. See [../docs/threat-model.md](../docs/threat-model.md) G1/G2.
