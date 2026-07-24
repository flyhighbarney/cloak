# TLS Inspection Module

The inspection module lets **any CLI tool that talks to `api.openai.com` or `api.anthropic.com`** — including Claude Code CLI, Codex CLI, `curl`, and the vendor SDKs — get scanned transparently by policyd without any code change to the tool.

This is the same DLP/SWG (Secure Web Gateway) pattern that every corporate web filter uses for general HTTPS traffic. Applied specifically to AI-provider traffic, on the developer's own machine.

## What it does

```
    Claude Code CLI                              (user's subscription auth
        │                                          passes through untouched)
        │  HTTPS to api.anthropic.com
        │  (which /etc/hosts sends to 127.0.0.1)
        ▼
    ┌─────────────────────────────────────┐
    │ policyd tlsinspect on :8443         │
    │   1. Terminates TLS with a leaf     │
    │      cert issued by our local CA    │
    │   2. Reads request body             │
    │   3. Runs DLP + injection scoring   │
    │   4. Redacts or blocks per policy   │
    │   5. Forwards to real host          │
    │      (validated system TLS)         │
    └─────────────────────────────────────┘
        │  HTTPS to real api.anthropic.com
        ▼
    api.anthropic.com
```

The user's Anthropic OAuth token / subscription bearer goes through *exactly as sent*. policyd never inspects auth headers, never stores them, never logs their values.

## When to use it vs. the gateway proxy

| Scenario | Use |
|---|---|
| App has a configurable base URL (OpenAI SDK, Anthropic SDK, LangChain) | **Point at the gateway** on `:4000` — cleaner, no cert install |
| CLI tool with a hardcoded endpoint (Claude Code CLI, Codex, Cursor BYOK) | **Enable inspection** here |
| App with certificate pinning (mobile apps, Cursor Pro proxy) | Neither works — pinning refuses substituted certs |

## One-time setup

### 1. Generate the local CA

```bash
policyctl trust show
```

Prints the on-disk location of `ca-cert.pem` and the platform-specific install command.

### 2. Trust the CA (per-user, reversible)

```bash
policyctl trust install
```

Runs the OS's certificate-trust tool with a clear consent prompt:

- **Windows** — `certutil -user -addstore Root <cert>` (current user only)
- **macOS** — `security add-trusted-cert -k ~/Library/Keychains/login.keychain-db`
- **Linux** — Prints the command; `update-ca-certificates` requires `sudo`

Undo any time with `policyctl trust remove`.

### 3. Enable the module in `pipeline.yaml`

```yaml
inspect:
  enabled: true
  listen: ":8443"
  hosts:
    - api.openai.com
    - api.anthropic.com
```

Restart policyd. You'll see `tlsinspect.listening` in the log.

### 4. Direct AI-provider hostnames at policyd

Two options:

**Option A — /etc/hosts (simple, permanent):**

```
# /etc/hosts   (Windows: C:\Windows\System32\drivers\etc\hosts)
127.0.0.1 api.openai.com
127.0.0.1 api.anthropic.com
```

The port has to be 443 for this to work — you'll need to move policyd's inspection listener to `:443` (requires admin/root on port ≤1024).

**Option B — OS system proxy setting** (recommended for opt-in per-session use):

Point HTTPS proxy at `127.0.0.1:8443`. Only apps that honor the system proxy will be intercepted.

## Verifying it works

With the module enabled and the CA trusted:

```bash
# Send a test request that mentions PII. Note: this uses the intercepted
# hostname on the standard port (443 or your configured port).
curl -sS https://api.anthropic.com/v1/messages \
  -H "x-api-key: <your-real-anthropic-key>" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "max_tokens": 100,
    "messages": [{"role":"user","content":"My email is jdoe@acme.com — please summarize"}]
  }'
```

Watch `policyd`'s log — you should see `tlsinspect.forwarded` with `findings=1`. Then grep the log for `jdoe@acme.com` — must be 0 hits (email was tokenized before being sent to Anthropic).

## Using it with Claude Code

Claude Code CLI honors the OS trust store. Once the CA is installed:

```bash
# No env var changes needed — Claude Code will talk to api.anthropic.com
# as usual; DNS/hosts sends the connection to policyd; policyd forwards.
claude -p "hello"
```

policyd's admin dashboard at `http://localhost:4001/admin` will show the request.

## What this module deliberately does NOT do

- **Does not store or inspect your auth token.** The `Authorization` / `x-api-key` header is copied through untouched to the real upstream.
- **Does not modify successful responses beyond de-anonymizing pseudonyms.**
- **Does not phone home.** Nothing about your traffic leaves your machine except the direct forward to the real provider.
- **Does not persist request/response bodies.** Only DLP finding *kinds* enter the audit log; the content itself is never written.

## Legal / policy notes

Running a TLS-inspecting proxy on your own machine, with your own consent, is common practice (Charles Proxy, mitmproxy, Fiddler, and every corporate web filter do exactly this). But two things to be aware of:

1. **Vendor consumer ToS** may have opinions about third-party proxies. Their API ToS (the one that governs API-key usage) permits proxying; their consumer subscription ToS may be stricter. Read yours.
2. **Do not ship the CA private key.** The CA is generated per-machine. If you distribute this to teammates, each machine generates its own CA at first boot. Never copy `ca-key.pem` to another machine.

## How to remove everything

```bash
policyctl trust remove
```

This removes the CA from the OS trust store and deletes `ca-cert.pem` + `ca-key.pem` from disk. Then set `inspect.enabled: false` in `pipeline.yaml` and restart policyd. Undo `/etc/hosts` entries manually if you added any.
