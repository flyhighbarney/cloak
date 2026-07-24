# cloakline — Complete Guide

**Use AI freely without exposing your company's private information.**

cloakline is a local-first AI security gateway that sits between your development tools and AI providers (Anthropic, OpenAI). It redacts PII, secrets, and API keys before they leave your machine, blocks prompt injections, and logs every decision — without changing your workflow.

---

## Table of contents

1. [Requirements](#1-requirements)
2. [Installation](#2-installation)
3. [First run](#3-first-run)
4. [CLI reference](#4-cli-reference)
5. [Configuration](#5-configuration)
6. [Security model](#6-security-model)
7. [Uninstall](#7-uninstall)
8. [Troubleshooting](#8-troubleshooting)
9. [FAQ](#9-faq)
10. [Architecture overview](#10-architecture-overview)

---

## 1. Requirements

| Requirement | Detail |
|---|---|
| **OS** | Windows 10 22H2 / Windows 11, or macOS 12+ (Monterey and later). Linux compiles and runs `cloak scan` offline, but has no bootstrap script yet — use the manual steps in §2b. |
| **Go** | 1.22 or later (to build from source) |
| **PowerShell** | 5.1+ (Windows, for balloon notifications) |
| **Admin rights** | Required only to edit `C:\Windows\System32\drivers\etc\hosts`. The daemon itself runs as your normal user account. |
| **Terminal** | Windows Terminal (recommended) or PowerShell 5.1+. CMD works but UTF-8 box-drawing characters need a Unicode font. |

---

## 2. Installation

### 2a. Fastest path — `npx cloakline install`

If you have Node.js 16+ on PATH (most developers do), this is the shortest install:

```bash
npx cloakline install
```

That does the following:

1. Downloads the platform-native binaries + scripts from the [latest GitHub Release](https://github.com/flyhighbarney/cloakline/releases) into a stable location:
   - Windows: `%LOCALAPPDATA%\cloakline\`
   - macOS: `~/.cloakline/`
2. Runs the platform's `bootstrap` script with `--skip-build` (binaries are already downloaded), which handles CA trust, hosts file, scheduled task / LaunchAgent, pf redirect on macOS, and verification.

**No cloning, no Go compiler needed.** The npm package (`node_modules/cloakline`) is only a JS shim — the daemon is a native Go binary.

Standalone subcommands work without a full install:

```bash
npx cloakline scan file.py        # offline DLP scan
npx cloakline doctor              # local health check
npx cloakline tail                # live terminal dashboard
```

The first invocation downloads only the `cloak` CLI (~10 MB). Subsequent runs use the cached binary.

**Environment overrides:**
- `CLOAKLINE_TAG=v0.1.2 npx cloakline install` — pin to a specific release
- Set `CLOAKLINE_TAG=latest` (default) to always pull newest

### 2b. Build-from-source (developers) — one-command install

#### Windows

From a fresh clone, run:

```powershell
.\scripts\bootstrap.ps1
```

That's it. The script:

1. **Self-elevates** — pops one UAC prompt to run as Administrator
2. **Builds** both binaries with `go build`
3. **Trusts the local inspection CA** — Windows shows one security dialog; click **Yes**
4. **Configures** `configs\pipeline.yaml` (flips inspect on, sets listen to `:443`)
5. **Registers a scheduled task** to run cloakline as your user at login
6. **Starts the task** and verifies cloakline is listening on `:443`
7. **Adds hosts-file entries** for `api.anthropic.com` and `api.openai.com`
8. **Verifies DNS** actually resolves those to `127.0.0.1` before declaring success

Flags: `-SkipBuild`, `-SkipTrust`.

#### macOS

From a fresh clone:

```bash
./scripts/bootstrap.sh
```

The script:

1. **Verifies Go 1.22+ is on PATH** — fast-fails before any sudo prompts
2. **Builds** both binaries with `go build`
3. **Trusts the local inspection CA** — Keychain may prompt for your login password
4. **Chains to `install.sh`**, which:
   - Sets `inspect.listen` to `:8443` in `pipeline.yaml`
   - Installs a **pf redirect** (`:443 → :8443` on `lo0`) so the daemon can stay unprivileged — needs one `sudo` for `pfctl`
   - Writes `~/Library/LaunchAgents/com.cloakline.daemon.plist` and loads it
   - Verifies cloakline is listening on `:8443` and admin `:4001` responds
   - Adds hosts entries for `api.anthropic.com` and `api.openai.com` (needs `sudo`)
   - Flushes DNS (`dscacheutil` + `mDNSResponder`) and verifies `api.anthropic.com` resolves to `127.0.0.1`

Flags: `--skip-build`, `--skip-trust`.

**macOS notes:**
- Keys are stored in your **login Keychain** under the service name `cloakline` (visible in Keychain Access.app)
- HIGH-tier notifications don't appear as balloons yet on macOS — the redaction still happens, but you check the `/admin` dashboard to see what was caught
- The pf redirect keeps the daemon unprivileged (`:8443`) while still intercepting standard `:443` traffic
- Daemon logs land in `/tmp/cloakline.log` and `/tmp/cloakline.err`

If any step fails, the hosts file is rolled back automatically so nothing is left in a half-installed state.

Requirements: Go 1.22+ on PATH (unless you use `--skip-build` / `-SkipBuild`).

### 2c. Manual install (if you prefer step-by-step)

```bash
# Clone the repo
git clone https://github.com/flyhighbarney/cloakline.git
cd cloakline

# Build both binaries (outputs to ./bin/)
make build
# or individually:
go build -trimpath -o ./bin/cloakline.exe ./cmd/cloakline
go build -trimpath -o ./bin/cloak.exe    ./cmd/cloak
```

The two binaries are self-contained — no runtime dependencies.

### 2d. Interactive setup wizard

```bash
./bin/cloak.exe setup
```

`cloak setup` is an interactive wizard that walks through four steps:

| Step | What happens |
|---|---|
| **1 — CA install** | Generates a local root CA in `%APPDATA%\cloakline\ca\` and installs it into your Windows user certificate store (certutil). This lets cloakline terminate TLS so it can inspect request bodies. |
| **2 — API keys** | Prompts for your Anthropic and OpenAI API keys and stores them in the OS keyring (DPAPI-encrypted on Windows). Never written to disk in plaintext. |
| **3 — Enable inspection** | Sets `inspect.enabled: true` in `configs/pipeline.yaml`. |
| **4 — Hosts file** | Prints the two lines to add to your hosts file. Requires Administrator Notepad; not done automatically for safety. |

After setup, optionally choose to add a startup shortcut so cloakline runs on login.

### 2e. Hosts file (required for TLS interception)

Open Notepad as Administrator and edit `C:\Windows\System32\drivers\etc\hosts`. Add:

```
127.0.0.1 api.anthropic.com
127.0.0.1 api.openai.com
```

Then in `configs/pipeline.yaml`, set `inspect.listen: ":443"` and start cloakline as Administrator (or use the Scheduled Task approach — see §5).

> **Why is this needed?** These entries redirect AI-provider hostnames to your local machine. cloakline terminates the TLS connection, inspects the body, and forwards to the real provider using its own connection. Without this step, your tools talk to providers directly and cloakline cannot see the traffic.

### 2f. Start the daemon

```bash
./bin/cloakline.exe --config ./configs
```

Verify it's running:

```bash
./bin/cloak.exe doctor
```

Expected output:
```
cloak doctor
────────────────────────────────────────
  ✓ config file: C:\Users\you\AppData\Roaming\cloak\config.yaml
  ✓ gateway URL: http://127.0.0.1:4000
  ✓ api_key: sk-gw-****...****
  ✓ gateway healthy (status: ok)
  ✓ auth and upstream OK
```

---

## 3. First run

After installation, use your AI tools **exactly as before** — no wrapper, no proxy flag, no code changes:

```bash
claude -p "help me debug this"
codex "write a test for my auth function"
```

cloakline intercepts and inspects every request silently. If it finds something sensitive:

- **HIGH tier** (API keys, passwords, credit cards): redacted silently. The AI receives `[REDACTED_API_KEY]` instead of the real value. A Windows notification appears letting you "Allow session" if the paste was intentional.
- **MEDIUM tier** (SSNs, emails, phone numbers): tokenised — the AI sees a pseudonym, you see your real data back in the response.
- **LOW tier** (IPs, URLs, names): passed through, flagged in the dashboard.

Open the dashboard any time:

```bash
cloak dashboard
# or navigate directly to:
# http://127.0.0.1:4001/admin
```

---

## 4. CLI reference

All commands: `cloak <command> [options]`

---

### `cloak setup` (alias: `cloak install`)

One-time interactive installation wizard. Idempotent — safe to run again to update keys or re-verify the CA.

```bash
cloak setup
```

---

### `cloak scan`

Scan a file or stdin for PII, secrets, and API keys **offline** — no daemon needed. Use this before pasting anything into ChatGPT, Claude.ai, or any online service.

```bash
cloak scan contract.txt          # scan a file
cat dump.sql | cloak scan -      # scan stdin
cloak scan --json report.py      # emit JSON (for scripts)
```

Exit code 0 = no findings. Exit code 1 = findings present.

**Example output:**
```
✗ contract.txt — 2 findings

  ● ssn at contract.txt:14:12
      XXX-**-XXXX
  ● email at contract.txt:22:5
      jo***@ex***.com

! Do not paste this into a public AI service.
```

---

### `cloak chat`

Send a prompt through your configured gateway and print the reply.

```bash
cloak chat "What is the capital of France?"
cloak chat --model claude-3-5-sonnet-20241022 "Explain TLS in one paragraph"
```

Requires `cloak login` or `POLICYD_GATEWAY` / `POLICYD_API_KEY` env vars.

---

### `cloak doctor`

Validate local config, ping the gateway, and verify auth with a 1-token test completion.

```bash
cloak doctor
```

Run this when something looks off. Every check prints either `✓` or a one-line actionable fix.

---

### `cloak tail`

Live terminal dashboard. Shows real-time stats (total requests, secrets caught, PII redacted, injections blocked) and a scrolling activity log.

```bash
cloak tail
```

No gateway config needed — talks directly to `http://127.0.0.1:4001`. Press Ctrl-C to exit.

**Example output:**
```
┌────────────────────────────────────────────────────────────────┐
│ cloakline  live monitor             updated 14:22:03 UTC      │
├────────────────────────────────────────────────────────────────┤
│  TOTAL SCANNED   SECRETS CAUGHT   PII REDACTED   INJECTIONS   │
│  42              3                7              0             │
├────────────────────────────────────────────────────────────────┤
│  RECENT ACTIVITY                                       live    │
│  TIME      STATUS   ENDPOINT                  DLP             │
│  14:22:01  ALLOW    /v1/messages                              │
│  14:21:58  REDACT   /v1/messages              aws_key         │
└────────────────────────────────────────────────────────────────┘
  Ctrl-C to exit · refreshes every 2s
```

---

### `cloak dashboard`

Open the admin web dashboard in your default browser.

```bash
cloak dashboard
```

The dashboard shows the same information as `cloak tail` plus:
- Full audit log table (last 100 requests)
- DLP preferences panel (override per-kind actions at runtime)
- API key management (add/remove provider keys)

---

### `cloak trust`

Manage the local TLS inspection CA.

```bash
cloak trust show      # print CA path + manual install command
cloak trust install   # install CA into Windows user trust store
cloak trust status    # check if CA is trusted
cloak trust remove    # revoke + delete the local CA
```

---

### `cloak launch`

Start a developer CLI with cloakline preflight checks and automatic key injection.

```bash
cloak launch claude -p "hello"     # Anthropic Claude Code CLI
cloak launch codex "print hi"      # OpenAI Codex CLI
cloak launch cursor                # print Cursor BYOK config block
```

Before starting the child process, `cloak launch` checks:
1. cloakline admin responds on `http://127.0.0.1:4001/healthz`
2. (best effort) the inspection CA is trusted

If checks fail, it prints a one-line fix and aborts.

---

### `cloak login`

Save gateway URL + virtual key to `~/.config/cloak/config.yaml`.

```bash
cloak login https://gateway.example.com
```

Prompts for the virtual key (`sk-gw-…`) and an optional tenant name.

---

### `cloak keys`

Manage tenant virtual keys (placeholder — coming soon).

For now, edit `configs/principals.yaml` manually and restart the daemon.

---

### `cloak version`

```bash
cloak version    # or: cloak -v, cloak --version
```

---

## 5. Configuration

### `configs/pipeline.yaml`

The main configuration file for the cloakline daemon.

```yaml
inspect:
  enabled: true         # set to false to disable TLS interception
  listen: ":443"        # HTTPS port (443 requires admin; 8443 is dev-friendly)
  hosts:                # hostnames whose TLS cloakline will terminate
    - api.anthropic.com
    - api.openai.com

admin:
  listen: "127.0.0.1:4001"   # admin dashboard port (never expose externally)

gateway:
  listen: "127.0.0.1:4000"   # OpenAI-compatible proxy port
```

### `configs/providers.yaml`

Upstream provider definitions. Add your provider's base URL and auth header here. Keys themselves are stored in the OS keyring, not in this file.

### `configs/rules.yaml`

Per-kind DLP action overrides. Example: change the default `redact` action for `email` to `allow`:

```yaml
kinds:
  email:
    action: allow
```

Valid actions: `allow`, `warn`, `redact`, `redact_one_way`, `block`.

### Runtime prefs

Go to `http://127.0.0.1:4001/admin/prefs` to override actions at runtime without restarting. Runtime prefs take priority over `rules.yaml`.

### Auto-start on Windows login

`cloak setup` offers to create a startup shortcut. If you declined, create it manually:

1. Open `shell:startup` (Win+R → type `shell:startup`)
2. Create `cloakline.cmd` with:
   ```bat
   @echo off
   start "" /min "C:\path\to\cloakline.exe" --config "C:\path\to\configs"
   ```

Or use Task Scheduler for a more robust setup (runs before login):

```powershell
$action  = New-ScheduledTaskAction -Execute "C:\path\to\cloakline.exe" -Argument "--config C:\path\to\configs"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "cloakline" -Action $action -Trigger $trigger -RunLevel Highest
```

---

## 6. Security model

### What cloakline stores

| Data | Where | Protection |
|---|---|---|
| Provider API keys | OS keyring | DPAPI-encrypted (Windows), Keychain (macOS) |
| DLP preferences | `%APPDATA%\cloakline\prefs.bin` | AES-256-GCM, key wrapped by DPAPI |
| Local CA private key | `%APPDATA%\cloakline\ca\ca-key.pem` | File-system ACLs (user-only) |
| Audit log | In-memory ring buffer (1 000 entries) | Not persisted — resets on restart |

### What cloakline never stores

- Plaintext of any HIGH-tier finding (API keys, passwords, credit cards)
- Raw request or response bodies
- Provider auth headers (`Authorization`, `x-api-key`)

> "Never store high risk information. Never, ever store credentials or anything that is so important and very private in the server or in the nodes or logs."

### Allow-session flow

When cloakline redacts something HIGH-tier, a Windows notification appears. Clicking **Allow session** opens `http://127.0.0.1:4001/admin/session/allow?nonce=<token>`. The nonce is:

- Single-use (consumed on first click)
- Valid for 5 minutes
- Stored only in process memory (never on disk)

After clicking Allow, that session is opted out for 1 hour. Resend your original message — it passes through unmodified.

### CA trust scope

The local inspection CA is installed **per-user** (`certutil -user -addstore Root`). It is NOT added to the machine-wide trust store. Other users on the same machine are not affected.

---

## 7. Uninstall

### If you installed with `npx cloakline install`

```bash
npx cloakline uninstall
```

That runs the platform's `uninstall` script from the installed location, then you can `rm -rf ~/.cloakline` (macOS) or `rmdir /s /q "%LOCALAPPDATA%\cloakline"` (Windows) for a full wipe.

### macOS (built from source)

```bash
./scripts/uninstall.sh
```

That single command unloads the LaunchAgent, removes the pf anchor, deletes hosts entries, flushes DNS, reverts `pipeline.yaml`, and removes the CA from Keychain. Binaries and app-data are left in place — delete `bin/` and `~/Library/Application\ Support/cloakline/` manually for a full wipe.

### Windows (manual)

```bash
# 1. Remove the local CA from the OS trust store.
cloak trust remove

# 2. Delete the daemon binary (wherever you put it).
#    If in the Startup folder:
del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\cloakline.cmd"
#    Or the Task Scheduler entry:
Unregister-ScheduledTask -TaskName "cloakline" -Confirm:$false

# 3. Remove cloakline data (keys, prefs, CA files).
rmdir /s /q "%APPDATA%\cloakline"

# 4. Remove CLI config.
rmdir /s /q "%APPDATA%\cloak"

# 5. Undo hosts file changes.
#    Open C:\Windows\System32\drivers\etc\hosts as Administrator
#    and delete the two lines you added during setup.

# 6. (Optional) Remove CLI binary if installed to PATH.
del "%GOPATH%\bin\cloak.exe"
```

After removing the hosts file entries, AI tools talk directly to their providers again.

---

## 8. Troubleshooting

### cloakline is not intercepting traffic

**Check 1:** Is the daemon running?
```bash
cloak doctor
```
If it says "cloakline not reachable on 127.0.0.1:4001", start it:
```bash
./bin/cloakline.exe --config ./configs
```

**Check 2:** Are the hosts file entries present?
```powershell
Select-String "anthropic" C:\Windows\System32\drivers\etc\hosts
```
If missing, add them (requires Administrator).

**Check 3:** Is the CA trusted?
```bash
cloak trust status
```
If not trusted:
```bash
cloak trust install
```

---

### TLS certificate error in AI tool

The tool is rejecting cloakline's certificate. Possible causes:

1. **CA not installed:** Run `cloak trust install`.
2. **CA installed for wrong user:** The trust store install is per-user. If you run your AI tool as a different user or via `sudo`, they won't see the CA. Use the same user account.
3. **Certificate pinning:** Some tools (e.g., older versions of curl or hard-coded pinning) reject non-standard CAs. Switch to the `cloak launch` wrapper which injects the right CA via environment variables.

---

### My API keys are being rejected (401)

cloakline does **not** modify provider auth headers. If you're getting 401s:

1. Verify your keys are stored: open `http://127.0.0.1:4001/admin/keys`
2. Re-run `cloak setup` to re-enter your keys
3. Check `configs/providers.yaml` to confirm the provider URL is correct

---

### HIGH-tier content is being redacted but I want to allow it

1. Wait for the Windows notification balloon (appears near the system tray)
2. Click **Allow session**
3. Your browser opens a confirmation page
4. Go back to your AI tool and **resend the message**

cloakline will pass it through unmodified for 1 hour.

If the notification does not appear:
- Check that Claude.exe (or claude.exe) is running — notifications only fire when Claude Desktop is open
- Or go directly to `http://127.0.0.1:4001/admin` and manage sessions from the dashboard

---

### The dashboard is not loading

1. Confirm the daemon is running: `cloak doctor`
2. The admin listener only binds to `127.0.0.1:4001` — it's not accessible from other machines by design
3. Check `configs/pipeline.yaml` for the `admin.listen` field

---

### The live tail shows "unreachable"

`cloak tail` talks directly to `http://127.0.0.1:4001` (not via the gateway). If it shows the daemon as unreachable, start cloakline:

```bash
./bin/cloakline.exe --config ./configs
```

`cloak tail` retries automatically every 2 seconds once you start the daemon.

---

### Windows Defender / antivirus flags cloakline

cloakline terminates TLS and modifies your hosts file — both of which look suspicious to signature-based AV. Add the cloakline binary directory to your AV exclusion list, or build from source and verify the code yourself (Apache 2.0 license, all logic in Go).

---

### Port 443 permission denied

Port 443 requires elevated privileges on Windows. Options:

1. **Use the Scheduled Task approach** with `Run as Administrator`:
   ```powershell
   Register-ScheduledTask -TaskName "cloakline" -Action $action -Trigger $trigger -RunLevel Highest
   ```
2. **Use port 8443 for development** — change `inspect.listen: ":8443"` in `pipeline.yaml`. Then in the hosts file use a port-redirecting approach (WSL netsh portproxy) or accept that standard port 443 requests won't be intercepted.

---

## 9. FAQ

**Q: Does cloakline send any data to Anthropic or a third party?**

No. cloakline is entirely local. It forwards your requests to AI providers (which you configured yourself), but does not send data to any cloakline server. There is no telemetry, no license check, no home-phone.

---

**Q: Will AI tools still work normally after installation?**

Yes. cloakline is transparent. For non-sensitive requests, it forwards the body unchanged. The only difference you notice is that sensitive content arrives at the AI with `[REDACTED_*]` markers.

---

**Q: What happens to my API keys?**

Your keys are stored using the OS keyring (Windows DPAPI on Windows, macOS Keychain on macOS). They are encrypted under your user account and can only be decrypted by your user session. They are never written to disk in plaintext and never appear in logs.

---

**Q: What if I paste something sensitive by accident?**

For HIGH-tier content (API keys, passwords, credit cards), cloakline redacts it before it reaches the AI. The AI responds with a marker like `[REDACTED_API_KEY]`. Nothing sensitive was sent.

If you pasted it intentionally (e.g., asking the AI to review a credentials file), click **Allow session** in the notification to resend unredacted for 1 hour.

---

**Q: Does cloakline inspect streaming responses?**

Currently cloakline inspects request bodies (what you send to the AI). Response bodies are forwarded as-is. Outbound DLP (scanning AI responses before they reach you) is on the roadmap.

---

**Q: Can I use cloakline as a shared team gateway?**

Yes, but that requires different setup. The `cmd/cloakline` daemon supports multi-tenant routing via `configs/principals.yaml`. Deploy it on a server, point your team at its URL with `cloak login`, and each developer uses a virtual key (`sk-gw-…`). The TLS interception layer is designed for local use; for a team gateway, you'd use the HTTP proxy mode instead.

---

**Q: How do I add a new AI provider?**

Edit `configs/providers.yaml` to add the provider's base URL and auth-header pattern. Restart cloakline. The OpenAI-compatible proxy endpoint (`/v1/chat/completions`) handles most providers; Anthropic's native `/v1/messages` endpoint has a dedicated adapter.

---

**Q: My terminal shows garbled box-drawing characters**

The live dashboard (`cloak tail`) uses Unicode box-drawing characters. Enable UTF-8 in your terminal:

- **Windows Terminal**: enabled by default
- **CMD.exe**: run `chcp 65001` before `cloak tail`, or switch to Windows Terminal
- **PowerShell**: usually works; if not, add `[Console]::OutputEncoding = [Text.Encoding]::UTF8` to your profile

---

**Q: Can I disable specific DLP checks?**

Yes. Go to `http://127.0.0.1:4001/admin/prefs` and set any kind's action to `allow`. Changes take effect immediately without a restart.

Alternatively, edit `configs/rules.yaml`:
```yaml
kinds:
  phone:
    action: allow    # stop tokenising phone numbers
  email:
    action: allow    # pass emails through untouched
```

---

**Q: How do I update cloakline?**

```bash
git pull
make build
# Restart the daemon (kill + start, or let the Scheduled Task restart it on next login)
```

There is no auto-update mechanism — updates are always deliberate.

---

## 10. Architecture overview

```
 Your AI tool (claude, codex, Cursor, etc.)
       │
       │ HTTPS  (intercepted by hosts file entry)
       ▼
 ┌─────────────────────────────────────────┐
 │  cloakline TLS Inspector (:443)         │
 │                                         │
 │  1. Terminate TLS with local CA         │
 │  2. Read request body                   │
 │  3. Run DLP pipeline:                   │
 │     ├── DLP tier 1 (HIGH: redact_one_way)│
 │     ├── DLP tier 2 (MEDIUM: tokenize)   │
 │     ├── DLP tier 3 (LOW: flag only)     │
 │     └── Injection detection             │
 │  4. Forward (possibly modified) body    │
 │  5. Stream response back                │
 └────────────────┬────────────────────────┘
                  │ HTTPS (real connection)
                  ▼
         api.anthropic.com  /  api.openai.com

 ┌─────────────────────────────────────────┐
 │  Admin listener (127.0.0.1:4001)        │
 │  /admin          — web dashboard        │
 │  /admin/keys     — provider key mgmt    │
 │  /admin/prefs    — runtime DLP overrides│
 │  /admin/api/*    — JSON API for CLI     │
 │  /healthz        — health check         │
 └─────────────────────────────────────────┘

 ┌─────────────────────────────────────────┐
 │  Gateway listener (127.0.0.1:4000)      │
 │  OpenAI-compatible HTTP proxy           │
 │  For tools that support a base-URL swap │
 └─────────────────────────────────────────┘
```

### Key design decisions

| Decision | Rationale |
|---|---|
| **LOCAL TLS termination** | The only way to inspect HTTPS bodies without modifying AI tools or injecting a proxy env var |
| **Local CA, user trust scope** | Doesn't affect system-wide trust; revoke instantly with `cloak trust remove` |
| **No plaintext in logs or disk** | HIGH-tier content is zeroized immediately after redaction; audit ring stores only finding *kinds*, not values |
| **In-memory ring buffer (not a database)** | Simpler, faster, no SQLite dependency; restart clears the log intentionally |
| **DPAPI for key storage** | Strongest option available on Windows without a hardware token; tied to the user account, not the machine |
| **Go single binary** | Easy to audit, easy to deploy, no runtime, no interpreter, minimal attack surface |

### DLP pipeline

```
Request body
    │
    ├─► DLP tier 1: HIGH findings
    │     api_key, aws_key, github_token, private_key → redact_one_way → [REDACTED_*]
    │     password, credit_card                       → redact_one_way + notify
    │
    ├─► DLP tier 2: MEDIUM findings
    │     ssn, email, phone → tokenize → pseudonym stored in per-request vault
    │                         AI sees pseudonym; vault restores original in response
    │
    ├─► DLP tier 3: LOW findings
    │     ip_address, url_path → flagged in dashboard; body not modified
    │
    └─► Injection detection
          Weighted rule scoring; block if score > threshold
```
