# Keeping Claude Code (and every other AI client) unbroken

cloakline works by lying to your OS: hosts file redirects `api.anthropic.com` to `127.0.0.1`, and cloakline pretends to be Anthropic. When that lie holds together perfectly, everything is transparent. When any part of the deception breaks, EVERY app that talks to Anthropic breaks with it — including the Claude Code desktop app you're likely using to work on cloakline itself.

This document catalogs every failure mode we know about, the guard we've built for each, and what to do when the guard fails.

## Fast paths

**Something's broken and you don't know what:**

```powershell
.\scripts\diagnose.ps1
```

Non-destructive. Prints every layer's health with the exact fix command below any FAIL.

**Something's broken and you don't care why, just fix it:**

```powershell
.\scripts\panic-restore.ps1    # from admin PowerShell
```

Kills cloakline, removes hosts entries, unregisters the task, flushes DNS. Idempotent. Doesn't touch your CA, vault files, or config edits.

**You want to reinstall after a clean:**

```powershell
.\scripts\install.ps1          # from admin PowerShell
```

Safe-ordering installer. Rolls back hosts entries automatically if any step fails.

## The failure modes we know about

### 1. Hosts entry present, cloakline not listening → ConnectionRefused

**How it happens:** the install script crashed midway, or someone unregistered the scheduled task without also removing hosts, or cloakline.exe crashed and had no restart plan.

**Symptom:** Claude Code (or curl, or any HTTPS client) fails with `ECONNREFUSED` or `unable to connect to host` for **every** request to Anthropic.

**Guard:**
- `install.ps1` adds hosts entries LAST, only after verifying cloakline is listening. Any failure rolls the hosts entries back automatically.
- `install.ps1` registers a scheduled task with `RestartCount=3` and `RestartInterval=1 min` so a crash auto-recovers.
- `diagnose.ps1` flags the state as CRITICAL if hosts is set but cloakline isn't running.

**Emergency fix:** `panic-restore.ps1`.

### 2. cloakline scans a non-chat request and 403s it → auth breaks silently

**How it happens (this bit us):** Claude Code refreshes its OAuth token → sends POST to `api.anthropic.com/v1/oauth/token`. cloakline's injection scorer scans the body, finds something that looks like a rule trigger, returns 403. Claude Code interprets that as "auth failed" and the whole session dies with **no useful error message**.

**Symptom:** Claude Code says `Failed to authenticate. API Error: 403 {"error":"content blocked by policy","reason":"injection"}` even though nothing you typed is remotely a prompt injection.

**Guard:** cloakline now only enters the DLP + injection pipeline for chat endpoints ([internal/tlsinspect/forward.go `isChatEndpoint`](internal/tlsinspect/forward.go)):
- `/v1/messages` (Anthropic chat)
- `/v1/chat/completions` (OpenAI chat)
- `/v1/completions` (OpenAI legacy)
- `/v1/responses` (OpenAI Responses API)

Everything else — OAuth, list-models, embeddings, moderation, health — passes through byte-for-byte. Test coverage: `TestNonChatEndpointsPassThroughUnscanned` in [internal/tlsinspect/nostorage_test.go](internal/tlsinspect/nostorage_test.go).

**Emergency fix if you ever see this again:** `panic-restore.ps1` restores real Anthropic; then diff cloakline's `isChatEndpoint` list against the endpoints your client uses.

### 3. Scheduled task registered as SYSTEM → CA / DPAPI path mismatch

**How it happens:** an early version of `install.ps1` ran cloakline as SYSTEM (thinking :443 needed root, Unix-style). SYSTEM's `%APPDATA%` is `C:\Windows\System32\config\systemprofile\AppData\...`, so cloakline generated a fresh CA there that the user's cert store didn't trust. Every request failed with TLS-verify errors.

**Symptom:** `x509: certificate signed by unknown authority`.

**Guard:** the current `install.ps1` registers the task as the **current interactive user** (`-LogonType Interactive`, `-RunLevel Highest`). Windows lets normal users bind :443 fine — this is the Linux mental-model trap Windows doesn't share. All paths (CA, vault, prefs) resolve to the same profile the human uses.

**Emergency fix:** re-run `install.ps1`; it re-registers the task under your current user.

### 4. Windows PS 5.1 encoding issue → install script parse errors on unrelated lines

**How it happens:** any non-ASCII character (✓, em-dash, emoji) in a `.ps1` without a UTF-8 BOM gets misread as ANSI. PowerShell 5.1's parser throws confusing "unterminated string" errors on lines nowhere near the actual issue.

**Guard:** `install.ps1`, `uninstall.ps1`, `diagnose.ps1`, and `panic-restore.ps1` are all pure ASCII. CI-style parse checks (in `docs/session-notes.md` gotcha #2).

**Emergency fix if you edit any of these:** run this after editing —
```powershell
[System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw path\to\file.ps1), [ref]$null)
```
Silence = pass; exception = fix the file.

### 5. Hosts file lock during install → half-applied redirect

**How it happens:** AV / Defender scans hosts on modification. Two `Add-Content` calls in quick succession → second one gets `IOException: file in use`.

**Guard:** both `install.ps1` and `panic-restore.ps1` retry hosts writes up to 6-8 times with 500ms sleep between attempts. And the install rolls back partial state on any error.

**Emergency fix:** manually edit hosts.

### 6. Unregistering the task doesn't stop the running process

**How it happens:** `Unregister-ScheduledTask` removes the task definition but doesn't kill the currently-running instance. cloakline keeps listening on :443 with the (now-orphaned) hosts entry pointing at it. If you then remove hosts too, everything's fine — but if the process dies for other reasons, no auto-restart.

**Guard:** `panic-restore.ps1` kills the process AND unregisters the task in order.

**Emergency fix:** `Get-Process cloakline | Stop-Process -Force` (from admin PowerShell if the process was started with elevation).

### 7. `nslookup` shows real Anthropic IPs — but Windows apps use 127.0.0.1

**How it happens (misleading diagnostic):** `nslookup` queries the DNS server directly, bypassing the hosts file. But the Windows DNS Client Service uses hosts BEFORE any DNS query. So `nslookup` can say "real IP" while every Windows app is being redirected.

**Guard:** `diagnose.ps1` uses `Resolve-DnsName` (which honors hosts), NOT `nslookup`.

**Emergency fix:** always trust `Resolve-DnsName` for cloakline diagnostics.

### 8. `Z:` drive not visible to a task running as SYSTEM

**How it happens:** SYSTEM has no user-mapped network drives. If the scheduled task's exe path was `Z:\...`, it might fail to launch under SYSTEM.

**Guard:** the current installer runs the task as the current user, whose drive mappings match your interactive shell. Also — Z: on this repo is actually a local disk (`DriveType 3`), not a mapped network drive, so this specific concern didn't apply here.

**Emergency fix:** if you ever move to a real network drive, install the task with paths under `C:\Program Files\cloakline\`.

### 9. Prefs file lock during dashboard save → override drops silently

**How it happens:** dashboard user clicks Save at the exact instant a DLP request is reading prefs. `os.Rename` during `ReadFile` on Windows returns `ERROR_SHARING_VIOLATION`.

**Guard:** `internal/prefs/prefs.go` now caches prefs in memory under an `sync.RWMutex`. Reads hit the cache (no I/O). Writes take the write lock, do the atomic rename, then update the cache under the same lock. Zero possibility of a read racing a write.

Regression test: `TestConcurrentLoadSaveIsRaceFree` in `internal/prefs/prefs_test.go`.

### 10. Confirmation prompt double-fires on every turn

**How it happens:** the DLP scanner joined ALL user + assistant messages and scanned the combined text. On turn 2, the flagged content from turn 1 was still in the conversation history, so cloakline triggered the y/n prompt AGAIN even when the user was just answering `y`.

**Guard:** intent detection now uses `extractLastUserPrompt` (latest user message only). `bytes.ReplaceAll` on the whole body still redacts any historical occurrences defensively.

### 11. Session key changes mid-flow → pending confirmation orphaned

**How it happens:** if the CLI refreshes its OAuth bearer between the prompt and the reply, cloakline's session-key hash changes → the `y` doesn't match the stored pending entry → user sees the prompt again instead of Claude's reply.

**Guard:** `SessionKey` now hashes only the first 128 chars of the auth header (stable prefix; rotating suffix ignored). Also returns "" for both-empty headers so unauthenticated callers don't cross-contaminate each other's pending entries.

### 12. Zeroize-too-early on the `y` path

**How it happens:** the `y` handler used `defer aesbox.Zeroize(plain)` and handed the same slice to `bytes.NewReader` inside `forwardBody`. Go's `net/http` Transport may keep a reference to the reader (for retry buffers) beyond the defer, meaning plaintext could linger past the intended zeroize window.

**Guard:** `forwardBody` now owns the zeroize lifecycle. The `defer aesbox.Zeroize(body)` runs AFTER the upstream round-trip completes and the response has been written back to the client. Caller-side defer removed.

## What to do BEFORE any install/upgrade

Save this checklist as a bookmark:

1. **Snapshot your hosts file.** `Copy-Item C:\Windows\System32\drivers\etc\hosts C:\Users\lordm\Desktop\hosts.backup.txt`
2. **Confirm Claude Code works.** Send one message. If it fails now, the install won't help.
3. **Only install from an admin PowerShell you can watch.** Don't background it.
4. **Read every green check** in the installer output. Any red → the rollback fires; verify hosts is clean before doing anything else.
5. **Immediately test Claude Code** after install completes. If it fails, run `panic-restore.ps1` — don't debug for hours.

## What to do WHILE cloakline is running

- Keep `diagnose.ps1` bookmarked. Run it any time Claude Code acts weird.
- The dashboard at http://127.0.0.1:4001/admin is your friend. If it doesn't load, cloakline is down.
- The scheduled task auto-restarts on crash (3 attempts). If the third attempt fails, the task is left in "Ready" state; check Task Scheduler > History.

## What to do AFTER something goes wrong

Order matters:

1. **Panic-restore first.** Get Claude Code back up.
2. **Then diagnose.** Once Claude Code is working, dig into what broke.
3. **Read `cloakline.err`** in `%APPDATA%\cloakline\logs\` (if the task was set up to log there) OR check Task Scheduler > cloakline > History.
4. **File a note in `docs/session-notes.md`** so this failure mode joins the guarded list.

## Rules of thumb

- **cloakline is a middleware layer.** Middleware failures cascade to every client. Test in a way that catches the cascade.
- **Never leave hosts entries with no listener.** The `install.ps1` safe-ordering + rollback exists for this exact reason. Don't hand-edit hosts around cloakline unless you own the whole coordination.
- **The scheduled task and the running process are two different things.** Unregistering the task doesn't kill the process. Killing the process doesn't unregister the task. `panic-restore.ps1` handles both.
- **`nslookup` lies about hosts-file redirects.** Use `Resolve-DnsName`.
- **UAC prompts don't come through non-interactive shells.** If a script says "elevate this to admin," you have to click Yes on a real dialog. AI assistants running in the background can't do this for you.

## The three scripts, one sentence each

| Script | What it does |
|---|---|
| `scripts/install.ps1` | Register scheduled task → start it → verify listening on :443 → THEN add hosts entries → verify DNS. Rolls back on any failure. |
| `scripts/diagnose.ps1` | Non-destructive read-only walk of all nine layers (hosts, DNS, task, process, port, admin, TLS, real Anthropic, CA trust). Exits non-zero on any critical issue. |
| `scripts/panic-restore.ps1` | Force-kill cloakline, unregister task, remove hosts entries, flush DNS, verify real Anthropic is reachable. Restores Claude Code to working state. |
