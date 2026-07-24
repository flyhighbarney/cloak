# Session notes — everything worth knowing to keep working on cloakline

Written at the end of a long session where policyd was renamed to **cloakline** (CLI: **cloak**), a three-tier DLP system + in-CLI confirmation flow was built, and the Windows installer went through several bruises before it stopped breaking Claude Code. This doc is what you should read *before* touching install.ps1 or the tlsinspect forward path.

## What shipped this session

- **Rename**: `policyd` → `cloakline`, `policyctl` → `cloak`. Every Go import path, every log message, every user-facing string. Old binaries and directories under `%LOCALAPPDATA%\policyd\` are orphaned; delete manually if you care.
- **Three-tier DLP** (HIGH / MEDIUM / LOW) with a `redact_one_way` action for credentials. See `docs/policy-tiers.md`.
- **Intent detector** (`internal/stage/intent/`): proximity regex for "my password is …", labelled `password:` blocks, etc.
- **AES-encrypted state**:
  - `internal/crypto/aesbox/` — AES-256-GCM helper. Used by prefs and the confirm pending map.
  - `internal/prefs/` — per-kind DLP override store at `%APPDATA%\cloakline\prefs.bin` (DPAPI-wrapped key on Windows).
  - `internal/tlsinspect/confirm.go` — pending-confirmation map keyed by session, bounded to 16, TTL 5 min, AES key ephemeral per process.
- **Synthetic Anthropic response** (`internal/tlsinspect/synthetic.go`) — the y/n/session prompt rendered inline in Claude Code's terminal. Both stream and non-stream Anthropic formats.
- **Dashboard**: `/admin/keys`, `/admin/prefs` (POST + CSRF), Brave-style hero tiles (secrets caught, PII redacted, injections blocked, time saved).
- **Windows install**: `scripts/install.ps1` + `scripts/uninstall.ps1`. Scheduled task runs cloakline at logon as the current user (NOT SYSTEM — see gotchas).
- **Full ASCII architecture + flow diagram** was drawn in the chat but not committed. Regenerate on request.

## Known bugs (see `ReportFindings` output in the review)

Ranked most-severe first. Numbers correspond to what a reviewer would file:

1. **SessionKey unstable across token rotation** (`confirm.go:95`). If the CLI refreshes OAuth between y-prompt and answer, the pending gets orphaned. Recommend hashing something more stable (e.g. principal ID) or storing a client-generated correlation ID.
2. **DLP rewrites message history each turn** (`forward.go:173`). `patterns.Scan` runs against the joined text of ALL messages. Intent was fixed to look at only the last user message; full DLP scan wasn't. Long conversations will diverge from what Anthropic saw earlier. Fix: scan latest message only, or maintain a "already-handled-in-this-session" set.
3. **Confirmation gate is `strings.Contains(host, "anthropic")`** (`forward.go:176`). OpenAI traffic silently skips the y/n prompt. Fix: exact-match host set (`api.anthropic.com`, `api.openai.com`) and add an OpenAI-shaped synthetic response.
4. **`session` opt-out still redacts** (`forward.go:230`). The flag only skips the prompt; the redact_one_way switch still fires. Fix: opt-out must also downgrade high-tier to `allow` for the TTL window.
5. **prefs Load/Save race** (`prefs.go:138`). No mutex around the file. Rare but real: concurrent dashboard-save + DLP-lookup can drop an override for one request.
6. **prefs decrypted per DLP finding** (`prefs.go:138`). ~90ms latency added on requests with several findings. Fix: cache Prefs in memory, invalidate on POST.
7. **Missing provider key crashes startup** (`config.go:497`). The user's explicit ask (see next section). Fix: warn + skip the provider in `config.Load`, don't fatal.
8. **Zeroize race on `y` path** (`forward.go:360`). Plaintext handed to `bytes.NewReader` could outlive the `defer aesbox.Zeroize` via http retry buffers.

## User's specific ask: auto-detect provider availability instead of removing OpenAI

Right now `configs/providers.yaml` has the Ollama and OpenAI entries commented out because their env vars aren't set and the daemon refuses to boot otherwise. The user rightly pointed out this is the wrong default. Better design:

**At `config.Load`**: for each provider, try `APIKeyForProvider(p)`. If it errors with "no key":
- Log `WARN "provider.skipped" id=<id> reason="no api key"` and drop it from `ir.Providers` before returning.
- Keep the provider available to add later via the dashboard (drop the key into the vault, restart, provider auto-enables).

**Similar for local providers** (Ollama):
- If `p.Local == true`, additionally probe `p.BaseURL/api/tags` (Ollama) or `/health` (generic) at startup with a 1-second timeout.
- If unreachable, log `WARN "provider.unavailable" id=<id>` and skip.

Once this is in, providers.yaml can ship every reasonable default uncommented — cloakline will silently disable the ones the machine can't use.

## Install gotchas we hit this session (troubleshooting reference)

Everything below has been resolved, but write these down in case you or a fresh install trips on them again.

### 1. UAC prompts cannot be triggered from a non-interactive shell

`Start-Process -Verb RunAs` from a background PowerShell doesn't surface the UAC dialog reliably. The install script must be launched by a human from an admin terminal. Do NOT trust "I'll trigger UAC for you" flows — they silently fail.

### 2. PowerShell 5.1 (default on Windows 10/11) rejects UTF-8 scripts without BOM

We hit this with the ✓ character in error messages. If the script mixes ASCII and multi-byte chars and has no BOM, PS 5.1 reads bytes as ANSI and the parser throws terminator errors on completely unrelated lines. **Rule**: keep `.ps1` files pure ASCII, or add a UTF-8 BOM. The bundled `scripts/install.ps1` and `scripts/uninstall.ps1` are ASCII-clean.

### 3. PowerShell 5.1 uses different Scheduled Tasks enum names than PS7+

- PS7: `-LogonType InteractiveToken`
- PS5.1: `-LogonType Interactive` ← use this

### 4. `-Host` is a reserved parameter name

`$Host` is a read-only automatic variable. You cannot use `-Host` as a function parameter name in PS 5.1 without triggering `Cannot overwrite variable Host because it is read-only or constant`. The installer's TLS check function uses `-Target` instead.

### 5. Windows hosts file gets briefly locked after writes

AV / Windows Defender scans hosts on modification. If you do two `Add-Content` calls in quick succession, the second gets `IOException: file in use by another process`. The installer now retries up to 6 times with 500 ms between attempts.

### 6. `net use` doesn't show all "network-looking" drives

Our test drive Z: showed as `DriveType 3 (Local Fixed Disk)` via `Get-CimInstance Win32_LogicalDisk` — it wasn't a mapped network drive at all. Don't assume Z: means SMB.

### 7. Windows lets non-privileged users bind :443

This is the big one. The Unix rule "ports <1024 need root" does NOT apply on Windows. Regular users can bind :443 fine. We originally designed the scheduled task to run as SYSTEM for exactly this reason and it caused a cascade of path-mismatch bugs (CA under `C:\Windows\System32\config\systemprofile\AppData\...`, DPAPI keys under a different profile, etc). **Fix**: the task now runs as the current interactive user. Only the hosts-file edit needs admin, and that happens once from install.ps1.

### 8. Partial install → hosts entry without a listener = every Anthropic client breaks

**This bit us hard.** An early install landed `127.0.0.1 api.anthropic.com` in hosts but cloakline wasn't listening. Claude Code (the desktop app being used to work on this) started returning `ConnectionRefused` on every request. The user had to manually remove the hosts entry to unblock themselves.

**Fix**: `scripts/install.ps1` now uses safe ordering:
1. Register task
2. Start task
3. **Verify** cloakline is listening on :443 AND admin :4001 responds (polling up to 15s)
4. ONLY THEN add hosts entries
5. Verify DNS resolves to 127.0.0.1

Any failure between steps 5-7 rolls back the hosts entries. The uninstaller `scripts/uninstall.ps1` also aggressively cleans hosts and DNS.

**If you ever see Claude Code fail with ConnectionRefused during future work on this, first thing to check**: is `api.anthropic.com` in the hosts file? Is cloakline actually listening? Uninstall.ps1 is your escape hatch.

### 9. Startup requires `OLLAMA_API_KEY` — worked around by commenting Ollama out

This is the finding #7 above. The workaround (commenting out ollama-local in `configs/providers.yaml`) is a band-aid. The real fix (auto-skip missing keys) hasn't landed yet.

## How to install (as of end of session)

From an **Administrator** PowerShell:

```powershell
cd "Z:\business solutions"
.\bin\cloak.exe trust install           # trust the local CA — user store, no UAC needed for this step alone
.\scripts\install.ps1                    # everything else — hosts, scheduled task, verification
```

Verify with:

```bash
claude   # opens interactive Claude Code
```

Then:

```
> help me reset password: hunter22day
    (cloakline shows y/n/session prompt inline)
> y
    (Claude responds to the real message)
```

## How to uninstall

```powershell
cd "Z:\business solutions"
.\scripts\uninstall.ps1    # removes task, hosts entries, flushes DNS
.\bin\cloak.exe trust remove
```

That restores Claude Code to normal.

## Files worth reading next (in priority order)

1. `internal/tlsinspect/forward.go` — the handler for intercepted CLI traffic. Where all the DLP + confirm logic lives.
2. `internal/tlsinspect/confirm.go` — the encrypted pending-confirmation state machine.
3. `internal/prefs/prefs.go` — where the per-kind toggles live.
4. `docs/policy-tiers.md` — the three-tier design explained.
5. `docs/inspect.md` — the original tlsinspect design doc (pre-rename; some `policyd` references remain intentionally as it's historical).
6. `scripts/install.ps1` — the installer with the safety net.
7. `configs/rules.yaml` — the tier default policy.

## Tests I trust

- `internal/keyvault/*_test.go` — including the "survives restart" test that fakes a fresh backend against the same on-disk dir. Prevents regression where DPAPI persistence gets broken.
- `internal/crypto/aesbox/aesbox_test.go` — has the paranoia test that greps ciphertext bytes for known plaintext markers.
- `internal/tlsinspect/nostorage_test.go` — the "no plaintext ever reaches upstream" check.
- `internal/tlsinspect/confirm_test.go` — confirmation state machine + evict + parseUserAnswer.

## Non-goals that were deferred (and why)

- **OpenAI/Codex confirmation flow** — synthetic response writer is Anthropic-only in this pass. OpenAI's chat completions have a different shape; it's a ~50-line follow-up in a sibling `synthetic_openai.go`.
- **Cursor Pro managed-proxy support** — cert pinning; can't be MITM'd without breaking the app.
- **Multi-user / team gateway** — the whole design is single-developer laptop. If you deploy to a shared VPS, disable the dashboard (`admin_listen: ""`) and treat the tlsinspect module as a per-machine agent.
- **LLM-based intent classifier** — regex proximity only. If it misses, the credential still gets one-way-redacted; if it false-positives, the user sees an extra prompt.
- **Durable audit log** — ring buffer only, wiped on restart. Tripwire `T-AUDIT-CHAIN` in `docs/tripwires.md`.

## Bottom line

The system works end-to-end today: labelled password paste in Claude Code triggers the y/n prompt, `y` forwards the original, `n` cancels. The safety-critical thing is the installer rollback — the previous incident where hosts got polluted without a listener taught us that ordering matters more than cleverness. If you touch install.ps1, keep the "verify before adding hosts" invariant.

Everything with a bug number above is a real thing to fix. Order-of-attack recommendation: (7) provider auto-skip → (4) session opt-out semantics → (2) history rewrite → (3) OpenAI gate → (5+6) prefs mutex + cache → (1) session key → (8) zeroize race.
