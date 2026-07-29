# Quick start: run once, forget about it

You paste your API keys **once**. After that you type `claude`, `codex`, and use Cursor normally. cloakline runs invisibly in the background, redacting PII silently and only speaking up when it blocks a real leak.

Tested on Windows. macOS/Linux notes are inline.

## 1. Build

```bash
make build
```

Produces `bin/cloakline.exe` and `bin/cloak.exe`.

## 2. Run the one-time setup

```bash
./bin/cloak.exe setup
```

That single command walks you through everything:

1. **Installs the local CA** into your Windows user trust store (no admin needed for this part).
2. **Prompts for your API keys.** You paste each one; it goes straight into the OS keyring (DPAPI-encrypted on Windows). The values never appear on screen again after you paste them.
3. **Enables the transparent scanner** in `configs/pipeline.yaml`.
4. **Tells you the exact two lines** to add to your Windows hosts file (this part needs an admin Notepad — I print, I don't execute).
5. **Optionally adds a Startup shortcut** so cloakline launches on every login.

You'll never need to run `setup` again unless you rotate keys.

## 3. Add the hosts lines (one-time, admin required)

Setup prints these two lines. Open **Notepad as Administrator**, edit `C:\Windows\System32\drivers\etc\hosts`, and paste:

```
127.0.0.1 api.anthropic.com
127.0.0.1 api.openai.com
```

Then in `configs/pipeline.yaml` change `inspect.listen: ":8443"` to `inspect.listen: ":443"` (binding port 443 needs admin — start cloakline from an elevated shell, or use the startup shortcut which handles this).

**Alternative that avoids admin entirely:** set your OS HTTPS proxy to `127.0.0.1:8443` and leave the listener at `:8443`. Works, but only apps that respect the system proxy get intercepted. The hosts approach is more reliable for CLIs.

## 4. Start cloakline (once, or on login if you enabled autostart)

```bash
./bin/cloakline.exe --config ./configs
```

Dashboard: **http://127.0.0.1:4001/admin** — bound to loopback only, nothing on your LAN can reach it.

## 5. Use your CLIs normally

That's it. Just use them.

```bash
claude -p "help me refactor this function"
codex "write a python script that does X"
# Or open Cursor and work — the base URL block from `cloak launch cursor`
# only needs to be pasted into Cursor Settings once.
```

**Nothing changes in your workflow.** No wrapper. No env vars. No prompts asking permission to redact. When you paste `jdoe@acme.com` into a Claude prompt, cloakline swaps it for a pseudonym before Anthropic sees it, then swaps the real value back into Claude's response. You never notice. Claude does its job. Your customer's email never left your machine.

## What you'll see (and won't see)

- **Silent, in the background:** redactions of PII (emails, phones, SSNs, names, credit card numbers). Your CLI shows no interruption.
- **Loud, on purpose:** blocks of real credentials (API keys, AWS keys, GitHub tokens, private keys). If you accidentally paste a real API key, cloakline will refuse to forward it and Claude/Codex will return an error. This is the point — a leaked credential is unrecoverable damage.
- **On the dashboard:** the running totals. "3,412 requests scanned, 27 secrets caught, 194 PII items redacted, ~3h saved." Refresh whenever you want to see what got protected today.

## Do the keys survive a restart?

Yes. On Windows they're stored as DPAPI-encrypted files under `%LOCALAPPDATA%\cloakline\keys\`. Only your Windows login can decrypt them. Reboot your PC, kill cloakline, log out and back in — the keys are still there. There's an automated test (`TestWindowsBackendSurvivesRestart`) that fakes a restart on every CI run to prove it.

## Reset / uninstall

```bash
./bin/cloak.exe trust remove          # revoke the CA
del "%LOCALAPPDATA%\cloakline\keys\*.bin"   # forget all keys
```

Also remove the two hosts-file lines you added, and delete `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\cloakline.cmd` if you enabled autostart.

## What is *not* stored, ever

- **The plaintext of your prompts.** cloakline only logs finding *kinds* (e.g. "email", "ssn"), never the actual text.
- **The plaintext of your API keys.** DPAPI ciphertext on disk; masked (`••••••••wxyz`) in the dashboard.
- **Provider auth headers.** See [inspect.md](inspect.md) for the passthrough contract — the `Authorization` / `x-api-key` header you send goes to the real provider unchanged.

## What is stored, in memory only (wiped on restart)

- The ring-buffered activity log (last 1000 requests, kind of finding + verdict).
- Lifetime counters for the dashboard tiles ("secrets caught", "time saved" etc.). These reset when cloakline restarts — durable audit is tripwire `T-AUDIT-CHAIN` in [tripwires.md](tripwires.md), a different feature we haven't built.

## Manual mode (if setup wasn't right for you)

Everything setup does is scriptable:

```bash
./bin/cloak.exe trust install
# Open http://127.0.0.1:4001/admin/keys and paste keys via the browser instead
# Edit configs/pipeline.yaml manually
```

`cloak launch claude` / `codex` / `cursor` also still works if you don't want to touch the hosts file — it uses the `:4000` gateway path instead of transparent inspection. Slower to set up, but zero system-level changes.
