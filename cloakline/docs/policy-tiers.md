# Policy tiers

cloakline v2 classifies every DLP finding into one of three tiers. The tier determines how the finding is handled by default. All defaults are overridable in `configs/rules.yaml` and at runtime in the dashboard `/admin/prefs` panel.

## The tiers at a glance

| Tier | Meaning | Default action | Where it goes |
|------|---------|----------------|---------------|
| **HIGH** | Credential-shaped or a labelled password / card | One-way redact to `[REDACTED_<KIND>]`. Confirmation flow for intentional password / card pastes. | Never stored. Never logged. Never restored on the response. |
| **MEDIUM** | Personal data | Tokenize round-trip via the per-request session vault. AI sees a pseudonym; user's CLI sees the original value back in the response. | Plaintext lives only inside the current request; vault entry is cleared when the request completes. |
| **LOW** | Contextual hints (IPs, URL paths, names) | Pass through untouched. | Only the *kind* is flagged in the dashboard. Body is not modified. |

## Kinds and their default tiers

| Kind | Tier | Default action | Notes |
|---|---|---|---|
| `api_key` | HIGH | `redact_one_way` | Marker `[REDACTED_API_KEY]` |
| `aws_key` | HIGH | `redact_one_way` | Marker `[REDACTED_AWS_KEY]` |
| `github_token` | HIGH | `redact_one_way` | Marker `[REDACTED_GITHUB_TOKEN]` |
| `private_key` | HIGH | `redact_one_way` | Marker `[REDACTED_PRIVATE_KEY]` |
| `password` | HIGH | `redact_one_way` + confirm-on-intent | Only detected when labelled (`password: X`) |
| `credit_card` | HIGH | `redact_one_way` + confirm-on-intent | Luhn-validated |
| `ssn` | MEDIUM | `redact` (round-trip) | US format `xxx-xx-xxxx` |
| `email` | MEDIUM | `redact` (round-trip) | Toggle in dashboard |
| `phone` | MEDIUM | `redact` (round-trip) | US + international formats |
| `ip_address` | LOW | `allow` (flag only) | IPv4 dotted quad |
| `url_path` | LOW | `allow` (flag only) | HTTP(S) URLs with a path |
| `person_name` | LOW | `allow` (flag only) | Not detected yet — NER lands with T-DLP-TIER3 |

## The "Allow session" flow (notification-based)

HIGH-tier findings are always redacted silently and immediately — the AI receives the static marker, not the plaintext. There is no CLI prompt blocking the response.

When a HIGH-tier redaction fires, cloakline:

1. Sends the redacted body upstream immediately. The AI responds with `[REDACTED_PASSWORD]` (or similar), which signals to the user that something was masked.
2. Fires a **Windows balloon notification** (appears near the system tray) that says what was blocked. The notification has two buttons:
   - **Allow session** — opens `http://127.0.0.1:4001/admin/session/allow?nonce=<one-time-token>` in the default browser.
   - **Keep blocked** — dismisses; nothing changes.
3. If the user clicks **Allow session**, the admin server consumes the nonce, calls `handler.OptOutSession(sessionKey)`, and shows a confirmation page. The session is now opted out for **1 hour**.
4. The user resends their original message. This time cloakline passes it through unmodified because `IsOptedOut(sessionKey)` returns true.

Properties:
- **Never blocks the response.** Claude always replies, even when redaction fires.
- **No timing window.** The user can click "Allow session" at any point within 5 minutes of the notification appearing; after that the nonce expires.
- **Works in Desktop, CLI, and Cursor.** No multi-turn synchronization needed.
- **Nonce is single-use.** Clicking "Allow session" twice does nothing on the second click (nonce consumed).

## Storage discipline (per user directive)

- **HIGH-tier plaintext never touches disk.** Not in logs, not in audit, not in the session vault, not in prefs. The audit ring holds only the *kind* string (e.g. `"api_key"`), not the value.
- **HIGH-tier plaintext does not live in memory after redaction.** The old y/n confirmation flow that stored an encrypted copy of the pending body has been removed. `[REDACTED_*]` markers are written into the forwarded body and the original bytes are never held.
- **The allow-session nonce** (`internal/adminui nonceEntry`) holds only a SHA-256 session key (never the plaintext), expires in 5 minutes, and is stored only in process memory.
- **Anything else cloakline persists** (prefs, keys) is AES-encrypted at rest with a per-user key wrapped by the OS (DPAPI on Windows).

## Overriding the defaults

- Edit `configs/rules.yaml` — YAML-based, requires cloakline restart.
- Use the dashboard `/admin/prefs` panel — takes effect on the next request, no restart.
- Runtime prefs override YAML rules; YAML rules override the tier defaults.
