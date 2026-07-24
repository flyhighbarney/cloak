# cloakline Guard — VS Code Extension

Real-time detection of PII, secrets, and API keys in your open files. Warns you *before* you paste them into Copilot, Cursor, Claude Code, or any other AI assistant.

## Features

- 🔴 **Real-time diagnostics** — SSNs, credit cards, emails, private keys, AWS/GitHub tokens, and generic API keys light up as you type.
- 🛡️ **Runs entirely locally** — no data leaves your machine. Not even to cloakline.
- 🔍 **Command palette actions**:
  - `cloakline: Scan Current File`
  - `cloakline: Scan Selection`
  - `cloakline: Show Recent Findings`
  - `cloakline: Configure Gateway`
- 📊 **Status bar** shows total findings for the current session.

## Configuration

Open **Settings → Extensions → cloakline**:

| Setting | Default | Meaning |
|---|---|---|
| `cloakline.gatewayUrl` | *(empty)* | Optional. Your cloakline gateway URL for the "Show findings" link. |
| `cloakline.scanOnSave` | `true` | Rescan on file save. |
| `cloakline.scanOnType` | `true` | Rescan 500 ms after last keystroke. |
| `cloakline.severity` | `warning` | `error` \| `warning` \| `information` — how loudly to flag findings. |

## What it detects

| Kind | Example |
|---|---|
| US Social Security number | `123-45-6789` |
| Credit card number | Luhn-validated 13–19 digit sequences |
| Email address | `alice@company.com` |
| Generic API keys | `sk-...`, `pk-...`, `api_key_...`, `token_...` |
| AWS access keys | `AKIAxxxxxxxxxxxxxxxx` |
| GitHub tokens | `ghp_...`, `gho_...`, `github_pat_...` |
| PEM private keys | `-----BEGIN … PRIVATE KEY-----` |

The pattern set mirrors [cloakline's server-side DLP](https://github.com/flyhighbarney/cloakline/blob/main/internal/dlp/patterns/patterns.go) so what shows up in the editor matches what the gateway would block.

## Install for local development

```bash
cd vscode
npm install
npm run compile
# Press F5 in VS Code to launch an Extension Development Host
```

## Package + publish

```bash
npm run package     # produces cloakline-guard-0.1.0.vsix
npx vsce publish    # requires a Marketplace publisher account
```

## License

Apache 2.0. Same as the rest of the [cloakline project](https://github.com/flyhighbarney/cloakline).
