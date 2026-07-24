# policyd Guard — VS Code Extension

Real-time detection of PII, secrets, and API keys in your open files. Warns you *before* you paste them into Copilot, Cursor, Claude Code, or any other AI assistant.

## Features

- 🔴 **Real-time diagnostics** — SSNs, credit cards, emails, private keys, AWS/GitHub tokens, and generic API keys light up as you type.
- 🛡️ **Runs entirely locally** — no data leaves your machine. Not even to policyd.
- 🔍 **Command palette actions**:
  - `policyd: Scan Current File`
  - `policyd: Scan Selection`
  - `policyd: Show Recent Findings`
  - `policyd: Configure Gateway`
- 📊 **Status bar** shows total findings for the current session.

## Configuration

Open **Settings → Extensions → policyd**:

| Setting | Default | Meaning |
|---|---|---|
| `policyd.gatewayUrl` | *(empty)* | Optional. Your policyd gateway URL for the "Show findings" link. |
| `policyd.scanOnSave` | `true` | Rescan on file save. |
| `policyd.scanOnType` | `true` | Rescan 500 ms after last keystroke. |
| `policyd.severity` | `warning` | `error` \| `warning` \| `information` — how loudly to flag findings. |

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

The pattern set mirrors [policyd's server-side DLP](https://github.com/flyhighbarney/policyd/blob/main/internal/dlp/patterns/patterns.go) so what shows up in the editor matches what the gateway would block.

## Install for local development

```bash
cd vscode
npm install
npm run compile
# Press F5 in VS Code to launch an Extension Development Host
```

## Package + publish

```bash
npm run package     # produces policyd-guard-0.1.0.vsix
npx vsce publish    # requires a Marketplace publisher account
```

## License

Apache 2.0. Same as the rest of the [policyd project](https://github.com/flyhighbarney/policyd).
