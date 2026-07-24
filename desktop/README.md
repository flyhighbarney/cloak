# cloakline Desktop

A native Mac + Windows companion for the [cloakline](https://github.com/flyhighbarney/cloakline) gateway. Built with [Wails](https://wails.io/) (Go backend + web frontend, single binary).

## What it does

- **Compose window** for AI prompts with **local redaction preview**. As you type, sensitive strings (SSNs, credit cards, emails, API keys, PEM blocks) are highlighted *before* the prompt ever leaves your machine.
- **Send to AI** button routes the prompt through your cloakline gateway. Both OpenAI-shaped (`/v1/chat/completions`) and Anthropic-shaped (`/v1/messages`) models are supported.
- **Settings panel** stores gateway URL + virtual key in `~/.config/policyctl/config.yaml` (shared with the CLI).
- **Live health pill** in the header shows whether the gateway is reachable.

Non-dev end users (paralegals, associates, analysts) get an AI-composer that can't leak their client's data. This is the shape that makes the sale to a law firm.

## Build prerequisites

- Go 1.22+
- Node.js 20+
- [Wails CLI](https://wails.io/docs/gettingstarted/installation): `go install github.com/wailsapp/wails/v2/cmd/wails@latest`

## Development

```bash
cd desktop
wails dev
```

Wails hot-reloads the frontend and rebuilds the Go binary on save.

## Build a release binary

```bash
cd desktop
wails build              # cross-compile disabled; run on target OS
```

Output lands in `desktop/build/bin/`:

- **macOS:** `cloakline-desktop.app` bundle (unsigned — see below).
- **Windows:** `cloakline-desktop.exe`.
- **Linux:** `cloakline-desktop`.

## Code signing (Mac)

Unsigned Mac binaries prompt users with "unidentified developer." To ship broadly:

1. Enroll in the [Apple Developer Program](https://developer.apple.com/programs/) ($99/year).
2. Follow [Wails' macOS notarization guide](https://wails.io/docs/guides/mac-menu-bar/).

The `.app` bundle works locally without signing — right-click → Open on first launch bypasses Gatekeeper.

## Config

The desktop app shares its config file with `cloak`. Set it up once and either tool works.

If you ran `cloak login <url>` already, the desktop app finds the config automatically. Otherwise use the ⚙ (Settings) button in the header.

## What it deliberately does not do

- **No dev-tool features.** No file scanning, no audit dashboard, no key management. Those live in the CLI and the web `/admin` page.
- **No streaming display.** Responses arrive as one blob. Streaming UI ships when there's demand.
- **No conversation history.** Every prompt is one shot. Multi-turn is a future addition.

Focused on the one job that non-devs actually do with AI: paste something, get an answer, don't leak your client.

## License

Apache 2.0.
