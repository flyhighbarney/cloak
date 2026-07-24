# cloakline

Local-first AI security gateway. Redacts PII, secrets, and API keys before they leave your machine.

## Install and run

```bash
npx cloakline install
```

That downloads platform-native binaries + scripts from the [latest GitHub Release](https://github.com/flyhighbarney/policyd/releases) and runs the platform's bootstrap installer.

**Supported platforms:**
- Windows 10 22H2 / Windows 11 (`x64`, `arm64`)
- macOS 12+ (`x64`, `arm64`)

## Other commands

```bash
npx cloakline scan file.txt      # offline DLP scan (no daemon needed)
npx cloakline doctor             # local health check
npx cloakline tail               # live terminal dashboard
npx cloakline dashboard          # open admin UI in browser
npx cloakline setup              # interactive setup wizard
npx cloakline uninstall          # reverse the install
```

Any subcommand not listed above is forwarded to the underlying `cloak` binary, so `npx cloakline <anything>` maps to `cloak <anything>`.

## Where things end up

| Location | Contents |
|---|---|
| **Windows** `%LOCALAPPDATA%\cloakline\` | Binaries (`bin\*.exe`), configs, scripts |
| **macOS** `~/.cloakline/` | Binaries (`bin/*`), configs, scripts |

The npm package itself (`node_modules/cloakline`) contains only this JS shim — safe to `rm -rf` after install.

## Docs and source

See the full [project README](https://github.com/flyhighbarney/policyd) and [docs/GUIDE.md](https://github.com/flyhighbarney/policyd/blob/main/docs/GUIDE.md) for architecture, security model, and troubleshooting.

## License

Apache-2.0
