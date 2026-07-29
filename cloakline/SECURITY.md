# Security Policy

## Reporting a vulnerability

If you have discovered a security vulnerability in cloakline, please **do not open a public issue.** Instead, email:

**security@cloakline.dev** *(or contact the maintainer directly via the GitHub account listed in the repo — [flyhighbarney](https://github.com/flyhighbarney))*

We will acknowledge receipt within **72 hours** and provide an estimated remediation timeline within **7 days**.

## Supported versions

cloakline is under active development. Only the `main` branch is currently supported for security fixes. Once tagged releases begin, we will maintain the current major version and issue security patches for the previous one for at least six months.

## Scope

**In scope:**
- The `cloakline` binary and its libraries under `internal/`.
- The `cloak` CLI.
- The deployment recipe under `deploy/` (Caddyfile, docker-compose.yml, deploy.sh).
- Documentation that gives incorrect security guidance.

**Out of scope:**
- Vulnerabilities in third-party dependencies — please report those directly to the upstream project. If a dependency vulnerability materially affects cloakline's security posture, we will publish an advisory.
- Vulnerabilities in the upstream LLM providers (OpenAI, Anthropic, etc.) — report to those vendors directly.
- Social engineering, physical attacks, or attacks that require compromising the host operating system.

## Threat model

Please read [`docs/threat-model.md`](docs/threat-model.md) before reporting. Many attack vectors are already documented there with their mitigation status. If your report addresses a threat *not* covered in that document, that's especially valuable.

## Vulnerability disclosure

We follow **coordinated disclosure**:

1. You report privately.
2. We acknowledge, assess, and produce a fix.
3. Once a fix is available, we publish a GitHub Security Advisory that credits you (unless you request anonymity) and describes the vulnerability, its impact, and the remediation.
4. If the vulnerability requires operator action (config change, key rotation, etc.), we publish a runbook alongside the advisory.

## Bounty

There is currently **no monetary bug bounty program**. This is a bootstrapped project. We will credit you publicly and are happy to provide a written recommendation for security work.

## Governance-level security concerns

The following are known operational risks called out explicitly in [`docs/threat-model.md`](docs/threat-model.md):

- Operators disabling DLP "temporarily for debugging."
- `LOG_LEVEL=debug` left on in production, causing prompt content to appear in logs.
- Config drift across instances (mitigated by exporting `cloakline_config_hash` as a metric).
- Real cloud API keys accidentally committed to git (mitigated by `.gitignore` and the loader refusing inline keys).

Governance concerns are not vulnerabilities per se, but reports of *ineffective* mitigations for these threats are in scope.

## Cryptography

cloakline does not implement its own cryptography. TLS is delegated to Caddy (Let's Encrypt); virtual keys are hashed with SHA-256 via the Go standard library. If you find a place where custom cryptography has snuck in, that is itself a bug.

## Contact

- **Security:** security@cloakline.dev *(update this address before flipping the repo public)*
- **General:** open a GitHub issue in this repository.

Thank you for helping keep cloakline users safe.
