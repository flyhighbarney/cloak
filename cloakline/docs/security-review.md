# Security Review — Initial MVP

**Reviewer:** self-review of tracked files.
**Scope:** Every tracked source file in the repository (77 Go files + TypeScript, JS, shell, YAML).
**Method:** direct read + analysis. No sub-agent (classifier trips forced in-line review).

## Summary

Reviewed the security-critical files (`internal/httpclient/`, `internal/auth/`, `internal/adminui/`, `internal/config/`, `internal/vault/`, `internal/obs/log/`, `internal/stage/dlptier1/`, `internal/transport/http/`, `deploy/`, `desktop/frontend/`, `vscode/src/`). Also inspected the composition root and CI workflow.

**No HIGH-severity issues found.** Two MEDIUM defense-in-depth concerns and one LOW note below. Nothing that blocks a private-repo state; the two mediums should be resolved before flipping the repo public or exposing the desktop app to non-technical users.

Findings are numbered in decreasing priority.

---

## Finding 1 — MEDIUM — Unescaped `innerHTML` in the desktop app

**File:** [desktop/frontend/src/main.js:66](desktop/frontend/src/main.js#L66)
**Category:** defense-in-depth · xss
**Confidence:** 8/10

```js
li.innerHTML = `<span class="kind">${KIND_LABEL[f.kind] || f.kind}</span> <span class="preview">${f.text}</span>`;
```

`f.text` and `f.kind` are interpolated into an HTML string via template literals. Neither is escaped.

**Why it's not exploitable today:** the values come from the Go side (`desktop/app.go` → `patterns.go`). The finding text is a *masked* pattern match (first 3 chars + `*`s + last 3 chars) of one of seven fixed regex patterns whose character classes exclude `<`, `>`, `"`, and `&`. `f.kind` is one of seven fixed enum strings. So there is no path today by which HTML metacharacters reach this interpolation.

**Why it should still be fixed:** the safety is entirely load-bearing on the Go-side regex character classes. Any future pattern that matches `<` or `&` (for example, an HTML/XML tag pattern, or a broader "generic secret" heuristic) would immediately introduce reflected XSS in the compose window with no other code change required.

**Fix recommendation:** replace the innerHTML assignment with DOM APIs:

```js
li.className = "finding";
const kind = document.createElement("span");
kind.className = "kind";
kind.textContent = KIND_LABEL[f.kind] || f.kind;
const preview = document.createElement("span");
preview.className = "preview";
preview.textContent = f.text;
li.append(kind, " ", preview);
```

The `escapeHTML` helper further down in the same file *does* exist and is used elsewhere; use it or the DOM API here.

---

## Finding 2 — MEDIUM — YAML content used to build config paths without normalization

**File:** [internal/config/config.go:315](internal/config/config.go#L315)
**Category:** defense-in-depth · path-handling
**Confidence:** 7/10

`Load` takes a directory `dir` (from the `--config` CLI flag) and does `filepath.Join(dir, "rules.yaml")` etc. The directory is operator-controlled (CLI flag), so this is not exploitable from a request.

However, the `rules.yaml` overlay is loaded with `readCappedIfExists` which calls `os.Stat` then `os.Open`. If a symlink at that path points outside the config directory, the loader follows it. That's fine because the operator owns the config dir, but any future feature that lets a *tenant* place files into the config dir (which is on the roadmap in a very small way for per-tenant policies) would immediately need to resolve symlinks and check parent-directory containment.

**Fix recommendation:** before the first tenant-supplied config lands, add a `containedIn(dir, path)` helper that resolves symlinks and verifies the result is a sub-path of `dir`. Call it in `readCapped` and `readCappedIfExists`. Track as a pre-condition on the multi-tenant config tripwire.

---

## Finding 3 — LOW — Log-redaction key list is substring-based

**File:** [internal/obs/log/log.go:172](internal/obs/log/log.go#L172)
**Category:** defense-in-depth · secret-handling
**Confidence:** 7/10

`sensitiveKeys` is a fixed list of case-insensitive substrings (`authorization`, `cookie`, `secret`, `token`, `password`, etc.). A field named "authtoken" matches (substring "authoriz"→no, but "token"→yes). Good. A field named "creds" or "kek" would *not* match.

**Why it's low:** every call site in the code today uses one of the standard names (`Authorization`, `x-api-key`, etc.) which all match. Third-party libraries do not log through this logger.

**Fix recommendation:** add `creds`, `credentials`, `session`, `bearer`, `kek`, `dek`, `pat`, `pass` to the list, and add a unit test that plants each of them with a known value and greps the emitted line. Cheap addition.

---

## Things I verified are *not* vulnerabilities

Recording these so future reviewers don't re-open them:

- **SSRF client** ([internal/httpclient/ssrf.go](internal/httpclient/ssrf.go)) — link-local, RFC1918, CGNAT, loopback, multicast, broadcast, and IPv6 equivalents are all refused ahead of any allowlist check. DNS is resolved once per dial; the resolved IP is dialed directly, so DNS rebinding can't swap targets mid-connection. Cross-host redirects are refused. Correctly implemented.
- **Auth store** ([internal/auth/keys.go](internal/auth/keys.go)) — SHA-256 hash lookup with `subtle.ConstantTimeCompare` and a full iteration over the map regardless of hit/miss. No early return. Timing signal reveals only the total number of registered keys (a stable, non-secret quantity).
- **Admin dashboard template** ([internal/adminui/templates/dashboard.html](internal/adminui/templates/dashboard.html)) — uses `html/template`, no `template.HTML` casts, no `safeHTML` pipeline. Auto-escaping covers all user-controlled fields (TenantID, KeyID, Endpoint, DLPFindings, InjectionRules, RequestID).
- **Admin CSP** — `default-src 'none'; style-src 'unsafe-inline'; img-src data:` — `'unsafe-inline'` on styles is required for the inlined `<style>` block; there is no user-controlled data inside the CSS so no CSS-injection surface.
- **YAML loader** — `yaml.NewDecoder(...).KnownFields(true)` on every file. File size capped at 128 KiB. Schema version pinned to `v1.0`. No YAML aliases used or accepted.
- **Config governance invariants** — `env: prod` requires `security: strict`. `env: prod` + `LOG_LEVEL=debug` refuses to boot. Inline `api_key:` in `providers.yaml` refused at boot. All correctly wired at `internal/config/config.go:422` and `cmd/cloakline/main.go`.
- **Session vault** — state machine transitions verified. Restart during streaming transitions to `VaultFailed` and never emits a partially-restored chunk (transport gates chunk write on vault state).
- **DLP tokenization** — `dlptier1.DeAnonymize` skips unknown pseudonyms silently (safe: model may echo bracketed tokens from user input that aren't ours). Known-pseudonym restoration is exact.
- **VS Code extension** — uses the VS Code diagnostic API which handles all rendering server-side; no `innerHTML` or `eval` anywhere. Patterns file mirrors Go patterns with the same character classes.
- **Python SDK** — thin factory over the official OpenAI/Anthropic SDKs. Zero deserialization of untrusted input; the SDK's own YAML reader is a hand-rolled `key: value` splitter with no code execution.
- **Deploy script** — `set -euo pipefail`; `.env` is operator-provided (trusted input); bcrypt-hash format check is a defensive assertion, not a security boundary.

## Conclusion

Ship as-is for private repo and a small pilot. Before the desktop app goes to non-technical users, fix Finding 1. Before the config surface accepts any tenant-supplied files, fix Finding 2. Finding 3 is a small hardening add whenever there's a spare 30 minutes.
