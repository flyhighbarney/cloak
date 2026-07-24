# Versioning

Two independent version streams. Neither is optional.

1. **Component API version** — the contract between the composition root and each pluggable implementation (Stage, Router, Upstream, Transport, Vault, Extractor, Meter, PolicyEngine).
2. **Config schema version** — the shape of `providers.yaml`, `principals.yaml`, `policies.cel`, `pipeline.yaml`.

Provider wire versions (e.g. OpenAI's `2024-08-06` or Anthropic's `anthropic-version` header) are a separate concern — handled inside each upstream adapter, not visible outside.

## Component API Version

### Format

`vN.M` — no third component, no prereleases. Example: `v1.0`, `v1.3`, `v2.0`.

- **N (major)** — incremented on any breaking change to the interface: method signature change, method removal, semantic contract change, error-type change.
- **M (minor)** — incremented on additive changes only: new method with a documented default for existing impls, new struct field with a defined zero value, new error type.

### Interfaces That Carry Version

Every interface defined in [interface-contracts.md](interface-contracts.md) has:

```go
type Xxx interface {
    APIVersion() string    // returns e.g. "v1.0"
    // ... other methods
}
```

`APIVersion()` is called exactly once per implementation at composition-root startup. It is not called on the hot path.

### Composition-Root Compatibility Table

`cmd/cloakline/versions.go` (Phase 0 stub):

```go
var supported = map[string]VersionRange{
    "Stage":         {Min: "v1.0", MaxExclusive: "v2.0"},
    "Router":        {Min: "v1.0", MaxExclusive: "v2.0"},
    "Upstream":      {Min: "v1.0", MaxExclusive: "v2.0"},
    "Transport":     {Min: "v1.0", MaxExclusive: "v2.0"},
    "SessionVault":  {Min: "v1.0", MaxExclusive: "v2.0"},
    "Extractor":     {Min: "v1.0", MaxExclusive: "v2.0"},
    "Meter":         {Min: "v1.0", MaxExclusive: "v2.0"},
    "PolicyEngine":  {Min: "v1.0", MaxExclusive: "v2.0"},
}
```

At startup, for each registered impl:
1. Read the interface it implements.
2. Look up the compatibility range in `supported`.
3. Call `impl.APIVersion()`.
4. If not in the range, panic with:
   ```
   version mismatch: interface=Stage impl=DLPTier1
   want v1.0 ≤ v < v2.0, got v0.9
   ```

There is no "just skip it and continue" path. A misversioned component is a boot failure.

### Deprecation Cycle

To evolve an interface:

1. **Design the change.** Decide: additive (minor) or breaking (major)?
2. **Additive path.** Add the new method/field with a documented default. Existing impls (still on the old minor) continue to work. Bump minor. New impls use it.
3. **Breaking path.** Ship a new major version of the interface *alongside* the old one:
   - `internal/api/stage.go` keeps `type Stage interface { ... }` at v1.
   - New `internal/api/stage_v2.go` adds `type StageV2 interface { ... }`.
   - Composition root accepts either. Documentation marks v1 as deprecated with a target removal date at least two minor releases out.
4. **Removal.** After the deprecation window, drop v1. Bump the composition root compatibility table.

Minimum deprecation window: **two minor releases OR one calendar quarter**, whichever is longer.

### What Constitutes a Breaking Change

- Removing a method or field.
- Renaming a method or field (equivalent to removal + addition).
- Changing a method signature (any parameter or return type).
- Changing the semantic contract (e.g. `Send` may now return `nil, nil` where it previously always returned a non-nil pair).
- Changing an error's identity (e.g. splitting `ErrProvider` into `ErrProviderTransient` and `ErrProviderPermanent` if existing code was matching on `ErrProvider`).
- Reordering behaviors around defined guarantees (e.g. making a previously synchronous method eventually consistent).

What is not breaking:
- Adding a new method that has a documented default behavior for old impls (the composition root supplies a shim wrapper).
- Adding a new field to a struct with a zero value that preserves prior behavior.
- Adding a new error type that no existing code claims to match.
- Adding a new implementation.

## Config Schema Version

### Format

Every config file carries a top-level `schema_version` field:

```yaml
schema_version: v1.0
env: prod
security: strict
# ... rest of file
```

Same `vN.M` semantics as component APIs.

### Loading

The config loader:

1. Reads `schema_version`.
2. Looks it up in the loader's version table.
3. If unknown, refuses to load. Not a silent upgrade attempt.
4. If known but older than the current major, may run a documented forward-migration; otherwise fails.

The composition root refuses to boot with any config version outside the supported range.

### Migrations

Config migrations are Go code in `internal/config/migrate/`. Each migration is:

- One function: `func Migrate_v1_1_to_v1_2(in RawConfig) (RawConfig, error)`.
- Idempotent.
- Well-tested against real config samples.
- Referenced by the loader's version dispatch table.

Migrations run before validation. A migration that changes semantics silently is a bug — write to logs at INFO level explaining the migration performed.

## Policy Version (CEL)

Each CEL policy file entry has:

```yaml
policies:
  - id: openai-default-v1
    api_version: v1.0     # policy environment version
    kind: routing
    expression: |
      ...
```

`api_version` here refers to the **policy environment** version (which variables and functions are exposed to CEL) — see [policy-language.md](policy-language.md).

Policy environment version bumps follow the same rules:
- Additive helper functions or fields → minor bump.
- Removing/renaming a helper or field → major bump.

At load, each policy's declared environment version is checked against the runtime environment version.

## Wire Version (Provider APIs)

**Not covered by this document.** Each upstream adapter (`internal/upstream/openai/`, `internal/upstream/anthropic/`, ...) manages its own wire-version pinning via provider-appropriate headers (`OpenAI-Beta`, `anthropic-version`, `api-version`).

Rationale: provider wire versions change on the provider's schedule, not ours. Coupling them to our internal versioning would force our release cadence to match five different vendors.

Each upstream adapter documents its pinned wire version(s) in its package doc and logs the pinned version at load.

## Rules of Thumb

1. When in doubt whether a change is breaking, treat it as breaking.
2. `APIVersion()` is a required method — no zero-config "unversioned" impls.
3. The composition root is the only place that enforces versions. Individual stages/adapters do not check versions of their peers.
4. Migrations move forward only. There is no downgrade path.
5. Every version bump is called out in the changelog with the interface name and the reason.
6. Deprecation windows are honored. "One-off exceptions" are not.

## Phase 0 Baseline

All interfaces launch at `v1.0`. Config schema launches at `v1.0`. Policy env launches at `v1.0`.

The first minor bump (`v1.1`) fires the first time an interface gains a method after Phase 0 lands. The first major bump (`v2.0`) is a project event and requires a design review.
