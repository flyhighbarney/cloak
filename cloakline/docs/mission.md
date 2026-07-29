# Mission

**We are building a local-first, transport-agnostic AI policy enforcement engine that happens to expose an OpenAI-compatible HTTP gateway.**

The policy engine is the product. The HTTP gateway is one integration surface. MCP, WebSocket/Realtime, SDK-embedded, CLI, and browser-extension are peers — not "future work."

## What this means in practice

- The center of the codebase is `internal/engine/` — the DAG scheduler that runs policy stages over a canonical request. Every other package is either a stage, an adapter, or infrastructure.
- Transports are pluggable. Adding MCP later means writing a `Transport` implementation, not restructuring the core.
- Upstream providers are pluggable. Adding Anthropic later means writing an `Upstream` implementation, not spreading `if provider == "anthropic"` through the pipeline.
- Policies are declarative (CEL). Adding a new routing rule means editing `policies.cel`, not writing Go.

## What we are explicitly not building

We are not building "the best AI gateway." That market has established competitors (LiteLLM, Portkey, Bifrost, Kong AI Gateway, Cloudflare AI Gateway), each with more maintainers than we will have. Competing on gateway features is a losing position.

We are not building a managed cloud control plane. The zero-cost constraint forbids it and the local-first mission makes it counterproductive.

We are not building a compliance SaaS. Hash-chained logs, SSO, and SIEM integration are deferred behind tripwires — they land only when a specific customer conversation forces them.

## What durability looks like

The industry is migrating away from the client → HTTP → gateway → provider shape. MCP, agent-to-agent, edge inference, and in-process interceptors bypass the central-gateway model. A codebase organized around "the HTTP gateway" ages badly. A codebase organized around a policy engine — where HTTP is one of several ways to reach it — stays useful across that migration.

The single durable moat is the policy layer: DLP, guardrails, routing decisions, budget enforcement, audit. Everything else is table stakes or transport plumbing.

## The three tests every decision must pass

1. **Transport-independence** — Does this design work identically whether the request arrives over HTTP, MCP, WebSocket, or an in-process call? If no, redesign.
2. **Provider-independence** — Does this design work identically for OpenAI, Anthropic, Bedrock, Ollama? If no, redesign or push the divergence into an adapter.
3. **Scope-discipline** — Is this the minimum thing that proves the abstraction? If we are building it because it is on the blueprint's feature list rather than because a tripwire fired, we are not building it yet.

## Non-negotiables

- Zero cost. Apache-2.0 / MIT / BSD dependencies only. No paid tiers. No hosted anything.
- Single stateless binary. No database in Phase 0.
- Local-first. The default deployment is a developer's laptop. Cross-machine is a deferred tripwire.
- Modality-first. Text, image, audio, PDF, archive, office are peer content types. DLP is not "regex over text."

## The audience for this mission

This document is the tiebreaker. When two designs both look reasonable, the one that better satisfies this mission wins. When a feature is proposed that satisfies neither test #1 nor test #2 above, this document is the reason to say no.
