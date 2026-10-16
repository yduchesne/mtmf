# MTMF Roadmap — Unscheduled Backlog

## Purpose and scope

This document records proposed work that has **not** been assigned to a specific MTMF release or an approved implementation PR sequence. It is an intake and prioritization backlog, not a commitment, acceptance of an architecture, or evidence that functionality is implemented.

Version-specific plans remain in `ROADMAP_V01.md` and future versioned roadmaps. When an item is approved for a release, transfer it to that release's roadmap with explicit PR boundaries, acceptance criteria, dependencies, and security review; update this document to link to the plan or remove the duplicate. Do not silently expand v0.1 scope.

## Unscheduled items

### R-001 — Provider-neutral OIDC trust and issuer assurance

**Status:** Proposed; architecture review required. **Target version:** Unassigned. **Priority:** Before production multi-IdP support.

**Problem.** The current development authentication path verifies JWTs locally with JWKS, but also performs synchronous, zero-positive-cache Keycloak Admin REST realm attestation and twice-per-actor-resolution client attestation. The Admin REST projection, expected client policy, and `azp`/`client_id` token-class interpretation are Keycloak-specific. Other IdPs cannot be assumed to expose equivalent admin APIs or token claims. The Admin REST reader also requests an attestation client-credentials token for each individual configuration read, making authenticated API requests dependent on IdP administrative availability and increasing latency/load.

**Desired direction (not yet approved design):**

- Preserve the provider-neutral JWT verification and authoritative MTMF identity/Application/Tenant/subscription/authorization boundary; accept only explicitly configured trusted issuers, algorithms, audiences, token classes and verified client bindings.
- Define an explicit provider-neutral **verified credential identity and class** contract. Specify how each provider derives service vs interactive-user evidence from *validated* claims and provider policy; never infer class solely from an unverified claim or silently treat an absent Keycloak-specific claim as equivalent.
- Separate request-path authentication from **issuer-configuration assurance**. Consider optional provider-specific assurance adapters (Keycloak initially), independently scheduled or startup attestation, bounded freshness, explicit drift and unavailability handling, and operational observability. Avoid assuming OIDC standardizes IdP administrative configuration.
- Make assurance requirements an explicit deployment policy. A configured mandatory assurance requirement must fail closed on drift, stale/unavailable attestation, or unsupported adapter; no implicit downgrade or automatic adoption of live issuer configuration. Clearly define the behavior for deployments that do not require provider-specific attestation.
- Define JWKS refresh, unknown-`kid` and rotation handling, cache-expiry behavior, concurrency/thundering-herd controls, IdP outages, and bounded stale-key policy. Preserve fail-closed token verification.
- Keep the existing Keycloak development profile working until migration is reviewed; do not enable the currently disabled production profile through this documentation item.

**Acceptance criteria for a future implementation plan:**

1. A documented trust model and threat analysis cover issuer compromise/configuration drift, client impersonation, token-class confusion, key rotation, revocation limitations, IdP outage, and administrative API privilege exposure.
2. Provider-neutral interfaces support a second OIDC issuer with different claim conventions **without** Keycloak Admin REST dependencies.
3. Negative tests reject cross-issuer/cross-audience/cross-client, wrong token class, missing/ambiguous identity evidence, untrusted `kid`, policy downgrade, and stale mandatory assurance.
4. Tests exercise attestation drift, outage, freshness expiry, recovery, and explicit no-attestation policy; no silent fallback.
5. Benchmark request-path latency and IdP call counts, and document operational requirements and migration gates.
6. Update versioned roadmap and create bounded PR plan(s) only after architecture review.

**Relevant current code:** `packages/mtmf-service/src/mtmf_service/authentication/{jwt_verifier,attestation,composition,config}.py`; `packages/mtmf-core/src/mtmf_core/application/authentication.py`.

### R-002 — First-class administrative CLI (`mtmf-cli`)

**Status:** Architecture approved; implementation not started. **Target version:** Unassigned. **Priority:** Staged delivery, parallel to onboarding PRs 21–26.

**Architecture:** [Administrative CLI — Architecture and Requirements](CLI_ARCHITECTURE.md).

**Problem.** MTMF needs a supported, scriptable, human-friendly administration interface without granting operators or consuming Applications direct database access or privileged internal-service access.

**Intended outcome:** Deliver a separately installable Python `mtmf-cli` with a hierarchical Typer/Rich `mtmf` command, named profiles, secure authentication, deterministic human/JSON output, stable exit codes, and resource-management operations backed **exclusively** by the official `mtmf-client` and versioned authorized HTTPS endpoints. The CLI must never import MTMF internals, invoke privileged initialization/root recovery, impersonate users, or infer authority from Client Credentials.

**Staged implementation:**

1. **CLI-1 — Foundation:** distribution/workspace packaging, command shell, configuration/profile precedence, supported authentication, redaction, output/error contracts, completion, clean-install and deterministic tests. Do not invent unsupported API operations.
2. **CLI-2 — Existing API coverage:** implement only commands supported by real authenticated/authorized HTTP endpoints; require deployed authorization, cross-Tenant denial and mutation-audit acceptance.
3. **CLI-3 — Expanded management:** add Tenant, Organization, Group, Role, Application/subscription and invitation commands only as corresponding versioned APIs and official client operations become available. In particular, `mtmf tenants add` is gated on approved onboarding contracts and implementation in PRs 21–26.

**Security and dependency gates:** Reuse server-side verified service and acting-user identities, exact-Action authorization, explicit Tenant context, default DENY and atomic audit. The CLI is **not** a root recovery tool. CLI-1/2 may proceed independently of PRs 21–26; CLI-3 depends on the relevant HTTP operations. Each implementation PR must include its own security and acceptance evidence, including negative cases. Detailed design, proposed commands and testing requirements are normative in [`CLI_ARCHITECTURE.md`](CLI_ARCHITECTURE.md).

**Promotion:** Assign release and bounded implementation PR identifiers only after prioritization; retain this item here until that decision, then cross-link the versioned roadmap rather than duplicating commitments.

## Backlog maintenance

Use stable IDs, problem statement, security implications, dependencies, proposed outcome, and disposition. Items remain uncommitted until promoted into a versioned roadmap. This file must not be used to bypass the existing release gates or authorization invariants.
