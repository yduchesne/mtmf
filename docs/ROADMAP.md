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

## Backlog maintenance

Use stable IDs, problem statement, security implications, dependencies, proposed outcome, and disposition. Items remain uncommitted until promoted into a versioned roadmap. This file must not be used to bypass the existing release gates or authorization invariants.
