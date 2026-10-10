# HTTP Integration and Batch Authorization — v0.1 Planned Design

> **STATUS: DESIGN ONLY — NOT IMPLEMENTED.** This document records the agreed target architecture for future roadmap PRs 12–20. No application registry, Tenant subscription checks, trusted HTTP actor propagation, batch authorization endpoint, native Rust batch evaluator, or client authorization snapshot is implemented by this documentation PR. Existing single-action `Authorizer` and PR 8H Python `CompiledPolicy` remain the implemented baseline. See [ROADMAP_V01.md](ROADMAP_V01.md).

## 1. Trust boundary and responsibilities

MTMF is a separately deployed, authoritative **Policy Decision Point (PDP)** exposed through a versioned HTTPS API. Consuming applications (ATI, Digr, Darkula, Hammeridian) are **Policy Enforcement Points (PEPs)**: they authenticate users through their chosen trusted flow, request authorization decisions, and enforce the returned effects at handlers, workflows, and database/data-access boundaries. MTMF never substitutes for application-side row/resource isolation.

- **`mtmf-core` (PDP internals; PR 16):** authoritative policy and role resolution, subscription-eligibility orchestration (PR 13), fail-closed authorization, Python semantic reference, and native Rust batch evaluation after parity/performance validation. Not imported by consuming applications.
- **`mtmf-api` (contract; PR 15):** detached, versioned request/response types, errors and semantic contract; no core/PyO3/PostgreSQL/FastAPI types leak into the public contract.
- **`mtmf-service` (HTTP trust boundary; PRs 14, 17):** validates service credentials, verified end-user context, Tenant/Organization binding, request size and errors; invokes core PDP and returns decisions.
- **`mtmf-client` (PEP convenience; PR 18):** HTTP transport, validated batch results, short-lived scoped authorization snapshots and `require`/`is_allowed` helpers. Does not decide policy, embed the Rust engine, or guarantee enforcement when application code bypasses it.
- **Consuming application (PEP; PR 20 ATI reference):** owns domain data and resource ownership checks, places enforcement at trusted boundaries, and prevents cross-Tenant data access even if an action-level capability is ALLOW.

Consumers MUST NOT connect directly to MTMF PostgreSQL or use `mtmf-core` as an embedded authorization library. Internal MTMF package use is unaffected.

## 2. Authentication, subscription and authorization are separate gates

1. **Authentication (PR 14):** OAuth 2.0 client credentials authenticate the calling service; MTMF derives the registered Application from validated credentials. End-user identity propagation is separately verified; a supplied `principal_id` or `identity_id` alone is not evidence. Verify issuer, audience, signature, expiry, service-to-Application mapping, and authorization to act for the selected user/Tenant.
2. **Subscription eligibility (PR 13):** a Tenant subscribes to a registered Application. Missing, expired, suspended or cancelled subscriptions deny new application authorization grants; Tenant-level subscriptions do not automatically grant Organization-level permissions. Billing and metering are excluded.
3. **Authorization (PRs 15–17):** MTMF evaluates explicit requested Actions against applicable Roles/PermissionSets/Permissions, existing scope and dominance rules, and the verified context. Subscription eligibility is a prerequisite, never a replacement for permission evaluation.

If any gate fails, no ALLOW may be issued. A user may belong to multiple Tenants: the requested active Tenant must be verified and explicitly bound to every decision. Do not confuse the service's OAuth client identity with the end user's acting Identity.

## 3. Proposed HTTP batch API (PR 15 contract; PR 17 implementation)

`POST /v1/authorization/evaluate` is a **future proposed endpoint, not available today**. The service identity/Application is derived from the authenticated access token and MUST NOT be trusted from a request-body application key. User context must be tied to a validated end-user authentication assertion or an approved delegation mechanism (exact token exchange/verification format to be settled in PR 12/14).

Illustrative logical request **after authentication context verification** (not a final wire schema):

```json
{
  "tenant_id": "tenant-uuid",
  "organization_id": "organization-uuid",
  "actions": [
    {"action": "urn:example:investigation:read", "scope": "organization"},
    {"action": "urn:example:investigation:delete", "scope": "organization"}
  ]
}
```

Illustrative response (the actual Action URNs, response envelope, reason taxonomy, and scope encoding remain PR 15 design work):

```json
{
  "decisions": [
    {"action": "urn:example:investigation:read", "effect": "ALLOW"},
    {"action": "urn:example:investigation:delete", "effect": "DENY", "reason": "NO_MATCHING_PERMISSION"}
  ],
  "snapshot_id": "opaque-correlation-id",
  "issued_at": "2026-10-09T00:00:00Z",
  "expires_at": "2026-10-09T00:05:00Z"
}
```

Every requested Action receives exactly one correlated decision; preserve input ordering or stable request identifiers, even with duplicates. Unknown/unrecognized Actions and missing decisions MUST deny; infrastructure/authentication failures MUST NOT be transformed into ALLOW. Invalid authentication normally yields an HTTP error rather than an authorization snapshot. API errors must distinguish transport failures from a legitimate policy DENY. No implicit "all permissions" response is required in v0.1.

**Capability vs resource authorization:** an ALLOW for a general capability (e.g., read investigations in an Organization) is not blanket permission to read every investigation. When resource-specific policies are owned by MTMF, the request must contain adequate resource/scope qualifiers or require fresh resource-scoped evaluation. Application-owned constraints and Tenant-isolated queries remain the PEP's responsibility.

## 4. Client snapshots and revocation (PR 18)

The client helper validates and retains decisions only for their **exact authenticated Application, verified acting user, Tenant, optional Organization, target/resource scope, and enumerated Action set**. It exposes `is_allowed(action, scope)` and `require(action, scope)`; unknown, missing, expired, malformed or context-mismatched decisions deny. Snapshots are server-side application objects, **not bearer credentials** for browsers or cross-service delegation. Do not allow an ALLOW for one Organization, resource, user, or Tenant to be replayed in another.

A short configurable TTL (five minutes is a *proposal*, not a committed default) bounds the worst-case stale-grant window absent active invalidation. Revocation of a Role, membership, or subscription is not retroactive for already-issued valid snapshots. Sensitive actions may require shorter TTL or a fresh resource-scoped decision. If MTMF is unavailable, no new grants are created; previously verified decisions may be used only within their original scope and unexpired lifetime. Client code must not silently extend expired snapshots.

## 5. Native batch performance (PR 16)

The existing PR 8G experiment found pure-Python indexed `CompiledPolicy` faster than repeated single-action Rust FFI calls; PR 8H productionized the Python default. Batch evaluation may amortize conversion/crossing overhead, **but Rust superiority is unproven**.

PR 16 must send one detached, validated shared context/policy and an Action array across the Python/Rust boundary **once per batch**, then return ordered effects; do not implement a Python loop of N Rust invocations. Compare Python single-action, Python native batch, and Rust native batch, including shared-policy preparation, object conversion, parsing, evaluation, and result conversion. Test batch sizes 1/5/10/25/50/100/500, realistic policy sizes, p50/p95/p99 latency, throughput, allocations, and full semantic parity. Preserve Python as the default unless empirical evidence justifies a change.

## 6. Implementation ownership and acceptance

| Roadmap PR | Planned deliverable | Implemented now? |
| --- | --- | --- |
| 12 | Architecture, trust, and batch contracts | No — this document is advance design guidance |
| 13 | Application registration and Tenant subscriptions | No |
| 14 | Trusted service/end-user authentication boundary | No |
| 15 | Versioned HTTP batch API DTO contract | No |
| 16 | Python/Rust native batch and parity benchmarks | No |
| 17 | Authenticated HTTP service endpoint | No |
| 18 | HTTP client and scoped snapshot enforcement helper | No |
| 19 | Decision observability/audit | No |
| 20 | ATI PEP reference integration and E2E security validation | No |

Future coding PRs must define exact action URNs, DTO schemas, token propagation/verification, authorization failure taxonomy, subscription lifecycle transitions, resource-scoping rules, and TTL policy before exposing these capabilities. No API or runtime behavior is claimed by this document.
