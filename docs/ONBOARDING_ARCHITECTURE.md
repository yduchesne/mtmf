# Application-Neutral Onboarding Architecture

> **STATUS: PROPOSED DESIGN — DOCUMENTATION ONLY. NOT IMPLEMENTED.**
> This document freezes the v0.1 onboarding security design, state machines,
> admission rules, and future versioned management contracts so that roadmap
> PRs 22–26 implement a reviewed design rather than invent one. It does **not**
> describe shipped behavior. Every future API is **PROPOSED / NOT IMPLEMENTED**.
> No production readiness is claimed.
>
> **STOP-01 is OPEN.** The trusted authority that creates the first ordinary
> Tenant and its first verified user is not settled. See
> `../pr-artifacts/pr-21/PR21_STOP_REPORT.md`. Until a human reviewer resolves
> STOP-01, this design is a draft and PR 21 is not DONE.
>
> Normative security remains [SECURITY_MODEL.md](SECURITY_MODEL.md); root and
> stewardship behavior remains [ROOT_AND_STEWARDSHIP.md](ROOT_AND_STEWARDSHIP.md);
> HTTP integration remains
> [HTTP_INTEGRATION_BATCH_AUTHORIZATION.md](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md);
> the wire contract for the future endpoints is
> [ONBOARDING_HTTP_CONTRACT.md](ONBOARDING_HTTP_CONTRACT.md). If this document
> conflicts with the Security Model, the Security Model governs.

## 1. Purpose and scope

MTMF is an independent HTTP service. Consuming applications authenticate their
own users, call MTMF through the versioned HTTP API (via `mtmf-client`), and
enforce decisions locally. Onboarding is the problem of:

- creating an ordinary Tenant with a verified first steward;
- reusing global Identities and Principals across Applications and Tenants;
- subscribing an independently authenticated Application to a Tenant; and
- inviting a verified user to an existing Tenant

without circular authorization or privilege escalation.

**In scope (design only):** admission authority, state machines, identity reuse,
lifecycle, stewardship, idempotency, concurrency, transaction/audit semantics,
failure/reconciliation, threats, and the future versioned API contracts.

**Out of scope:** any runtime API, DTO, migration, IdP flow, audit code, CLI
command, or production trust change. This document introduces no new
authorization engine, provider, or generic framework. It reuses the existing
authenticated actor boundary, `EffectiveRoleResolver`, `Authorizer`,
`MtmfSpi`/UnitOfWork, stored-function write boundaries, and audit seams.

## 2. Existing components and reused seams

The following components exist on `main` (baseline `455ae7a`, migration head
`0013`) and MUST be reused rather than duplicated:

| Component | Location | Role in onboarding |
| --- | --- | --- |
| `Tenant` (`owner_identity_id`, `lifecycle`) | `mtmf_core.domain.tenant` | Ordinary Tenants start `PROVISIONING`; ownership is immutable provenance, not authority |
| `TenantStewardshipDesignation` + lifecycle validator | `mtmf_core.domain.stewardship` | Structural stewardship and `PROVISIONING→ACTIVE` transition validation |
| `ExternalSubjectBinding`, `ServiceCredentialBinding` | `mtmf_core.domain.authentication_binding` | Immutable `(issuer, subject)`→Identity and `(issuer, client_id)`→Application bindings |
| `AuthenticatedActorContextService` | `mtmf_core.application.authentication` | Verified two-token actor composition for an **existing** eligible ordinary Tenant + membership |
| `EffectiveRoleResolver` / `build_authorization_context` | `mtmf_core.application.effective_roles` | Tenant-filtered applicable Roles for the `Authorizer` |
| `ManagementAuthorizationResolver` | `mtmf_core.application.management_authorization` | Delegated cross-Tenant management scope (PR 11) |
| `ManagementMembershipService` | `mtmf_core.application.management_memberships` | The reviewed one-UoW authenticated/authorized/audited mutation pattern |
| `VerifiedMutationProvenance` | `mtmf_core.application.mutation_provenance` | Closed registration of audited mutation kinds |
| `ApplicationTenantEligibilityService` | `mtmf_core.application.application_eligibility` | Fail-closed subscription eligibility (never an `ALLOW`) |
| Detached management DTOs / error catalog | `mtmf_api.management`, `mtmf_api.errors` | Versioned request/response and static error envelope |
| `MtmfSpi` / `UnitOfWork` | `mtmf_core.persistence` | One provider, one real transaction per UoW, opt-in commit |
| Mandatory post-upgrade privilege verifier | `PostgresMigrationManager` | Granted-signature allowlist; never bypassed |

The privileged PR 10 bootstrap/stewardship primitives are installation/operator
only and are **never** `mtmf_runtime`-granted. The existing privileged
development initializer is a development fixture, **not** a production
onboarding interface.

## 3. Architectural invariants (binding)

These invariants bind PRs 22–26. They restate
`docs/ROADMAP_V01.md`/`AGENTS.md` and MUST NOT be weakened for convenience.

- MTMF is an independent HTTP service. Consuming systems and CLI use the
  versioned HTTP API via `mtmf-client`, never the database, embedded core, or
  privileged initialization.
- Service Client Credentials authenticate one Application, **not** an acting
  user, Tenant, operator, or permission. Verify user proof independently; never
  trust a caller-supplied Identity/Principal UUID, email, or Tenant ID as
  identity proof.
- No ordinary onboarding in the protected SYSTEM/root Tenant; no root
  subscription, impersonation, or recovery shortcut.
- A global Identity is keyed by a trusted `(issuer, subject)` binding; its
  associated Principal is global. Reuse across Applications and Tenants,
  without inheriting membership in other Tenants.
- A Tenant is not `ACTIVE` until its initial verified steward Principal,
  designated Identity, both Tenant memberships, and authorized Tenant
  Administrator Role assignment are valid and committed.
- Tenant creator/owner provenance does not confer stewardship, Role,
  membership, or Application subscription.
- Default DENY; the server selects the exact Action; trusted actor context,
  explicit Tenant scope, and authoritative Role resolution precede writes.
- One UoW = one real transaction; atomic MTMF state and mutation audit;
  PostgreSQL writes only through approved versioned stored-function boundaries.
  No IdP/network call inside a UoW.
- No partial success on failures; stable authoritative MTMF UUIDs returned after
  commit. No consumer-local transaction is claimed to be atomic with MTMF.
- The existing production root authentication/recovery gate and unscheduled
  multi-IdP work are **not** solved by this design.

## 4. New-Tenant admission

### 4.1 The circular-authentication problem

`AuthenticatedActorContextService.resolve` requires an already existing
ordinary ACTIVE Tenant, the verified user's persisted Identity/Principal
memberships, an eligible Application/Tenant registration and subscription, and
equality between the requested and verified Tenant. It therefore **cannot**
authenticate the first user of a Tenant that does not yet exist. A service
access token alone must never create a Tenant.

### 4.2 Proposed admission model (UNAPPROVED — STOP-01)

**Design decision proposed for approval:** v0.1 new-Tenant provisioning uses a
separately authenticated, approved **operator provisioning authority**, not
ordinary D1 actor resolution. The existing privileged development initializer
is not a production onboarding interface.

Alternative for the reviewer: an explicitly designed, least-privilege
**pre-Tenant** self-service admission with abuse/rate/quota and
operator-delegation controls (STOP-01 Option B). Neither option is approved.

### 4.3 Trusted provisioning sequence

External identity verification and any remote IdP call occur **outside** the
UoW. Then, in one serialized transaction:

```text
verify external issuer/subject and operator authority OUTSIDE UoW
    → begin serialized UoW
    → resolve/reuse global Identity and Principal by verified binding
    → create ordinary PROVISIONING Tenant (unique provisioner+tenant_key)
    → establish Principal+Identity Tenant memberships
    → establish approved Tenant Administrator Role and stewardship
    → verify activation invariant, activate Tenant
    → persist exact mutation provenance and audit atomically
    → commit → return authoritative IDs
```

If the operator authority cannot be established without a bypass, the
implementation MUST STOP; it MUST NOT call the ordinary actor path and pretend
the recipient is already a member, and MUST NOT use the development initializer
or root impersonation.

## 5. Existing-Tenant invitation

A verified Tenant steward/administrator with the exact invitation-create
permission issues an invitation to a specific `(issuer, subject)` and approved
Tenant Role. Invitation creation does **not** grant membership.

A first-time recipient has no Tenant membership, so acceptance needs a
**separate verified-token-only pre-membership admission seam**. It must not call
ordinary actor resolution and pretend the recipient is already a member.
Acceptance requires independent user proof **plus** a single-use capability.
Only the invited Tenant receives the new memberships/Role; an existing global
Identity/Principal is reused.

Invitation state machine (PR 25): `PENDING → ACCEPTED / REVOKED / EXPIRED`.
Terminal states cannot be reopened. Acceptance is one-time and bound to the
independently verified recipient, the exact Tenant, and the approved Role.

## 6. Application subscription

Application **registration** and Tenant **subscription** are distinct.
Creating a Tenant does **not** automatically subscribe the creating Application.
A new subscription requires an independently authorized operator or an existing
eligible Tenant management authority. Existing subscription eligibility cannot
bootstrap its own creation.

Reject inactive Tenant/Application, SYSTEM/root, unauthorized Application ID,
and cross-Tenant requests. Never accept caller-supplied authorization
decisions. The existing `ApplicationTenantEligibilityService` remains the
authoritative eligibility gate; a subscription is eligibility, never a
Permission.

## 7. Global Identity reuse

A global Identity is keyed by a trusted `(issuer, subject)` binding
(`ExternalSubjectBinding`, immutable, `ACTIVE`/`REVOKED`). Its Principal is
global. Reuse is explicit:

- an existing active `(issuer, subject)` binding resolves to the existing
  Identity and Principal; a second Tenant membership does not create a second
  Identity;
- a conflicting binding (a different Identity already bound to the same
  `(issuer, subject)`, or a different subject presented for an existing
  Identity) is a fail-closed integrity error, never a silent reassociation;
- membership in Tenant A never implies membership in Tenant B; cross-Tenant
  state is never unioned;
- `Identity.origin` (`LOCAL`/`FEDERATED`) is not inferred from a name, email,
  or login availability.

## 8. Tenant lifecycle

`ABSENT → PROVISIONING → ACTIVE`; an existing authorized Tenant may
`ACTIVE ↔ SUSPENDED`. `PROVISIONING` is non-authorizing. There is no automatic
activation, silent deletion/recreation, or `ACTIVE` commit without stewardship.
Subscription state may be established separately, and the onboarding response
must reflect it accurately. These states do not replace soft-deletion
semantics.

Frozen identity/ownership fields:

| Field | Identity and ownership | Rule |
| --- | --- | --- |
| `tenant_id` | MTMF UUID | stable, ordinary Tenant only |
| `tenant_key` | provisioner-scoped semantic key | immutable, unique in the provisioning authority scope; **new future persistence requirement**, not current `Tenant.name` |
| `name` | display metadata | mutable and non-unique, never used to deduplicate |
| `identity_id` | MTMF UUID | global, unique active external `(issuer, subject)` binding |
| `principal_id` | MTMF UUID | global; reuse for an existing verified Identity |
| `application_id` | MTMF registered Application | derived from the verified service binding; never trusted from the body |
| `operation_id` | server-generated audit correlation | distinct from the client idempotency key |
| `idempotency_key` | client-generated UUID | durable replay key scoped by authenticated Application/operator and operation kind |

`tenant_key` grammar: `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`, case-sensitive, no
whitespace, no name fallback. If existing persistence already provides a
compatible immutable semantic key, reuse it and document its unique constraint;
otherwise PR 22 owns the migration. Never silently treat `name` as unique.

## 9. Stewardship

Stewardship is a separate structural designation, not a Role. A Tenant's first
steward is established atomically with activation:

- the steward Principal has an `ACTIVE` Tenant membership at TENANT scope;
- the steward has the approved Tenant Administrator Role assignment;
- the designated acting Identity belongs to the steward Principal, is active,
  and has a valid Tenant membership;
- the designation and the `ACTIVE` transition commit only when the invariant
  holds; a stewardless `ACTIVE` Tenant is forbidden.

`owner_identity_id` is immutable creator provenance and never confers
stewardship, Role, membership, or subscription. Privileged designation/transfer
remains installation/operator-only until the trusted invocation boundary
exists; it is never exposed through the shared runtime login or a
caller-supplied actor UUID.

## 10. Existing-Tenant join: session-Tenant isolation

The same verified user may be a member of multiple Tenants. Each session/request
is bound to exactly one verified Tenant; authorization state is never unioned
across Tenants, and resolving membership in Tenant A never yields membership or
Roles in Tenant B. An invitation acceptance is Tenant-specific and grants only
the invited Tenant's membership and approved Role.

## 11. Idempotency and concurrency

Idempotency identity is `(verified Application or operator identity, operation
kind, idempotency_key)` plus a durable canonical request fingerprint:

- same key / same fingerprint → same committed UUIDs and response, no second
  grant;
- same key / different fingerprint → `409`;
- new key / same semantic `tenant_key` → authorized resolution of the existing
  Tenant if immutable attributes match; otherwise a conflict;
- display name is never a deduplication key.

Durable uniqueness is required for `(provisioning authority, tenant_key)`,
`(issuer, subject)` active binding, the idempotency scope, exact membership
pairs, and invitation redemption. Races are serialized using existing locking
conventions; the loser receives a safe replay or a conflict, never a duplicate
identity. A successful MTMF commit followed by a lost HTTP response retries
idempotently and returns the same IDs.

## 12. Transaction, audit, and failure contracts

External identity verification and any remote IdP calls occur **before** the
UoW. Within one UoW: lock the relevant records, validate state, resolve effective
Roles and the exact Action, write through reviewed stored functions, append the
registered mutation audit, and commit. Any error rolls back all state and
audit. There is no fabricated mutation audit for an authorized no-op.

Audit fields: authenticated Application or approved operator, verified actor,
exact Action, target Tenant/Identity/Principal, outcome, server operation ID,
safe reason, timestamp, and immutable provenance. Never log a raw JWT, secret,
invitation capability, or unsafe external identity data. Reuse the PR 19C
provenance and audit seams; new mutation kinds require explicit registration.

Failure/reconciliation:

- a successful MTMF commit followed by a lost response → idempotent retry
  returns the same IDs;
- consumer-local persistence failure → the consumer reconciles through an
  authorized resolve; never create duplicate MTMF state;
- no distributed transaction is claimed between MTMF and a consumer's local
  store;
- an infrastructure/IdP failure is a typed failure with no writes, never a
  success or a reusable snapshot.

## 13. Security threats

| # | Threat | Expected rejection | Owner |
| --- | --- | --- | --- |
| T01 | Service token alone creates a Tenant | deny (no user/operator proof) | 22/24 |
| T02 | Caller-supplied Identity/Principal UUID treated as proof | deny before write | 23 |
| T03 | `owner_identity_id` used as steward/Role | deny | 22/23 |
| T04 | SYSTEM/root Tenant target or subscription | deny | 22/24 |
| T05 | Cross-client service/user token pair | reject | 24 |
| T06 | Conflicting external subject binding | fail closed; no rebind | 23 |
| T07 | Membership in A reused to authorize B | deny | 23/26 |
| T08 | Wrong recipient or no user token accepts an invitation | deny; no redemption | 25 |
| T09 | Invitation capability replay / double acceptance | exactly one grant | 25 |
| T10 | Unapproved or ROOT Role invitation | deny | 25 |
| T11 | Unauthorized Application enumerates Tenants by key/UUID | no lookup leak | 24 |
| T12 | Snapshot presented as a provisioning credential | deny | 24 |
| T13 | Idempotency key reuse with changed payload | `409`; no write | 22 |
| T14 | Partial commit (state without steward/audit) | full rollback | 22/23 |
| T15 | Secret/JWT/capability leaked to audit/logs | security test fails | 22–25 |

The full adversarial matrix `C01`–`C36` is
`../pr-artifacts/pr-21/PR21_SECURITY_MATRIX.md`.

## 14. Unresolved human decisions

1. **STOP-01** — operator-mediated v0.1 provisioning (Option A) or a
   commissioned pre-Tenant self-service admission (Option B). **Blocks DONE.**
2. Exact approved Action URNs and Role/Permission composition
   (`PR21_CONTRACT_REVIEW.md` §1).
3. Additive `404`/`409`/`410` error-catalog change ownership (PR 24/25).

Until resolved, implementations MUST choose the more restrictive behavior and
MUST NOT invent a design.

## 15. PR 22–26 allocation

| PR | Deliverable |
| --- | --- |
| 22 | Transactional Tenant provisioning and subscription foundation: `tenant_key`/idempotency persistence, authorized idempotent provisioning, stable resolution, SYSTEM/root exclusion, atomic audit, real-PostgreSQL retries/races/rollback |
| 23 | Global Identity/Principal resolution and reuse, Identity/Principal Tenant memberships, strict initial administrator/steward assignments, fail-closed conflicting bindings |
| 24 | Authenticated versioned onboarding management HTTP API: resolve, authorized Tenant metadata, subscription management, strict DTOs/error envelope, bounded handling |
| 25 | Invitations, acceptance, and official `mtmf-client` onboarding support: replay protection, expiry, revocation, atomic membership/Role establishment, authoritative UUID retrieval |
| 26 | Multi-Application onboarding conformance and v0.1 release gate: two independently authenticated Applications, global Identity/Principal reuse, per-Tenant isolation, COLD/REPEAT/RECREATE, concurrency/fault tests |

## References

- [Onboarding HTTP contract (PROPOSED)](ONBOARDING_HTTP_CONTRACT.md)
- `PR21_SECURITY_MATRIX.md` in `../pr-artifacts/pr-21/`
- `PR21_CONTRACT_REVIEW.md` in `../pr-artifacts/pr-21/`
- `PR21_STOP_REPORT.md` in `../pr-artifacts/pr-21/`
- [Security Model](SECURITY_MODEL.md), [Root and Stewardship](ROOT_AND_STEWARDSHIP.md),
  [HTTP Integration](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md), [Roadmap](ROADMAP_V01.md)
