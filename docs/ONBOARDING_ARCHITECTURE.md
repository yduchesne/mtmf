# Application-Neutral Onboarding Architecture

> **STATUS: PROPOSED DESIGN — DOCUMENTATION ONLY. NOT IMPLEMENTED.**
> This document freezes the v0.1 onboarding security design, state machines,
> admission rules, and future versioned management contracts so that roadmap
> PRs 22–26 implement a reviewed design rather than invent one. It does **not**
> describe shipped behavior. Every future API is **PROPOSED / NOT IMPLEMENTED**.
> No production readiness is claimed.
>
> **Amendment 01 (2026-10-15): STOP-01 CLOSED — Option B direction approved.**
> A Tenant is application-independent (D1); onboarding uses a single
> `ResolveOrProvisionTenant` orchestration (D2) with automatic initial creation
> only for a truly new global Identity (D3), reuse over duplication (D4),
> explicit multi-Tenant selection (D5), independent subscription approval (D6),
> planned Application/registration/subscription management (D7), and a narrowly
> scoped pre-Tenant Application-initiated admission (D8, Option B). See §17 and
> `pr-artifacts/pr-21/PR21_AMENDMENT01_DECISION_RECORD.md`. **Narrower
> STOP-02…STOP-06 remain open** (`pr-artifacts/pr-21/PR21_AMENDMENT01_STOP_REPORT.md`),
> so PR 21 is still not DONE.
>
> The original STOP-01 record (Option A vs B) is preserved in
> [`pr-artifacts/pr-21/PR21_STOP_REPORT.md`](pr-artifacts/pr-21/PR21_STOP_REPORT.md).
> Until the narrower STOPs are resolved, this design is a draft and PR 21 is
> not DONE.
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

## 4. Ownership and trust flow

The trusted path from an external identity to a consumer's local reference is:

```text
external IdP → verified service/user proof (outside transaction)
             → approved operator OR eligible ordinary actor admission
             → MTMF application use case → EffectiveRoleResolver / Authorizer
             → one UnitOfWork → typed repositories → versioned PostgreSQL functions
             → atomic state + audit → detached authoritative UUID response
             → HTTP mtmf-client → consuming application's local references/PEP
```

MTMF owns verified actor/application/Tenant context, authorization, security
state, and authoritative UUIDs. The consuming Application owns its own user
authentication flow, its local reference projections, and resource/data
enforcement. The admission branch is Option B (pre-Tenant Application-initiated
admission) for first registration and the ordinary already-member actor branch
for everything else; see §17.2–§17.3.

## 5. New-Tenant admission

### 5.1 The circular-authentication problem

`AuthenticatedActorContextService.resolve` requires an already existing
ordinary ACTIVE Tenant, the verified user's persisted Identity/Principal
memberships, an eligible Application/Tenant registration and subscription, and
equality between the requested and verified Tenant. It therefore **cannot**
authenticate the first user of a Tenant that does not yet exist. A service
access token alone must never create a Tenant.

### 5.2 Approved admission model (Option B — D8)

**STOP-01 is closed: v0.1 uses a narrowly scoped pre-Tenant Application-initiated
admission (Option B)**, not operator-only provisioning and not ordinary actor
resolution for an unknown Tenant. The trusted `ResolveOrProvisionTenant`
operation independently verifies the Application service token and the user
proof, then resolves the global Identity and the Tenant-context outcome. The
existing privileged development initializer is **not** a production onboarding
interface. The detailed entitlement/authority model is still unapproved
(STOP-02…STOP-04); see §17 and
`pr-artifacts/pr-21/PR21_AMENDMENT01_STOP_REPORT.md`.

### 5.3 Trusted provisioning sequence (Option B)

External identity verification and any remote IdP call occur **outside** the
UoW. Then, in one serialized transaction:

```text
verify Application service token + user proof + onboarding entitlement OUTSIDE UoW
    → begin serialized UoW
    → resolve/reuse global Identity and Principal by verified binding
    → (new Identity + no eligible Tenant) create ordinary PROVISIONING Tenant
       (unique provisioning authority + tenant_key)
    → establish Principal+Identity Tenant memberships
    → establish approved Tenant Administrator Role and stewardship
    → establish the explicitly authorized INITIAL Application registration + subscription
    → verify activation invariant, activate Tenant
    → persist exact mutation provenance and audit atomically
    → commit → return authoritative IDs
```

The full decision table (reuse/selection/subscription-required/deny) is §17.2.
The initial registration/subscription is the only subscription exception in the
pre-Tenant branch; adding another Application to an existing Tenant always
requires independent authorization (D6).

If the operator authority cannot be established without a bypass, the
implementation MUST STOP; it MUST NOT call the ordinary actor path and pretend
the recipient is already a member, and MUST NOT use the development initializer
or root impersonation.

## 6. Existing-Tenant invitation

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

## 7. Application subscription

Application **registration** and Tenant **subscription** are distinct.
Creating a Tenant does **not** automatically subscribe the creating Application
in general. A new subscription for an existing Tenant requires an independently
authorized operator or existing eligible Tenant management authority. Existing
subscription eligibility cannot bootstrap its own creation.

**Amendment 01 exception:** the one exception is the explicitly authorized
**initial** Application registration/subscription committed atomically with a
first-Tenant pre-Tenant admission for a truly new global Identity (§17.3, D3).
It is not automatic: it is gated by the Application onboarding entitlement. It
does not apply to adding another Application to an existing Tenant (D6), which
still requires independent authorization (STOP-04).

Reject inactive Tenant/Application, SYSTEM/root, unauthorized Application ID,
and cross-Tenant requests. Never accept caller-supplied authorization
decisions. The existing `ApplicationTenantEligibilityService` remains the
authoritative eligibility gate; a subscription is eligibility, never a
Permission.

## 8. Global Identity reuse

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

## 9. Tenant lifecycle

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

## 10. Stewardship

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

## 11. Existing-Tenant join: session-Tenant isolation

The same verified user may be a member of multiple Tenants. Each session/request
is bound to exactly one verified Tenant; authorization state is never unioned
across Tenants, and resolving membership in Tenant A never yields membership or
Roles in Tenant B. An invitation acceptance is Tenant-specific and grants only
the invited Tenant's membership and approved Role.

## 12. Idempotency and concurrency

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

## 13. Transaction, audit, and failure contracts

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

## 14. Security threats

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

The full adversarial matrix `C01`–`C36` and Amendment 01 `A01`–`A24` are in
`pr-artifacts/pr-21/PR21_SECURITY_MATRIX.md` and
`pr-artifacts/pr-21/PR21_AMENDMENT01_SECURITY_CASES.md`.

## 15. Unresolved human decisions

**STOP-01 is closed** (Amendment 01, D8 — Option B direction approved; see
§17). The narrower decisions below remain open and **block marking PR 21 DONE**:

1. **STOP-02** — pre-Tenant onboarding-entitlement issuer/grant/revoke model and
   authoritative state. See `pr-artifacts/pr-21/PR21_AMENDMENT01_STOP_REPORT.md`.
2. **STOP-03** — exact onboarding Action URNs and built-in Role/Permission
   composition (`pr-artifacts/pr-21/PR21_CONTRACT_REVIEW.md` §1).
3. **STOP-04** — authority for the initial/subsequent Application–Tenant
   registration (PR 13 registration mutation is operator-only).
4. **STOP-05** — terminal re-subscription / re-registration replacement policy.
5. **STOP-06** — Application service-credential binding management boundary.

Until resolved, implementations MUST choose the more restrictive behavior and
MUST NOT invent a design.

## 16. PR 22–26 allocation

| PR | Deliverable |
| --- | --- |
| 22 | Transactional Tenant provisioning and subscription foundation: `tenant_key`/idempotency persistence, authorized idempotent provisioning, stable resolution, SYSTEM/root exclusion, atomic initial registration/subscription, atomic audit, real-PostgreSQL retries/races/rollback |
| 23 | Verified global Identity/Principal resolution and reuse, Identity/Principal Tenant memberships, strict initial administrator/steward assignments, fail-closed conflicting bindings, the pre-Tenant verified-subject seam |
| 24 | Authenticated versioned onboarding management HTTP API: `ResolveOrProvisionTenant`, Tenant resolution/selection, Application create/inspect/suspend/retire, Application–Tenant registration, subscription create/inspect/list/suspend/cancel, strict DTOs/error envelope |
| 25 | Invitations, acceptance, and official `mtmf-client` onboarding support: replay protection, expiry, revocation, atomic membership/Role establishment, authoritative UUID retrieval |
| 26 | Multi-Application onboarding conformance and v0.1 release gate: **two independently authenticated Applications sharing one Tenant**, one new Identity creation, second-Application adoption with authorized subscription, repeated login, multi-Tenant selection, suspension/cancellation, cross-Tenant/cross-Application denial, races/retries, no duplicate Tenant, real audit, COLD/REPEAT/RECREATE |

If PR 24 proves too large, the implementation plan MUST name a specific
prerequisite PR with dependencies and acceptance; no undocumented expansion.

## 17. Amendment 01 — application-neutral Tenant resolution and management lifecycle

This section is normative for PRs 22–26 and is grounded in the actual PR 13
transition sets (see `pr-artifacts/pr-21/PR21_AMENDMENT01_BASELINE_RECONCILIATION.md`).

### 17.1 Tenant, Identity, and Application cardinality

- A global external `(issuer, subject)` binding maps to a stable global Identity;
  the Identity belongs to one global Principal. Reuse the Identity/Principal
  across consuming Applications and Tenant memberships. Never correlate accounts
  by email alone.
- Principal/Identity ↔ Tenant membership is **distinct** from Application ↔
  Tenant registration and subscription, and both are distinct from Role/
  Permission assignments.
- A Tenant has 0..N Application subscriptions; an Application has 0..N Tenant
  subscriptions. The protected SYSTEM/root Tenant is excluded from ordinary
  onboarding and subscriptions.
- An Application subscription grants **no** membership and **no** Role/
  Permission. Existing membership does not imply subscription, and does not
  authorize creating one.
- Application registration is global and independent of Tenant creation.
- Tenant owner/creator provenance and stewardship are **not** inferred from the
  Application that initiated onboarding.

### 17.2 ResolveOrProvisionTenant decision table (normative)

`ResolveOrProvisionTenant` verifies the Application service token and the user
proof, then resolves the global Identity and returns one of the outcomes below.
It is the single registration-facing orchestration (D2).

| Verified global identity | Existing Tenant context | Calling Application eligibility | Required outcome |
|---|---|---|---|
| Absent | None | Explicitly entitled for first-Tenant onboarding | `CREATED`: atomically provision Identity, Principal, Tenant, steward/memberships, and the initial approved registration/subscription; return stable IDs |
| Absent | None | Not entitled | deny; create nothing |
| Present | Exactly one visible active Tenant with active registration+subscription | Eligible | `REUSED`: return stable IDs; no mutation |
| Present | Multiple visible eligible Tenants | Eligible for each | `SELECTION_REQUIRED`: authorized Tenant choices only; no mutation |
| Present | Tenant membership but Application lacks active registration/subscription | Ineligible | `SUBSCRIPTION_REQUIRED`: no automatic subscription, no second Tenant; disclose only what the user is authorized to know |
| Present | No usable/visible Tenant | Any | `ONBOARDING_REQUIRED` (or explicit non-enumerating denial); **no automatic Tenant creation** |
| Present | Suspended/inactive Tenant | Any | fail closed / explicit status as visibility permits; no replacement Tenant |
| Present | Conflicting binding, ambiguity, partial/corrupt state | Any | fail closed; no auto-repair |

Additional rules:

- A user new to an Application may already be an existing MTMF Identity; never
  create based on absence of Application-local state or an Application
  subscription.
- An Identity with an existing Tenant but **no** subscription for the calling
  Application is `SUBSCRIPTION_REQUIRED`, **not** `REUSED`.
- Multiple Tenant memberships may have different subscription states; the
  returned choices are only those the verified user is authorized to know and
  the Application is eligible for, without leaking inaccessible Tenant names or
  IDs.
- `SELECTION_REQUIRED` is completed by a follow-up authorized request bound to a
  selected Tenant; the same orchestration may safely return a read-only outcome
  without creating anything.

### 17.3 Pre-Tenant trust boundary and admission (Option B)

- Independently authenticate the Application service token and verify the user
  proof against the approved issuer, audience/client binding, subject, expiry,
  and other required claims. Derive identities from verified tokens, never from
  caller-provided UUID/email. Preserve the existing cross-client verification
  constraint unless an explicitly reviewed alternative is required.
- **Pre-Tenant onboarding entitlement** is a separately configured,
  least-privilege authority bound to the authenticated Application. It is not
  implied by client credentials, normal subscription eligibility, the Tenant
  Administrator Role, or root impersonation. **STOP-02** proposes an
  operator-managed, versioned Application entitlement record (`ACTIVE`/`REVOKED`,
  immutable grant provenance) evaluated only in the pre-Tenant branch; the exact
  model and grant/revoke authority require human approval.
- Abuse controls: per-Application and per-verified-subject rate/quota limits,
  duplicate throttling, bounded payloads, idempotency, atomic audit, and
  rejection telemetry. Rate limits do **not** solve Sybil/identity-abuse risk;
  the entitlement remains the primary control.
- The narrow pre-Tenant branch is the **only** place that does not require an
  existing Tenant membership/subscription. Ordinary existing-Tenant mutations
  continue through the verified actor + exact Action/scope authorization path.
  There is no implicit global bypass.
- The initial Application–Tenant registration/subscription must be included in
  the approved first-Tenant admission transaction; otherwise the Tenant is
  unusable to the caller. This exception applies only to the **initial**
  Application during **new Identity + new Tenant** provisioning, never to adding
  another Application to an existing Tenant (D6/STOP-04).
- The transaction boundary, serialization/idempotency keys, uniqueness, rollback,
  and atomic mutation audit follow §12–§13. No network call occurs inside the
  UoW; no cross-IdP/DB atomicity is claimed.

### 17.4 Existing-Tenant Application adoption

When a second Application (for example, ATI following Digr) onboards the same
verified user:

- the same global Identity/Principal and the same Tenant are reused;
- if the second Application has no `ACTIVE` registration/subscription for that
  Tenant, the outcome is `SUBSCRIPTION_REQUIRED`; the user's existing membership
  does not authorize the new subscription;
- an explicitly authorized Tenant administrator (or a separately authorized
  operator) requests the second Application's registration/subscription through
  the management API (STOP-04 defines registration authority);
- eligibility is re-evaluated only after the committed state;
- an ordinary user cannot cause the subscription merely by signing in.

Billing/subscription commerce is out of scope; MTMF subscription is an
eligibility fact, not a billing record.

### 17.5 Lifecycle and deletion policy

The actual PR 13 transitions are: Application `ACTIVE↔SUSPENDED` and
`ACTIVE/SUSPENDED→RETIRED` (`RETIRED` terminal); registration `ACTIVE→REVOKED`
(`REVOKED` terminal); subscription `PENDING→ACTIVE/CANCELLED`,
`ACTIVE→SUSPENDED/CANCELLED/EXPIRED`, `SUSPENDED→ACTIVE/CANCELLED/EXPIRED`
(`CANCELLED`/`EXPIRED` terminal).

- Suspending an Application makes it ineligible; retiring it is terminal.
- Suspending a subscription makes it ineligible; cancelling/expiring is terminal.
- Suspension may be lifted (`SUSPENDED → ACTIVE`) for both Application and
  subscription; terminal states are immutable and are **never** reactivated
  in place.
- Physical hard-delete is out of scope for v0.1. Terminal rows are retained as
  history. A replacement subscription/re-registration is a **new row with a new
  UUID**; whether/when replacement is allowed is **STOP-05** (not yet approved,
  not implemented).
- Registration `REVOKED` and subscription `CANCELLED` are distinct facts.
- Eligibility changes become effective for the next evaluation; already-issued
  active authorization snapshots are not retroactively invalidated (§12).

## References

- [Onboarding HTTP contract (PROPOSED)](ONBOARDING_HTTP_CONTRACT.md)
- `pr-artifacts/pr-21/PR21_SECURITY_MATRIX.md`, `PR21_CONTRACT_REVIEW.md`,
  `PR21_STOP_REPORT.md`
- `pr-artifacts/pr-21/PR21_AMENDMENT01_DECISION_RECORD.md`,
  `PR21_AMENDMENT01_STOP_REPORT.md`,
  `PR21_AMENDMENT01_AUTHORIZATION_MATRIX.md`,
  `PR21_AMENDMENT01_BASELINE_RECONCILIATION.md`
- [Security Model](SECURITY_MODEL.md), [Root and Stewardship](ROOT_AND_STEWARDSHIP.md),
  [HTTP Integration](HTTP_INTEGRATION_BATCH_AUTHORIZATION.md), [Roadmap](ROADMAP_V01.md)
