# PR21_AMENDMENT01_CONTRACT_DIFF

**PR:** roadmap PR 21 — Amendment 01
**Status:** documentation-only. All new capabilities are **PROPOSED / NOT
IMPLEMENTED**.

## 1. Route/semantic diff

| Area | Pre-amendment PR 21 | Amendment 01 |
| --- | --- | --- |
| Tenant ownership | Implicitly could be read as Application-specific | **Explicit:** Tenant is application-independent; N:M Tenant↔Application subscriptions (D1) |
| First registration | `POST /v1/management/tenants` **DEFERRED**; operator-provisioning vs pre-Tenant admission unresolved (STOP-01) | `POST /v1/onboarding/resolve-or-provision` with typed outcomes; Option B direction approved (D2/D8) |
| New Identity creation | Not specified | Atomic Identity/Principal/Tenant/steward/initial registration+subscription, entitlement-gated (D3) |
| Existing Identity | No explicit reuse orchestration | `REUSED`/`SELECTION_REQUIRED`/`SUBSCRIPTION_REQUIRED`/`ONBOARDING_REQUIRED`; never auto-create a second Tenant (D4/D5) |
| Subscription approval | `POST .../subscriptions` sketch only | Independent approval; no silent subscription (D6) |
| Application management | None | `POST`/`GET`/`PATCH /v1/management/applications[...]` (D7) |
| Registration management | None | Registration create/inspect/revoke contracts (D7, STOP-04) |
| Subscription management | Create only, incomplete update | Create + bounded list/exact inspect + `PATCH` suspend/cancel with CAS (D7) |
| Lifecycle | Not mapped | Mapped verbatim from PR 13 source (see §2) |
| Error catalog | `404`/`409`/`410` proposed | Unchanged proposal; additive change owned by PR 24/25 |
| Authorization | Candidate URNs unapproved | Candidate URNs still unapproved; full actor×scope×audit matrix added |

## 2. Lifecycle semantics (source-grounded, unchanged)

The amendment does **not** change PR 13 transitions. It documents them:

| Aggregate | Permitted | Terminal | Notes |
| --- | --- | --- | --- |
| Application | `ACTIVE↔SUSPENDED`, `ACTIVE/SUSPENDED→RETIRED` | `RETIRED` | suspension lift allowed |
| Registration | `ACTIVE→REVOKED` | `REVOKED` | no in-place reactivation |
| Subscription | `PENDING→ACTIVE/CANCELLED`, `ACTIVE→SUSPENDED/CANCELLED/EXPIRED`, `SUSPENDED→ACTIVE/CANCELLED/EXPIRED` | `CANCELLED`, `EXPIRED` | suspension lift allowed; `ends_at` restrictive only |

Terminal rows are retained history; a replacement is a **new row with a new
UUID** (STOP-05 policy pending). No physical deletion. No terminal reactivation
claimed.

## 3. ResolveOrProvisionTenant outcome diff

| Outcome | Pre-amendment | Amendment 01 |
| --- | --- | --- |
| `CREATED` | not distinguished | new; new-Identity/new-Tenant only, entitlement-gated |
| `REUSED` | not distinguished | existing Identity + exactly one eligible Tenant |
| `SELECTION_REQUIRED` | not present | multiple eligible Tenants; authorized choices only |
| `SUBSCRIPTION_REQUIRED` | not present | membership exists but calling Application not subscribed |
| `ONBOARDING_REQUIRED` | not present | existing Identity, no usable/visible Tenant; no auto-create |
| deny / fail-closed | generic | missing entitlement, inactive/suspended Tenant, conflict, ambiguity |

## 4. PR 22–26 ownership

| Deliverable | Owner |
| --- | --- |
| `tenant_key`/idempotency persistence; atomic Tenant + initial registration/subscription; SYSTEM/root exclusion | PR 22 |
| Global Identity/Principal resolution+reuse; first steward membership/Role; pre-Tenant verified-subject seam; conflicting-binding fail-closed | PR 23 |
| `ResolveOrProvisionTenant`; Tenant resolve/selection; Application CRUD/lifecycle; registration; subscription create/list/suspend/cancel; exact authorization + audit | PR 24 |
| Invitations + pre-membership recipient acceptance (distinct from new-Tenant pre-Tenant admission) | PR 25 |
| Deployed two-Application/one-Tenant live E2E; adoption; selection; suspension/cancellation; races/retries; no duplicate Tenant; real audit; COLD/REPEAT/RECREATE | PR 26 |

## 5. Explicitly unchanged

- PR 13 internal models, guards, and operator-only mutation posture (PR 13 is
  the existing foundation; no history rewrite).
- `AuthenticatedActorContextService`, `EffectiveRoleResolver`, `Authorizer`,
  `MtmfSpi`/UnitOfWork, stored-function write boundary, and audit seams.
- Runtime privilege posture: `mtmf_runtime` gains no registry mutation grant.
- No physical deletion and no terminal reactivation.
