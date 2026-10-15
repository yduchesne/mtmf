# PR21_STOP_REPORT

**PR:** roadmap PR 21 — Application-neutral onboarding architecture and API contracts
**Status:** **STOP-01 OPEN — HUMAN DECISION REQUIRED BEFORE PR 21 CAN BE MARKED DONE.**
**Effect:** PR 21 may deliver the draft architecture and contracts, but must not
be marked DONE, and must not claim an approved admission model, until the
decision below is recorded.

## STOP-01 — Trusted authority for creating the first Tenant and its first user

### Exact location of the conflict

- **Roadmap objective:** `docs/ROADMAP_V01.md` §"v0.1 onboarding release
  requirement" requires that *"MTMF must let an authorized consuming
  Application securely onboard a new ordinary Tenant and its initial verified
  user"*.
- **Current implementation:** `AuthenticatedActorContextService.resolve`
  (`packages/mtmf-core/src/mtmf_core/application/authentication.py`) requires,
  before it can return a `VerifiedActorContext`:
  1. an existing ordinary ACTIVE Tenant;
  2. an existing `PrincipalTenantMembership` and `IdentityTenantMembership`
     for the verified `(issuer, subject)`;
  3. an eligible Application/Tenant registration and subscription;
  4. equality between the caller-selected `tenant_id` and the persisted
     verified Tenant.
- **Privileged primitives:** the only Tenant-creating primitives are the
  installation/operator-only, never-`mtmf_runtime`-granted functions from
  revision `0008` (`bootstrap_root`, `designate_steward`, `activate_tenant`).
  The existing privileged development initializer is not a production
  onboarding interface.

### Actual behavior

There is **no** production authenticated-and-authorized entry point that can
create an ordinary Tenant and its first verified user, because every such
entry point requires the very Tenant membership it would be creating. Any
attempt to expose Tenant creation through the ordinary two-token actor path
would be circular. A service access token alone authenticates an Application,
**not** a user, an operator, or a permission, and must never create Tenants.

### Violated invariant if unresolved

- `SECURITY_MODEL.md` §5 (root/bootstrap does not confer ordinary Tenant
  creation authority) and §25 (eligibility is a prerequisite, never a grant).
- `ROOT_AND_STEWARDSHIP.md` ("Creating an active ordinary Tenant and
  designating its first eligible steward must be atomic").
- `AGENTS.md` and `AUTHORIZATION.md`: default DENY; trusted actor context must
  precede writes; a caller-supplied UUID is never authentication.

### Smallest required reviewer decision

Choose exactly one:

- **Option A — operator-mediated v0.1 provisioning.** New-Tenant creation is
  performed by a separately authenticated, approved **operator provisioning
  authority** outside the ordinary actor path (the design frozen in
  `docs/ONBOARDING_ARCHITECTURE.md` §4). This **amends** the roadmap's
  "authorized consuming Application onboards a new Tenant" objective for v0.1.
- **Option B — pre-Tenant self-service admission.** Commission an explicitly
  designed, least-privilege **pre-Tenant** admission path for an authorized
  Application, with abuse/rate/quota controls and an operator-delegation
  model, reviewed as a new design before implementation.

Neither option may be assumed. **PR 21 does not claim option A is approved and
does not invent option B.**

### Impact on PRs 22–26

| PR | Impact if STOP-01 remains open |
| --- | --- |
| 22 | Tenant-provisioning authority/trust boundary cannot be finalized; migration for `tenant_key`/idempotency may still be drafted but not implemented |
| 23 | First-steward Identity/Principal creation authority is undefined |
| 24 | `POST /v1/management/tenants` remains `DEFERRED`; no self-service route may be exposed |
| 25 | Invitation acceptance depends on the same pre-Tenant/pre-membership seam class |
| 26 | The deployed two-Application onboarding acceptance cannot be claimed complete |

### Safe partial deliverables produced by PR 21

- `docs/ONBOARDING_ARCHITECTURE.md` (draft, status explicitly *proposed*).
- `docs/ONBOARDING_HTTP_CONTRACT.md` (PROPOSED / NOT IMPLEMENTED).
- `docs/pr-artifacts/pr-21/PR21_SECURITY_MATRIX.md` (C01–C36).
- `docs/pr-artifacts/pr-21/PR21_CONTRACT_REVIEW.md`.
- `docs/pr-artifacts/pr-21/PR21_BASELINE_RECONCILIATION.md`.
- `docs/pr-artifacts/pr-21/PR21_ACCEPTANCE_REPORT.md`.

### Resolution

_No resolution recorded. This STOP remains open until a human reviewer records
the chosen option and the corresponding authoritative documentation change._
