# PR21_AMENDMENT02_ACTION_MANIFEST

**PR:** roadmap PR 21 — Amendment 02 (updated by the STOP-03 Authorization Approval Addendum)
**Status:** **APPROVED DESIGN — HUMAN DECISION RECORDED 2026-10-15. STOP-03
CLOSED.** The exact literals, Role composition, and admission-only treatment
below are approved as design. **NOT IMPLEMENTED**: no Action, Permission, Role,
seed, or grant is created. (Prior status before 2026-10-15 was `PROPOSED —
AWAITING HUMAN APPROVAL`; that history is retained.)

> Amendment 02 addendum (2026-10-15): rows 1–25 are preserved. Vague Role
> references are replaced with the exact proposed Role URNs and the **11/2/7**
> grant partition. Rows 2 and 19 are **admission-only Action identifiers with
> zero Role/Permission grants**. Row 11 reuses row 8; row 17 reuses row 12.
> Exact Role/authority design: `PR21_AMENDMENT02_STOP03_AUTHORIZATION_DECISION.md`;
> operator boundary: `PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`.

## 1. Grammar and URN validation (grounded)

Canonical grammar (`domain/iam_urn.py`): `urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>`.
- `system` is the **definition namespace** (the only supported one for
  Action/Permission URNs), **not** a license for SYSTEM-scope execution.
- Resource is one non-empty, whitespace-free, colon-free component (hyphens
  allowed); operation is `<verb>-<qualifier>` (first `-` splits).
- No wildcard in any component; Action URNs are exact.
- Permission URN mirrors the Action under `urn:mtmf:iam:permissions:`.
- SYSTEM Role URN: `urn:mtmf:iam:roles:system:<role-name>` (one name component).

Every literal below was validated against these rules. Grammar-validity is not
approval.

## 2. Proposed exact Role URNs

| Role | Exact URN | Proposed scope/authority |
| --- | --- | --- |
| Application Administrator | `urn:mtmf:iam:roles:system:application-administrator` | Application + registration + entitlement administration (SYSTEM definition namespace) |
| Application Credential Administrator | `urn:mtmf:iam:roles:system:application-credential-administrator` | Service-credential-binding administration only (SYSTEM definition namespace; PR 14 gate) |
| Tenant Administrator (existing) | `urn:mtmf:iam:roles:system:tenant-administrator` | Additive: own-Tenant subscription + invitation create/revoke, exact Tenant scope |

> **Reconciliation finding (grounded):** the `Role` domain object has no scope
> field; `SecurityScope` is `ROOT/SYSTEM/TENANT/ORGANIZATION`, and the current
> `Authorizer`/`AuthorizationContext` binds a session to exactly one Tenant and
> accepts a cross-Tenant target only through a positively resolved
> TenantManagementGroup `management_scope`. **There is no current mechanism to
> authorize a global, Tenant-independent Application resource as a SYSTEM-scoped
> operator.** Therefore the operator authorization and privileged execution for
> rows 3–11, 21–25 are **future gates** (PR 24 or a named prerequisite), not
> implemented authority. See `PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`.

## 3. Exact operation manifest (rows 1–25)

Status legend: **APPROVED** = already seeded and human-approved (reused
unchanged); **APPROVED DESIGN — ADMISSION-ONLY (zero grants)** = canonical
Action/audit identifier with zero Role/Permission grant; **APPROVED DESIGN** =
exact literal approved as design (not implemented); **ALIAS** = reuses an
existing approved add Action; **APPROVED DESIGN — IMPLEMENTATION GATED BY
PR 14** = approved design whose implementation awaits the PR 14 trust review.

| # | Operation | Literal Action URN | Resource | Target scope | Verified actor | Required Permission | Authorized Role / admission | PR | Status |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Tenant resolve/inspect | `urn:mtmf:iam:actions:system:tenant:get-object` | tenant | exact Tenant | verified user | `urn:mtmf:iam:permissions:system:tenant:get-object` | existing Tenant-scoped grants | 24 | APPROVED (do not reseed) |
| 2 | Initial Tenant provisioning | `urn:mtmf:iam:actions:system:tenant:provision-object` | tenant | new ordinary Tenant | pre-Tenant entitlement + verified new Identity | — (none) | ADMISSION-ONLY (entitlement; zero Role grant) | 22/23 | APPROVED DESIGN — ADMISSION-ONLY (zero grants) |
| 3 | Application create | `urn:mtmf:iam:actions:system:application:create-object` | application | global | system operator | `urn:mtmf:iam:permissions:system:application:create-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 4 | Application inspect | `urn:mtmf:iam:actions:system:application:get-object` | application | global | system operator | `urn:mtmf:iam:permissions:system:application:get-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 5 | Application suspend | `urn:mtmf:iam:actions:system:application:suspend-object` | application | global | system operator | `urn:mtmf:iam:permissions:system:application:suspend-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 6 | Application resume | `urn:mtmf:iam:actions:system:application:resume-object` | application | global | system operator | `urn:mtmf:iam:permissions:system:application:resume-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 7 | Application retire | `urn:mtmf:iam:actions:system:application:retire-object` | application | global | system operator | `urn:mtmf:iam:permissions:system:application:retire-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 8 | Registration create | `urn:mtmf:iam:actions:system:application-tenant-registration:add-object` | registration | exact Application+Tenant | system operator | `urn:mtmf:iam:permissions:system:application-tenant-registration:add-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 9 | Registration inspect | `urn:mtmf:iam:actions:system:application-tenant-registration:get-object` | registration | exact Application+Tenant | system operator | `urn:mtmf:iam:permissions:system:application-tenant-registration:get-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 10 | Registration revoke | `urn:mtmf:iam:actions:system:application-tenant-registration:revoke-object` | registration | exact Application+Tenant | system operator | `urn:mtmf:iam:permissions:system:application-tenant-registration:revoke-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 11 | Registration replacement | reuses row 8 `...:add-object` | registration | exact Application+Tenant | system operator | row 8 Permission | `application-administrator` | 24 | ALIAS (row 8) |
| 12 | Subscription create | `urn:mtmf:iam:actions:system:application-subscription:add-object` | subscription | exact Tenant | Tenant admin (exact scope) | `urn:mtmf:iam:permissions:system:application-subscription:add-object` | `tenant-administrator` | 24 | APPROVED DESIGN |
| 13 | Subscription inspect | `urn:mtmf:iam:actions:system:application-subscription:get-object` | subscription | exact Tenant | Tenant admin (exact scope) | `urn:mtmf:iam:permissions:system:application-subscription:get-object` | `tenant-administrator` | 24 | APPROVED DESIGN |
| 14 | Subscription suspend | `urn:mtmf:iam:actions:system:application-subscription:suspend-object` | subscription | exact Tenant | Tenant admin (exact scope) | `urn:mtmf:iam:permissions:system:application-subscription:suspend-object` | `tenant-administrator` | 24 | APPROVED DESIGN |
| 15 | Subscription resume | `urn:mtmf:iam:actions:system:application-subscription:resume-object` | subscription | exact Tenant | Tenant admin (exact scope) | `urn:mtmf:iam:permissions:system:application-subscription:resume-object` | `tenant-administrator` | 24 | APPROVED DESIGN |
| 16 | Subscription cancel | `urn:mtmf:iam:actions:system:application-subscription:cancel-object` | subscription | exact Tenant | Tenant admin (exact scope) | `urn:mtmf:iam:permissions:system:application-subscription:cancel-object` | `tenant-administrator` | 24 | APPROVED DESIGN |
| 17 | Subscription replacement | reuses row 12 `...:add-object` | subscription | exact Tenant | Tenant admin (exact scope) | row 12 Permission | `tenant-administrator` | 24 | ALIAS (row 12) |
| 18 | Invitation create | `urn:mtmf:iam:actions:system:tenant-invitation:create-object` | invitation | exact Tenant | Tenant admin (exact scope) | `urn:mtmf:iam:permissions:system:tenant-invitation:create-object` | `tenant-administrator` | 25 | APPROVED DESIGN |
| 19 | Invitation accept | `urn:mtmf:iam:actions:system:tenant-invitation:accept-object` | invitation | invited Tenant only | verified recipient + capability | — (none) | ADMISSION-ONLY (pre-membership seam; zero Role grant) | 25 | APPROVED DESIGN — ADMISSION-ONLY (zero grants) |
| 20 | Invitation revoke | `urn:mtmf:iam:actions:system:tenant-invitation:revoke-object` | invitation | exact Tenant | Tenant admin (exact scope) | `urn:mtmf:iam:permissions:system:tenant-invitation:revoke-object` | `tenant-administrator` | 25 | APPROVED DESIGN |
| 21 | Entitlement grant | `urn:mtmf:iam:actions:system:application-onboarding-entitlement:grant-object` | entitlement | exact Application | system operator | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:grant-object` | `application-administrator` | 22/23 | APPROVED DESIGN |
| 22 | Entitlement revoke | `urn:mtmf:iam:actions:system:application-onboarding-entitlement:revoke-object` | entitlement | exact Application | system operator | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:revoke-object` | `application-administrator` | 22/23 | APPROVED DESIGN |
| 23 | Entitlement inspect | `urn:mtmf:iam:actions:system:application-onboarding-entitlement:get-object` | entitlement | exact Application | system operator | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:get-object` | `application-administrator` | 24 | APPROVED DESIGN |
| 24 | Credential binding add | `urn:mtmf:iam:actions:system:service-credential-binding:add-object` | credential binding | exact Application | system credential admin | `urn:mtmf:iam:permissions:system:service-credential-binding:add-object` | `application-credential-administrator` (PR 14 gate) | 24 (gated) | APPROVED DESIGN — IMPLEMENTATION GATED BY PR 14 |
| 25 | Credential binding revoke | `urn:mtmf:iam:actions:system:service-credential-binding:revoke-object` | credential binding | exact Application | system credential admin | `urn:mtmf:iam:permissions:system:service-credential-binding:revoke-object` | `application-credential-administrator` (PR 14 gate) | 24 (gated) | APPROVED DESIGN — IMPLEMENTATION GATED BY PR 14 |

## 4. Exact Permission/Role mapping and counts

### 4.1 Application Administrator — `urn:mtmf:iam:roles:system:application-administrator`

| # | Exact Permission | Count |
|---|---|---|
| 1 | `urn:mtmf:iam:permissions:system:application:create-object` | |
| 2 | `urn:mtmf:iam:permissions:system:application:get-object` | |
| 3 | `urn:mtmf:iam:permissions:system:application:suspend-object` | |
| 4 | `urn:mtmf:iam:permissions:system:application:resume-object` | |
| 5 | `urn:mtmf:iam:permissions:system:application:retire-object` | 5 application |
| 6 | `urn:mtmf:iam:permissions:system:application-tenant-registration:add-object` | |
| 7 | `urn:mtmf:iam:permissions:system:application-tenant-registration:get-object` | |
| 8 | `urn:mtmf:iam:permissions:system:application-tenant-registration:revoke-object` | 3 registration |
| 9 | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:grant-object` | |
| 10 | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:revoke-object` | |
| 11 | `urn:mtmf:iam:permissions:system:application-onboarding-entitlement:get-object` | 3 entitlement |
| | **Total** | **11** |

No credential-binding, subscription, invitation, root, or wildcard Permission.

### 4.2 Application Credential Administrator — `urn:mtmf:iam:roles:system:application-credential-administrator`

| # | Exact Permission | Count |
|---|---|---|
| 1 | `urn:mtmf:iam:permissions:system:service-credential-binding:add-object` | |
| 2 | `urn:mtmf:iam:permissions:system:service-credential-binding:revoke-object` | 2 |
| | **Total** | **2** |

No Application create/retire, entitlement, registration, subscription,
invitation, root, or wildcard Permission.

### 4.3 Tenant Administrator additive — `urn:mtmf:iam:roles:system:tenant-administrator`

| # | Exact Permission (additive) | Count |
|---|---|---|
| 1 | `urn:mtmf:iam:permissions:system:application-subscription:add-object` | |
| 2 | `urn:mtmf:iam:permissions:system:application-subscription:get-object` | |
| 3 | `urn:mtmf:iam:permissions:system:application-subscription:suspend-object` | |
| 4 | `urn:mtmf:iam:permissions:system:application-subscription:resume-object` | |
| 5 | `urn:mtmf:iam:permissions:system:application-subscription:cancel-object` | 5 subscription |
| 6 | `urn:mtmf:iam:permissions:system:tenant-invitation:create-object` | |
| 7 | `urn:mtmf:iam:permissions:system:tenant-invitation:revoke-object` | 2 invitation |
| | **Total** | **7** |

All seven are enforced at the **exact same Tenant**. No registration,
entitlement, credential, root, or wildcard Permission. Existing `0006`/`0012`
seed history is not modified; a future additive migration preserves seed
immutability.

### 4.4 Totals and arithmetic

| Class | Count |
| --- | --- |
| Application Administrator permission-backed operations | 11 |
| Application Credential Administrator permission-backed operations | 2 |
| Tenant Administrator additive permission-backed operations | 7 |
| **Distinct new Permission-backed operations** | **20** |
| Admission-only Action identifiers (rows 2, 19; zero grants) | 2 |
| Existing approved Action reused (row 1) | 1 |
| Aliases (rows 11→8, 17→12) | 2 |
| **Manifest rows** | **25** |

This arithmetic reconciles with the manifest and with the addendum; no conflict
with verified source semantics was found.

## 5. Admission-only identifiers (rows 2 and 19)

`tenant:provision-object` and `tenant-invitation:accept-object` are canonical
**operation/audit identifiers** used by the specialized admission paths. They
carry **no Role grant and no ordinary Permission assignment**. If the Action
catalog requires an associated Permission row, it must be a **dormant exact
Permission with zero Role grants**; ordinary Role authorization is bypassed only
through the separately verified admission path. A broad grant to make a
pre-membership operation pass is forbidden (contract failure S17).

## 6. Existing approved URNs reused unchanged

| Literal | Seed | Grant |
| --- | --- | --- |
| `urn:mtmf:iam:actions:system:tenant:get-object` | `0006` | built-in Tenant-scoped Roles |
| `urn:mtmf:iam:actions:system:role:get-object` | `0006` | built-in Security Administrator Roles |
| `urn:mtmf:iam:actions:system:organization:get-object` | `0006` | built-in Organization Roles |
| `urn:mtmf:iam:actions:system:identity-group-membership:add-object` | `0012` | sole built-in `tenant-administrator` |

These are **APPROVED** and MUST NOT be re-litigated, mutated, or duplicated.

## 7. Human decisions (STOP-03) — APPROVED 2026-10-15

1. [x] Approved every literal in §3.
2. [x] Approved the two new SYSTEM Role definitions and the exact 11/2/7
   composition in §4.
3. [x] Approved the additive, idempotent, fail-closed seed migration plan that
   adds the Actions/Permissions/Role definitions/grants without mutating
   `0006`/`0012`.
4. [x] Approved the admission-only treatment of rows 2 and 19 (zero Role
   grants).
5. [x] Approved the operator boundary and the future Role-assignment/privileged
   execution gate as a **deferred implementation prerequisite, NOT IMPLEMENTED**
   (`PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`).

Provenance: [`PR21_AMENDMENT03_HUMAN_APPROVAL.md`](PR21_AMENDMENT03_HUMAN_APPROVAL.md)
(`PR21-STOP03-APPROVAL-2026-10-15`). **STOP-03 is CLOSED as design; PR 21
remains NOT IMPLEMENTED and PRs 22–26 own implementation.**
