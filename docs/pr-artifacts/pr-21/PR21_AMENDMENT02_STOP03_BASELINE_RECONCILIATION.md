# PR21_AMENDMENT02_STOP03_BASELINE_RECONCILIATION

**PR:** roadmap PR 21 — Amendment 02 STOP-03 Authorization Approval Addendum
**Type:** documentation-only addendum on the existing PR 21 branch
**Status:** PHASE 0 COMPLETE — branch reconciled, source facts recorded, one material gap identified (operator/global-target authorization is not implemented).

## 1. Branch and SHAs

| Item | Value |
| --- | --- |
| Branch | `dev/onboarding-foundation` |
| Working tree at start | clean |
| `git rev-parse HEAD` | `8c5937d4ea1a3fc5800a103f389abbe3d0daec0c` (matches the reported tip) |
| Base (merge-base with `origin/main`) | `455ae7a35d090b2546afa0c78fc9e4750ffee5ec` |
| Migration head | `0013_security_mutation_audit_partitioning` |
| Remote push | none performed (not authorized) |
| Production changes | none |

Fresh-`main` vs branch delta: only the PR 21 documentation chain
(`4bcffda`, `7393978`, `2ef3d9a`, `b79d8aa`, `98f9a62`, `8c5937d`) — all
Markdown under `docs/` plus `README.md`. No production file differs from `main`.

## 2. Verified source paths (searched, not guessed)

| Concern | Path |
| --- | --- |
| Action/Role/Permission URN grammar | `packages/mtmf-core/src/mtmf_core/domain/iam_urn.py` |
| Action catalog / baseline examples | `packages/mtmf-core/src/mtmf_core/domain/action.py` |
| Role domain (no scope field) | `packages/mtmf-core/src/mtmf_core/domain/role.py` |
| Security scope enum | `packages/mtmf-core/src/mtmf_core/domain/scope.py` |
| Authorization context / request | `packages/mtmf-core/src/mtmf_core/authorization/context.py` |
| Authorizer | `packages/mtmf-core/src/mtmf_core/authorization/authorizer.py` |
| Cross-Tenant delegation | `packages/mtmf-core/src/mtmf_core/application/management_authorization.py`, `authorization/management.py`, `authorization/guards.py` |
| Verified actor composition | `packages/mtmf-core/src/mtmf_core/application/authentication.py` |
| PR 13 registry schema/functions/grants | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v010/01..04` |
| PR 14 credential bindings | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v011/01..04` |
| PR 19C exact Action + seed | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v012/02_membership_add_policy.sql` |
| Built-in seed `0006` | `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v006/01..04` |
| Runtime signature allowlist | `packages/mtmf-core/src/mtmf_core/persistence/postgres/roles.py` `expected_runtime_signatures()` |
| HTTP routes | `packages/mtmf-service/src/mtmf_service/app.py` |
| API DTO/error catalog | `packages/mtmf-api/src/mtmf_api/{management,errors}.py` |

## 3. Current Action/Permission/Role seed facts

- Grammar: `urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>`; exact;
  `system`-only definition namespace; no wildcard (`iam_urn.py`).
- Revision `0006` immutable built-in seed: 11 SYSTEM Roles, 11 ALLOW
  PermissionSets, 11 exact Permissions, 3 Actions (`tenant:get-object`,
  `role:get-object`, `organization:get-object`), 22 UUID literals.
- Revision `0012`: adds exactly `identity-group-membership:add-object`
  Action+Permission, granted to the sole built-in `tenant-administrator`.
- `builtin_role` + `role_save` guard protect built-in definitions; additions must
  be additive/versioned/idempotent/fail-closed.
- `BASELINE_ACTIONS` is not exhaustive; the proposed onboarding URNs are absent
  from every seed and from the runtime allowlist.

## 4. Operator/authentication and DB privilege boundaries

- The only ordinary actor composition is `AuthenticatedActorContextService.resolve`
  (verified service token + verified user token + existing eligible Tenant +
  memberships). It cannot authenticate a first user or an operator.
- No operator sign-in / canonical operator principal resolution exists.
- `Role` has no scope field; `SecurityScope` is `ROOT/SYSTEM/TENANT/ORGANIZATION`.
  `AuthorizationContext` binds a session to one Tenant; `AuthorizationRequest`
  accepts a cross-Tenant target only through a positively resolved
  TenantManagementGroup `management_scope`. **A global, Tenant-independent
  Application target as a SYSTEM-scoped operator is not representable.**
- Role assignments are Tenant-bound (`IdentityRoleAssignment` /
  `GroupRoleAssignment`); there is no global/system operator assignment
  mechanism.
- PR 13/14 privileged mutations are owner-owned `SECURITY INVOKER`,
  operator/installation-only, and **not** granted to `mtmf_runtime`. Only
  narrowly reviewed `SECURITY DEFINER` reads are runtime-granted.

## 5. Test harness

- Canonical gates: `./build.sh --qa`, `--sec`, `--rust`, `--integration`.
- Real-PostgreSQL restricted-runtime suites under `tests/integration/postgres`.
- No test fixture or endpoint exists for global Application management or a
  system operator; such feature tests are NOT RUN and belong to PR 24/26.

## 6. Evidence classification

| Item | State |
| --- | --- |
| PR 13 registry persistence + eligibility | DONE+VERIFIED |
| PR 14 credential binding persistence | DONE+VERIFIED (development scope) |
| PR 19C membership-add audited mutation | DONE+VERIFIED |
| Two-token actor composition (existing Tenant) | DONE+VERIFIED |
| Global Application management HTTP surface | NOT STARTED |
| Operator sign-in / SYSTEM Role assignment / global-target authorization | NOT STARTED |
| Onboarding entitlement persistence | NOT STARTED |
| Proposed onboarding Actions/Permissions/Roles | PROPOSED — AWAITING HUMAN APPROVAL (STOP-03 OPEN) |

## 7. Deviations / notes

- **N01 (material):** the proposed SYSTEM-scoped Application Administrator /
  Credential Administrator authority for global resources cannot be evaluated by
  the current Authorizer; documented as a future gate
  (`PR21_AMENDMENT02_STOP03_OPERATOR_BOUNDARY.md`), not as existing capability.
- **N02:** the proposed Role URNs are grammar-valid and do not collide with any
  seeded Role.
- **N03:** no proposed Action URN collides with an existing canonical URN.
- **N04:** the 11/2/7 partition reconciles with the manifest arithmetic
  (20 permission-backed + 2 admission-only + 1 existing + 2 aliases = 25).

No blocking conflict with an existing canonical URN, Role namespace, or trust
invariant was found. Proceeding is safe.


---

## Amendment 03 closure note (2026-10-15)

The `PROPOSED — AWAITING HUMAN APPROVAL (STOP-03 OPEN)` baseline-status row
above is historical. STOP-03 was subsequently **CLOSED** by
`PR21-STOP03-APPROVAL-2026-10-15`; see
[`PR21_AMENDMENT03_HUMAN_APPROVAL.md`](PR21_AMENDMENT03_HUMAN_APPROVAL.md).
