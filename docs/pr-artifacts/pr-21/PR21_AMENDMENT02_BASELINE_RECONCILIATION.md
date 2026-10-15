# PR21_AMENDMENT02_BASELINE_RECONCILIATION

**PR:** roadmap PR 21 — Amendment 02 (Final Security Policy Decisions)
**Type:** documentation-only amendment on the existing PR 21 branch
**Status:** PHASE 0 COMPLETE — repository reality recorded; no material divergence found.

## 1. Repository state

| Item | Value |
| --- | --- |
| Branch | `dev/onboarding-foundation` |
| `git status --short` | clean |
| `git rev-parse HEAD` | `b79d8aaa4597ca86aff97fdf0645e41ee6853b47` (matches the reported pre-amendment tip) |
| Base (merge-base with `origin/main`) | `455ae7a35d090b2546afa0c78fc9e4750ffee5ec` |
| Migration head | `0013_security_mutation_audit_partitioning` |
| Recent log | `b79d8aa` → `2ef3d9a` → `7393978` → `4bcffda` → `455ae7a` |
| Production changes | none |

## 2. Authoritative files inspected

- `AGENTS.md`, `docs/SECURITY_MODEL.md`, `docs/AUTHORIZATION.md`,
  `docs/ROOT_AND_STEWARDSHIP.md`, `docs/ROADMAP_V01.md`,
  `docs/ONBOARDING_ARCHITECTURE.md`, `docs/ONBOARDING_HTTP_CONTRACT.md`,
  `docs/HTTP_INTEGRATION_BATCH_AUTHORIZATION.md`, `docs/CLI_ARCHITECTURE.md`.
- All `docs/pr-artifacts/pr-21/PR21_AMENDMENT01_*.md` and the original PR 21
  baseline/acceptance/security/contract/STOP reports.
- PR 13 domain/persistence: `mtmf_core/domain/application.py`,
  `domain/eligibility.py`, `application/application_eligibility.py`,
  `persistence/repositories.py`, and `sql/v010/01..04`.
- PR 14: `domain/authentication_binding.py`, `sql/v011/01..04`,
  `application/authentication.py`.
- PR 19C: `application/mutation_provenance.py`, `sql/v012/01..06`.
- PR 10 seed: `sql/v006/01_builtin_seed_schema.sql`,
  `sql/v006/02_builtin_seed_function.sql`, `sql/v006/03_builtin_role_protection.sql`,
  `sql/v006/04_builtin_privilege_assertions.sql`.
- Action grammar/registry: `domain/iam_urn.py`, `domain/action.py`.
- Runtime privilege manifest: `persistence/postgres/roles.py`
  `expected_runtime_signatures()`.

## 3. Existing vs missing surfaces

| Surface | Status | Evidence |
| --- | --- | --- |
| Global `Application` (`ACTIVE/SUSPENDED/RETIRED`), unique normalized key | Implemented (PR 13) | `application.py`, `v010/01` |
| `ApplicationTenantRegistration` (`ACTIVE/REVOKED`) | Implemented (PR 13) | `application.py`, `v010/01` |
| `TenantApplicationSubscription` (`PENDING/ACTIVE/SUSPENDED/CANCELLED/EXPIRED`, `[starts_at, ends_at)`) | Implemented (PR 13 / 13-1) | `application.py`, schema check, guard functions |
| Registry mutation stored functions | Implemented, **operator/installation-only, never `mtmf_runtime`** | `v010/02`, `v010/03` |
| Registry runtime reads | 8 `SECURITY DEFINER` functions granted | `v010/03`; `roles.py` |
| Eligibility gate | Implemented, fail-closed, no `ALLOW` | `eligibility.py` |
| Service/credential bindings `(issuer, client_id)→Application`, `(issuer, subject)→Identity` | Implemented (PR 14 dev scope) | `authentication_binding.py`, `v011/01..03` |
| Credential binding mutations | Operator/installation-only (add/revoke); only `find_active` runtime-granted | `v011/03` |
| PR 19C exact membership-add Action + Permission + sole Tenant-Administrator grant | Implemented, human-approved | `v012/02_membership_add_policy.sql` |
| Application onboarding **entitlement** | **Missing** | no table/function/domain type |
| `ResolveOrProvisionTenant` use case/route | **Missing** | `app.py` routes are evaluate, identity-group-memberships, health |
| Application/registration/subscription management HTTP routes | **Missing** | `app.py`, `mtmf_api/management.py` |
| Onboarding Action URNs (Tenant provision, subscription/registration/invitation management) | **Missing / unapproved literals** | not in v006 or v012 seed |

## 4. Mutation privilege boundary (grounded)

- `mtmf_runtime` holds EXECUTE on exactly the reviewed allowlist from
  `expected_runtime_signatures()` (six membership-removal + 44 repository + 8
  Role-assignment + 9 TenantManagementGroup/root-registry reads + 8
  Application-registry reads + 2 authentication-binding reads + 2 PR 19C
  membership-add). No Application/registration/subscription mutation function
  is granted to runtime.
- The five registry mutation functions (`application_add`, `application_save`,
  `application_tenant_registration_add`, `application_tenant_registration_save`,
  `tenant_application_subscription_add`, `tenant_application_subscription_save`)
  are owner-owned `SECURITY INVOKER` with fixed empty `search_path` and no
  runtime grant.
- Credential-binding add/revoke are likewise not runtime-granted.
- New onboarding mutations must be added to the migration grants **and** the
  `expected_runtime_signatures()` manifest in the same reviewed migration, or
  they remain non-runtime.

## 5. Exact Action / Role seed facts (grounded)

- Action grammar: `urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>`;
  exact, no wildcard; only the `system` definition namespace is supported
  (`domain/iam_urn.py`). `BASELINE_ACTIONS` is explicitly not an exhaustive
  catalog (`domain/action.py`).
- Revision `0006` immutable seed: exactly 11 SYSTEM Roles, 11 ALLOW
  PermissionSets, 11 exact Permissions, 3 Actions (`tenant:get-object`,
  `role:get-object`, `organization:get-object`), 22 UUID literals.
- Revision `0012` adds exactly one Action/Permission:
  `urn:mtmf:iam:actions:system:identity-group-membership:add-object` →
  `urn:mtmf:iam:permissions:system:identity-group-membership:add-object`,
  granted to the sole built-in `urn:mtmf:iam:roles:system:tenant-administrator`.
- `mtmf.builtin_role` + the `role_save` guard protect the built-in definitions;
  a new built-in Role grant or a change to the `0006`/`0012` seed requires an
  additive, human-approved, fail-closed migration. None is proposed as approved
  by this amendment.

## 6. Discrepancies / notes

| # | Observation | Classification |
| --- | --- | --- |
| N01 | Amendment 01 proposed Action URNs are not in any seed and lack human approval | Expected; STOP-03 remains conditional-open |
| N02 | No `tenant_key` / idempotency persistence exists | Expected; PR 22 owns the migration |
| N03 | Application `SUSPENDED→ACTIVE` and subscription `SUSPENDED→ACTIVE` are legal in-place transitions | Grounded; documented, not terminal replacement |
| N04 | Terminal rows are retained history and do not block a later current row | Grounded; replacement = new UUID under policy P05 |
| N05 | Credential binding mutations are operator-only and not runtime-exposed | Grounded; P06 keeps separation |
| N06 | No material divergence from Amendment 01; D1–D8 unaffected | No STOP |

No prerequisite source file is missing and no binding invariant contradicts
P02–P06. Proceeding is safe.


---

## Amendment 03 closure note (2026-10-15)

The N01 row above (`STOP-03 remains conditional-open`) is the baseline state at
Amendment 02. STOP-03 was subsequently **CLOSED** by
`PR21-STOP03-APPROVAL-2026-10-15`; see
[`PR21_AMENDMENT03_HUMAN_APPROVAL.md`](PR21_AMENDMENT03_HUMAN_APPROVAL.md).
