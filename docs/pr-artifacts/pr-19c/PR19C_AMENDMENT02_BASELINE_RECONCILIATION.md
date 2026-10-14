# PR19C_AMENDMENT02_BASELINE_RECONCILIATION

**PR:** roadmap PR 19C.
**Date:** 2026-10-14.
**Base (origin/main):** `0f6d3fe2b8d35dd208afa5337be2b26e7e8a03db`.
**Implementation HEAD before this amendment:** `1fcb0aad873f059e00fbdbf90965f75860199650` (`1fcb0aa`).
**Branch:** `dev/mgmt-mutation`; clean tree at Phase 0; migration head `0012_security_mutation_audit`.
**Method:** inspected own branch source, ran the existing tests, and classified every original H/U/CC/DB case. No prior claim was accepted without source or execution evidence.

## 1. Reported-state reconciliation

| Reported (Amendment 02 §2) | Verified | Evidence |
| --- | --- | --- |
| Migration `0012_security_mutation_audit` | DONE + VERIFIED | `migrations/versions/0012_security_mutation_audit.py`, `sql/v012/*` |
| `ManagementMembershipService` | DONE + VERIFIED | `application/management_memberships.py` |
| Verified repository/SPI methods | DONE + VERIFIED | `lock_verified_add`/`add_verified` in `repositories.py`, Postgres + in-memory |
| Exact Action/Permission/sole Role grant | DONE + VERIFIED | `sql/v012/02_membership_add_policy.sql`, built-in policy test |
| Six-probe lock proof | DONE + VERIFIED | `PR19C_CONCURRENCY_PROOF.md` |
| Legacy runtime grant removal | DONE + VERIFIED | v012 grants + `test_runtime_privileges.py` |
| No HTTP route/DTO/composition | **superseded by this amendment** | new files below |
| No live dual-token acceptance | **still true → BLOCKED** | `PR19C_AMENDMENT02_LIVE_ACCEPTANCE.md` |

## 2. `ManagementMembershipService` actual signature (as built)

`ManagementMembershipService.add_identity_to_group(*, service_token, user_token, tenant_id, identity_id, group_id) -> ManagementMembershipResult`. It resolves both tokens itself via the injected `AuthenticatedActorContextService`, opens one UoW, calls `lock_verified_add`, resolves effective Roles, calls the authoritative `Authorizer`, builds and registers `VerifiedMutationProvenance`, calls `add_verified`, commits once, and returns `ManagementMembershipResult(tenant_id, identity_id, group_id, created, operation_id)`. The HTTP adapter therefore invokes it **once** and never authenticates twice (Amendment 02 Step B).

## 3. Case matrix (actual execution on final HEAD)

| Original case | Status | Evidence |
| --- | --- | --- |
| U01–U08 (original plan) | PARTIAL | covered by `test_api_management_dtos.py`, `test_management_http.py`, `test_mutation_provenance.py` |
| U-H01 canonical round trip | DONE + VERIFIED | `test_uh01_*` |
| U-H02 extra/missing/duplicate keys | DONE + VERIFIED | `test_uh02_*` |
| U-H03 wrong/noncanonical/zero UUID, malformed | DONE + VERIFIED | `test_uh03_*`, `test_uh02_uh03_invalid_body_*` |
| U-H04 oversized body | DONE + VERIFIED | `test_uh04_oversized_body_is_413_without_invocation` |
| U-H05 media type | DONE + VERIFIED | `test_uh05_wrong_content_type_is_415` |
| U-H06 201/200 | DONE + VERIFIED | `test_uh01_uh06_*`, `test_uh06_*` |
| U-H07 policy deny → FORBIDDEN | DONE + VERIFIED | `test_uh07_*` |
| U-H08 token failures | DONE + VERIFIED | `test_uh08_*` |
| U-H09 DB outage | DONE + VERIFIED | `test_uh09_*` |
| U-H10 single terminal management event | DONE + VERIFIED | `test_uh10_*` |
| U-H11 admission exhaustion | DONE + VERIFIED | `test_uh11_*` |
| U-H12 timeout permit retention | DONE + VERIFIED | `test_uh12_*` |
| DB-H01 new membership + audit | DONE + VERIFIED | `test_i01_*` |
| DB-H02 duplicate no audit | DONE + VERIFIED | `test_i02_*` |
| DB-H03 denied/non-steward/cross-Tenant/inactive | DONE + VERIFIED | `test_db_h03_*` |
| DB-H04 audit failure rollback | DONE + VERIFIED | `test_db_h04_audit_conflict_rolls_back_the_membership` |
| DB-H05 privilege manifest | DONE + VERIFIED | `test_runtime_privileges.py`, v012 assertions |
| CC-H01 revocation race | DONE + VERIFIED (proof) | `PR19C_CONCURRENCY_PROOF.md` E1/E2 |
| CC-H02 steward change race | DONE + VERIFIED (proof) | E3 |
| CC-H03 suspension/Role change race | DONE + VERIFIED (proof) | E4/E5 |
| CC-H04 concurrent duplicate adds | DONE + VERIFIED | `test_cc_h04_concurrent_duplicate_adds_commit_one_row_and_one_audit` |
| H01–H05 live Keycloak | **BLOCKED** | `PR19C_AMENDMENT02_LIVE_ACCEPTANCE.md` |

## 4. Defect found and fixed during this amendment

The Amendment 01 v012 lock/verify functions reused SQLSTATEs `MT040`–`MT043`, which are **already reserved by the PR 13 Application-registry integrity codes**, and `MT044`/`MT045` were unmapped (→ generic transaction error). This made target/guard failures indistinguishable from Application-registry faults and unmappable to the opaque `FORBIDDEN` error. Fixed by moving the membership-add guard failures onto the established prerequisite/payload codes `MT002` (→ `PersistenceReferenceError`) and `MT003` (→ `PersistenceIntegrityError`), reviewed here as a genuine defect fix to v012 only. The full non-live regression suite passes after the fix.

## 5. Gate results on final HEAD

| Gate | Result |
| --- | --- |
| `./build.sh --qa` | PASS — 2430 passed, coverage 90.45% |
| `./build.sh --sec` | PASS — 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS — 574 passed, 86 opt-in live skipped |
| Live Keycloak H01–H05 | **BLOCKED — not executed** |
