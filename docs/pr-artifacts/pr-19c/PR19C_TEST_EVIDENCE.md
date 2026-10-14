# PR19C_TEST_EVIDENCE

**PR:** roadmap PR 19C.
**Date:** 2026-10-14.
**Topology:** real PostgreSQL 18 (`mtmf_postgres_1`, host `127.0.0.1:25432`), provisioned `mtmf_owner`/`mtmf_migrator`/`mtmf_runtime`, real `PostgresMtmfSpi` and stored functions/UoW; unit suite on the in-memory provider. No live Keycloak/Uvicorn harness was executed.

## 1. Canonical gates

| Command | Result |
| --- | --- |
| `./build.sh --qa` | **PASS** — Ruff format, Ruff lint, strict Mypy, unit tests **2396 passed**, coverage **90.47%** (≥85%) |
| `./build.sh --sec` | **PASS** — Bandit + Semgrep **0 findings** |
| `./build.sh --integration` (equivalently `pytest tests/integration/postgres --no-cov`) | **PASS** — **570 passed**, 86 opt-in live tests skipped |
| `./build.sh --rust` | **NOT RUN** — no native code changed; not a PR 19C dependency |

## 2. Executed case IDs

| ID | Test | Result |
| --- | --- | --- |
| Amendment §D E1 | `SELECT identity(A) FOR SHARE` vs tenant-admin revocation | PASS (blocked) — concurrency proof script |
| E2a | actor ITM `FOR UPDATE` vs direct assignment add | PASS (blocked) |
| E2b | actor ITM `FOR UPDATE` vs identity-group membership add | PASS (blocked) |
| E3 | designation `FOR SHARE` vs `designate_steward` | PASS (blocked) |
| E4 | tenant `FOR SHARE` vs `suspend_tenant` | PASS (blocked) |
| E5 | role `FOR SHARE` vs `role_save` | PASS (blocked) |
| AP-01/AP-04 | built-in policy cumulative state | PASS — `tests/integration/postgres/test_postgres_builtin_policy.py` |
| AP-02 | idempotent replay of the member-add seed + built-in installer | PASS — `test_sc08_concurrent_seed_install_is_idempotent`, migration assertions |
| AP-05/AP-06/AP-07/AP-08/AP-09/AP-10 | steward/target guards (SQL layer) | PARTIAL — enforced by `identity_group_membership_add_lock`/`_verified`; dedicated case tests not yet written |
| I01 | new membership → exactly one audit row | PASS — `test_pr19c_management_membership.py::test_i01_new_membership_writes_exactly_one_audit_row` |
| I02 | duplicate → `false`, no new audit | PASS — `test_i02_duplicate_is_a_no_op_without_a_new_audit_row` |
| I04 | caller rollback rolls back both writes | PASS — `test_i04_caller_rollback_rolls_back_both_writes` |
| I06 | actual runtime invokes legacy function → denied | PASS — `test_i06_legacy_runtime_execute_is_denied` |
| I07 | runtime direct audit DML → denied | PASS — `test_i07_runtime_direct_audit_dml_is_denied` |
| I08 | malformed target/action → rejected | PASS — `test_i08_verified_function_rejects_malformed_target` |
| I10 | migration fresh/populated/re-run; strict postflight | PASS — `test_migrations.py`, `test_migration_privilege_lifecycle.py`, `test_runtime_privileges.py` |
| I11/I12 | policy-revocation / lifecycle races | Concurrency proof executed; dedicated 2-session case tests not yet written |
| H01–H05 | live dual-token HTTP acceptance | **NOT TESTED** — route/DTO/composition not implemented, no live Keycloak harness run |
| R01 | batch PDP + health unchanged | PASS — full unit + integration suites |
| R02 | membership-removal/stewardship audits unchanged | PASS — `test_membership_audit.py`, `test_postgres_root_stewardship.py` |
| R03 | remaining runtime allowlist entries unchanged | PASS — `test_runtime_privileges.py`, `test_stored_functions.py` |

## 3. Regression adaptations

Because the legacy runtime grant is intentionally revoked, integration fixtures that seeded Identity-Group memberships via the runtime SPI now seed through the administrator connection (`helpers.add_identity_group_membership`). Files adapted: `test_postgres_membership_repositories.py`, `test_postgres_error_concurrency.py`, `test_postgres_root_stewardship.py`, `test_postgres_stewardship_concurrency.py`. No security assertion or gate was weakened.

## 4. Not executed / not PASS

- Live Keycloak HTTP acceptance H01–H05.
- Full U03–U08 application unit matrix, CC-01–CC-07 and DB-01/DB-02 case tests.
- `./build.sh --rust`.

No unexecuted test is reported as PASS.

---

# Amendment 02 test evidence addendum (2026-10-14)

Canonical gates on final HEAD: `--qa` PASS (2430 passed, 90.45% coverage); `--sec` PASS (0 findings); `--rust` PASS; `--integration` PASS (574 passed, 86 opt-in live skipped).

New/extended tests (all executed):

| ID | Test | Result |
| --- | --- | --- |
| U-H01 | `test_api_management_dtos.py::test_uh01_*` | PASS |
| U-H02/U-H03 | `test_uh02_*`, `test_uh03_invalid_utf8_rejected`, `test_uh02_uh03_invalid_body_is_400_without_invocation`, `test_uh02_duplicate_json_keys_rejected` | PASS |
| U-H04 | `test_uh04_oversized_body_is_413_without_invocation` | PASS |
| U-H05 | `test_uh05_wrong_content_type_is_415` | PASS |
| U-H06 | `test_uh01_uh06_canonical_request_round_trip_created`, `test_uh06_authorized_duplicate_is_200_no_op` | PASS |
| U-H07 | `test_uh07_authenticated_policy_deny_is_opaque_forbidden` | PASS |
| U-H08 | `test_uh08_bad_service_and_user_tokens_map_correctly` | PASS |
| U-H09 | `test_uh09_database_outage_is_503_without_internals` | PASS |
| U-H10 | `test_uh10_single_terminal_management_event` | PASS |
| U-H11 | `test_uh11_admission_exhaustion_is_503_without_invocation` | PASS |
| U-H12 | `test_uh12_timeout_keeps_permit_until_worker_completes` | PASS |
| DB-H01/02 | `test_i01_*`, `test_i02_*` | PASS |
| DB-H03 | `test_db_h03_non_steward_actor_is_rejected`, `test_db_h03_cross_tenant_and_inactive_targets_are_rejected` | PASS |
| DB-H04 | `test_db_h04_audit_conflict_rolls_back_the_membership` | PASS |
| DB-H05 | `test_runtime_privileges.py` + v012 assertions | PASS |
| CC-H01..H03 | `PR19C_CONCURRENCY_PROOF.md` E1–E5 | PASS (proof) |
| CC-H04 | `test_cc_h04_concurrent_duplicate_adds_commit_one_row_and_one_audit` | PASS |
| H01–H05 | live Keycloak | **NOT EXECUTED — BLOCKED** |

No live test is reported as PASS. The `86 skipped` integration cases include the opt-in live suites and do not satisfy H01–H05.
