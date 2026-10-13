# PR 17-B Security-Hardening Test Matrix

**PR:** PR 17-B — security-hardening amendment
**Amended tip:** `6471e392d4b2f0ecc617ced9c70e33ef10c489ba`
**Starting tip:** `0c9ee1e6ae75d41b56d4353c85c65060a0432f64`
**Base:** `b60c50b9b134a28d2a1199ce01abc608c7f319d3`

New SH tests are additive to U01–U28 and I01–I20. Unit tests fake only the
Keycloak Admin REST transport and filesystem seams; live tests use real
Keycloak and real PostgreSQL.

## 1. SH01–SH18 mapping

| ID | Status | Executable test(s) | Evidence |
| --- | --- | --- | --- |
| SH01 | PASS | unit `test_create_includes_email_verification`; live `test_sh16_created_user_with_unverified_email_can_login` | Create body carries `emailVerified=false`; live Keycloak returns `emailVerified=False`. |
| SH02 | PASS | unit `test_sh02_existing_user_reuse_is_read_only_regardless_of_email_verification`; `test_u04_existing_user_never_reads_password_file` | Existing account reused read-only; password file not opened. |
| SH03 | PASS | unit `test_u08_email_mismatch_or_disabled_fails_without_repair`, `test_u09_multiple_exact_users_is_ambiguous`, `test_u14_federated_and_managed_accounts_are_rejected` | Wrong email / disabled / federated / ambiguous fail closed before any write. |
| SH04 | PASS | unit `test_sh04_definite_rejection_is_not_converted_by_a_matching_lookup` | 400 → fail closed; a matching username that appears afterwards is not accepted (calls are `GET, POST` only). |
| SH05 | PASS | unit `test_sh05_definite_4xx_fails_closed[400/401/403/422]` | Redacted `HTTP <code>`, no secret leakage, no re-read acceptance. |
| SH06 | PASS | unit `test_sh06_success_with_matching_location_is_accepted`, `test_sh06_success_with_mismatched_location_is_rejected`, `test_u02_missing_user_create_once_and_reread` | Success accepts only when the re-read id equals Keycloak's `Location` id; mismatch fails closed. |
| SH07 | PASS | unit `test_sh07_conflict_without_assertion_fails_closed` | 409 without independent correlation fails closed. |
| SH08 | PASS | unit `test_sh08_conflict_with_matching_assertion_is_accepted`; live `test_i12_two_simultaneous_initializers_converge` | Concurrent initializer honors the approved policy; I12 unchanged (one success + recoverable failure + idempotent retry). |
| SH09 | PASS | unit `test_sh09_lost_response_without_assertion_fails_closed`, `test_sh09_lost_response_with_matching_assertion_is_accepted`; live `test_i15a_lost_create_response_fails_closed_then_reconciles` | Lost response → fail closed without a second POST; correlation or rerun reuse. |
| SH10 | PASS | unit `test_sh10_indeterminate_post_with_lookup_failure_fails_closed`; live `test_i15c_indeterminate_re_read_fails_closed` | Indeterminate POST + failed lookup fails closed; no MTMF writes. |
| SH11 | PASS | unit `test_sh11_success_with_mismatched_assertion_fails` | Assertion mismatch fails closed before binding. |
| SH12 | PASS | unit `test_u11_unsafe_password_files_are_rejected_before_creation`, `test_password_file_rejects_oversize_nul_and_non_utf8` | Symlink/unsafe-mode/nonregular/oversize/empty/NUL/non-UTF-8 rejected before POST. |
| SH13 | PASS | unit `test_sh13_validation_and_read_use_the_same_descriptor`, `test_sh13_oversize_after_fstat_is_rejected`, `test_sh13_descriptor_is_closed_on_validation_failure` | Deterministic same-fd proof; oversize-after-fstat rejected; fd closed on failure. |
| SH14 | PASS | unit `test_u04_existing_user_never_reads_password_file`, `test_u22_existing_user_with_unreadable_password_file_succeeds` | Existing-user path never opens the password file. |
| SH15 | PASS | unit `test_test_failpoint_is_inert_by_default_and_triggers_when_set` (absent / near-miss / different value / exact), `test_entry_point_failpoint_stops_before_any_mtmf_write` | Failpoint inert except exact value; exits before any MTMF write. |
| SH16 | PASS | live `test_sh16_created_user_with_unverified_email_can_login` (+ I13/I14 OIDC login) | Real browser/OIDC authorization-code login succeeds for a newly created user with `emailVerified=false`. |
| SH17 | PASS | live `test_i13_i14_kill_after_create_then_restart_is_idempotent`, `test_i15a_lost_create_response_fails_closed_then_reconciles` | Stable subject, no duplicate MTMF state, no password reset across restart. |
| SH18 | PASS | live `test_i16_compose_container_isolation_and_live_secret_mount` | Real Compose containers: privileged secrets only in the initializer, never the runtime. |

## 2. I01–I20 preservation

The full live acceptance harness was re-run on the amended tree: **9 passed**
(`test_pr17b_live_acceptance.py`) plus **1 passed**
(`test_pr17b_compose_isolation.py`), and the PR 14/PR 17 regression suites
**51 passed** — 61 live tests total, 0 failures. I01–I20 remain PASS. The one
deliberate expectation change is I15a (see
`PR17B_SECURITY_HARDENING_RECONCILIATION_DECISION.md` §6): a lost create
response now fails closed without an assertion and reconciles on rerun, which is
exactly SH09/SH10.

## 3. Counts

| Suite | Tests |
| --- | --- |
| `tests/unit/service/test_pr17b_development_user.py` | 60 (17 SH-named) |
| `tests/unit/service/test_pr17b_initialize_script.py` | 12 |
| `tests/integration/postgres/test_pr17b_live_acceptance.py` | 9 (live) |
| `tests/integration/postgres/test_pr17b_compose_isolation.py` | 1 (live) |
| Full unit suite (`./build.sh --qa`) | 1878 passed, coverage 90.76% |
| Full live matrix | 61 passed |
