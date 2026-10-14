# PR19A_TEST_EVIDENCE

**PR:** roadmap PR 19A — verified-provenance mutation audit.
**Base commit:** `44c6c0b7230ccbd4820866fb97f36896566753a5`.
**Result:** every test that can be proven without a new management feature **ran and passed**; every database/end-to-end case is **BLOCKED / NOT EXECUTED** and is not claimed as PASS.

## 1. Canonical gate runs (executed)

| Gate | Command | Observed result | Exit |
|---|---|---|---|
| QA (Ruff format, Ruff lint, strict Mypy, unit + coverage) | `./build.sh --qa` | `2105 passed, 177 skipped, 3 warnings`; total coverage **90.76%**; `mutation_provenance.py` **100%** (75 stmts / 24 branches, 0 missing) | 0 |
| Security | `./build.sh --sec` | Bandit Medium/High 0 findings; Semgrep 297 rules on 207 targets, **0 findings** | 0 |
| Rust/native | `./build.sh --rust` | cargo fmt/clippy/test, `maturin develop`, installed-native probe, native-boundary/differential/compiled-policy tests, isolated wheel verification, benchmark smoke all passed | 0 |
| PostgreSQL integration | `./build.sh --integration` (MTMF `.env` sourced) | `564 passed, 86 skipped in 219.35s` | 0 |

Baseline (pre-change) results are `2085 passed / 90.67%` (`--qa`) and `564 passed / 86 skipped` (`--integration`); see `PR19A_BASELINE_REPORT.md`. The two new-suite commands are also runnable directly:

```
uv run --no-sync pytest tests/unit/application/test_mutation_provenance.py -q --no-cov
# 20 passed in 0.25s
```

## 2. Deterministic unit matrix

| ID | Scenario | Status | Evidence |
|---|---|---|---|
| PA-U01 | valid immutable provenance from trusted orchestration | **PASS (contract)** | `test_pa_u01_valid_provenance_is_accepted_and_immutable` (frozen mutation raises `FrozenInstanceError`); `test_pa_u01_equal_field_values_compare_equal`; `test_pa_u01_offset_zero_timestamp_is_normalized_to_utc`. Note: the record is constructed directly; a real *trusted orchestration* caller does not exist (BLOCKED). |
| PA-U02 | missing actor/tenant/application/target rejected before DB call | **PASS** | `test_pa_u02_none_identity_is_rejected` (5 params); `test_pa_u02_missing_required_field_is_a_constructor_error`; `test_pa_u02_empty_or_malformed_target_kind_is_rejected` |
| PA-U03 | naive/non-UTC timestamp, malformed operation UUID rejected | **PASS** | `test_pa_u03_non_uuid_operation_id_is_rejected`; `test_pa_u03_naive_timestamp_is_rejected`; `test_pa_u03_non_utc_timestamp_is_rejected`; `test_pa_u03_non_datetime_timestamp_is_rejected`; `test_pa_u03_non_action_urn_is_rejected` |
| PA-U04 | caller-supplied actor ID without verified context | **PASS (contract absence)** | `test_pa_u04_module_exposes_no_trusted_factory_or_flag` (no `from_actor_id`/`for_actor`/`trusted`; no `trusted`/`verified` field). "No mutation" is vacuous because no orchestration/write path exists. |
| PA-U05 | invalid service/user token fails closed | **NOT EXECUTED (PR 19A)** | Existing PR 14 authentication tests cover verification fail-closed; PR 19A added no call path to test. |
| PA-U06 | actor verified, Action DENY → no mutation/audit | **BLOCKED** | no category-A path |
| PA-U07 | cross-Tenant target / mismatched session → DENY | **BLOCKED** | no category-A path |
| PA-U08 | missing dominance/stewardship → DENY, no write | **BLOCKED** | no category-A path |
| PA-U09 | Action ALLOW → one trusted record passed to persistence | **BLOCKED** | no category-A path |
| PA-U10 | exception between authorization and commit → rollback | **BLOCKED** | no Persistence write path |
| PA-U11 | duplicate operation ID → no duplicate successful audit | **BLOCKED** | no audit table |
| PA-U12 | no-op update → no state-change audit | **BLOCKED** | no audit table |
| PA-U13 | invalid target-kind/action pairing rejected | **PASS** | `test_pa_u13_registry_is_empty_and_read_only_in_pr19a`; `test_pa_u13_unregistered_target_kind_fails_closed`; `test_pa_u13_unapproved_action_for_registered_kind_fails_closed`; `test_pa_u13_approved_pairing_is_accepted` |
| PA-U14 | telemetry exporter unavailable → atomicity unchanged | **NOT APPLICABLE** | PR 19A adds no telemetry/audit write; OTel behavior is unchanged and covered by PR 19. |
| PA-U15 | cancel during remote authentication | **NOT EXECUTED (PR 19A)** | unchanged PR 14 behavior |
| PA-U16 | structural repository caller supplies fabricated provenance | **BLOCKED** | no reviewed path accepts provenance; the provenance contract is not referenced by any SPI/repository signature. |

## 3. PostgreSQL / vertical-slice matrix

| ID | Scenario | Status | Reason |
|---|---|---|---|
| PA-I01 | migration on empty DB → table/grants/postflight | **NOT EXECUTED** | no migration/table added (Phase 0 STOP). |
| PA-I02 | authorized management mutation → state + one audit row | **BLOCKED** | no category-A path. |
| PA-I03 | rollback after staged mutation | **BLOCKED** | no migration/table. |
| PA-I04 | audit-insert failure → state rolls back | **BLOCKED** | no migration/table. |
| PA-I05 | no-op → no misleading audit | **BLOCKED** | no migration/table. |
| PA-I06 | duplicate operation UUID | **BLOCKED** | no migration/table. |
| PA-I07 | runtime direct audit-table DML | **BLOCKED** | no new table; existing "no runtime table DML" posture is unchanged and still verified by PRIV tests. |
| PA-I08 | runtime legacy bypass for a migrated operation | **BLOCKED** | no operation migrated; every legacy mutator remains executable. |
| PA-I09 | owner/migrator config cannot be used by production UoW | **NOT EXECUTED (PR 19A)** | unchanged; existing `A1-*`/`PRIV-17` regression passes. |
| PA-I10 | forged Tenant/Identity/target mismatch | **BLOCKED** | no category-A path. |
| PA-I11 | concurrent revocation/role change vs mutation | **BLOCKED** | no category-A path. |
| PA-I12 | existing membership removal → old audit exactly once | **PASS (existing regression, not PR 19A coverage)** | `tests/integration/postgres/test_membership_audit.py`, `test_membership_removal*.py` pass within `--integration`. |
| PA-I13 | stewardship/root recovery → old audit/obligations preserved | **PASS (existing regression, not PR 19A coverage)** | `tests/integration/postgres/test_postgres_root_stewardship.py`, `test_postgres_stewardship_concurrency.py` pass within `--integration`. |
| PA-I14 | migration rerun/upgrade-to-head, stable verifier | **PASS (existing regression)** | migration/privilege lifecycle tests pass; head remains `0011`. |
| PA-I15 | real authenticated operation through existing service seam | **BLOCKED** | no mutation route/seam exists; not replaced by a synthetic test-only API. |
| PA-I16 | unauthorized actor → no mutation/audit | **BLOCKED** | no category-A path. |

## 4. Environmental note

The 86 integration skips are the opt-in live Keycloak/Uvicorn/Collector cases and match the PR 19 baseline; they are not counted as passes. No test result in this report was inferred or fabricated: every PASS above names an executed test, and every non-executed case is explicitly labeled.
