# PR22A_BASELINE_AND_INTEGRITY_RECONCILIATION

**Roadmap identifier:** PR 22A — Entitlement persistence foundation
**Branch:** `dev/tenant-provisioning`
**Type:** Phase 0 integrity and implementation reconciliation for the PR 22 blocker-resolution plan.
**Status:** COMPLETE — checkout matches the reported branch/tip; Git integrity verified; entitlement foundation confirmed.

## 1. Repository state and integrity

| Item | Value |
| --- | --- |
| Branch | `dev/tenant-provisioning` |
| `git rev-parse HEAD` | `4ddc82f0de85fe1d07a11ef66337605d7587aacb` |
| Base (`git merge-base HEAD main`) | `abba785f74c684d45e302d870a611abe10e1aa04` |
| Content commit | `07db63d90b44cb71a1bb6dc5ded99a51f9fe0da3` |
| Working tree (`git status --porcelain=v1`) | clean |
| `git diff --check` | clean (no whitespace errors) |
| `git fsck --full` | **exit 0** — no `error`/`broken`/`missing`; 32 harmless dangling objects (residue of the earlier interrupted commit) |
| Migration head | `0014_pr22_onboarding_entitlement` |
| Push | none (not authorized) |

The three previously truncated artifacts were verified by content, not size:
`PR22_ACCEPTANCE_REPORT.md` (68 lines), `PR22_INTEGRATION_ACCEPTANCE.md`
(71 lines), `PR22_FINAL_SHA.md` (13 lines) all contain their expected headings
and links.

## 2. Changed files vs base (exact inventory)

Implementation:
- `packages/mtmf-core/src/mtmf_core/domain/onboarding_entitlement.py` (new)
- `packages/mtmf-core/src/mtmf_core/domain/errors.py` (`OnboardingEntitlementInvariantError`)
- `packages/mtmf-core/src/mtmf_core/persistence/postgres/migration.py` (`HEAD_REVISION = "0014"`)
- `packages/mtmf-core/src/mtmf_core/persistence/postgres/migrations/versions/0014_pr22_onboarding_entitlement.py` (new)
- `packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/v014/01..04.sql`, `__init__.py` (new)
- `tests/unit/core/test_onboarding_entitlement.py` (new)
- `tests/integration/postgres/test_pr22_onboarding_entitlement.py` (new)
- Head/manifest updates in `tests/unit/core/test_postgres_migration.py` and
  `tests/integration/postgres/{test_migration_privilege_lifecycle,test_migrations,test_postgres_role_assignments,test_postgres_runtime_security,test_pr19b_audit_partitioning,test_runtime_privileges}.py`

Documentation:
- `docs/DATABASE.md`, `docs/ROADMAP_V01.md`, and the seven
  `docs/pr-artifacts/pr-22/*` artifacts.

## 3. Reused seams (verified paths)

`MtmfSpi`/`PostgresMtmfSpi` (`persistence/spi.py`, `persistence/postgres/spi.py`),
`UnitOfWork` (`persistence/unit_of_work.py`), repository conventions
(`persistence/repositories.py`), `sql_version_files`
(`persistence/postgres/resources.py`), `expected_runtime_signatures()`
(`persistence/postgres/roles.py`), `PostgresMigrationManager`
(`persistence/postgres/migration.py`), the PR 13 operator-only pattern
(`sql/v010/02..03`), PR 14 bindings (`sql/v011`), PR 19C audit/provenance
(`sql/v012`, `application/mutation_provenance.py`), and the real-PostgreSQL
test fixtures (`tests/integration/postgres/conftest.py`). No duplicate layer.

## 4. Installed schema / functions / grants

- `mtmf.application_onboarding_entitlement` and
  `mtmf.application_onboarding_entitlement_event` (append-only history).
- Constraints: `state IN (1,2)`, `quota_total > 0`,
  `0 <= quota_consumed <= quota_total`, `version >= 0`, bounded reasons,
  revocation-consistency; `UNIQUE (application_id) WHERE state = 1`.
- Seven owner-owned `SECURITY INVOKER` functions with `search_path = ''` and
  `PUBLIC` EXECUTE revoked: `application_onboarding_entitlement_grant`,
  `_revoke`, `_get`, `_find_by_application`,
  `_event_find_by_entitlement`, and the two guards.
- **No `mtmf_runtime` grant**; runtime EXECUTE allowlist unchanged at **78**;
  no runtime table privilege.

## 5. P22-01…P22-18 reconciliation

Legend: DONE+VERIFIED / PARTIAL / BLOCKED / NOT STARTED. "Test exists" is
distinguished from "executed and passed in the required real-PostgreSQL,
restricted-runtime topology".

| ID | State | Evidence |
| --- | --- | --- |
| P22-01 | DONE+VERIFIED | `test_p22_01_operator_grant_with_explicit_quota` (executed, passed) |
| P22-02 | DONE+VERIFIED | `test_p22_02_runtime_cannot_grant_entitlement` |
| P22-03 | DONE+VERIFIED | `test_p22_03_revoke_is_terminal` |
| P22-04 | DONE+VERIFIED | `test_p22_04_regrant_after_revoke_uses_fresh_uuid` |
| P22-05 | DONE+VERIFIED | `test_p22_05_inactive_application_is_denied`, `..._unknown_application_is_denied` |
| P22-06 | PARTIAL | invalid/nonpositive quota verified; **quota exhaustion** requires the blocked composite |
| P22-07 | BLOCKED | concurrent distinct provisioning requests require the composite |
| P22-08 | BLOCKED | idempotency replay ledger not implemented |
| P22-09 | BLOCKED | fingerprint conflict not implemented |
| P22-10 | BLOCKED | fault-after-stage rollback requires the composite |
| P22-11 | BLOCKED | PR 23 participant + composite not implemented |
| P22-12 | BLOCKED | coordinator/participant not implemented |
| P22-13 | BLOCKED | first-Tenant composite not implemented |
| P22-14 | PARTIAL | retired/inactive Application denied at grant; SYSTEM/root composite not implemented |
| P22-15 | DONE+VERIFIED | full integration suite green (PR 13 lifecycle regression) |
| P22-16 | DONE+VERIFIED | `test_p22_16_runtime_cannot_read_or_revoke_entitlement` |
| P22-17 | DONE+VERIFIED | `test_p22_17_migration_postflight_and_runtime_allowlist_unchanged` |
| P22-18 | DONE+VERIFIED | `test_p22_18_history_is_append_only`; migration/privilege lifecycle suites |

Additional PR 22A invariant tests (added this pass, executed and passed on real
PostgreSQL):
- `test_p22a_concurrent_duplicate_grant_has_one_active` (concurrent duplicate
  grant ⇒ exactly one ACTIVE, one GRANTED event).
- `test_p22a_entitlement_functions_create_no_tenant_or_linkage` (no Tenant,
  registration, or subscription created).
- `test_p22a_nil_application_and_operator_uuids_are_denied` (closed via the
  reviewed FK constraints).

## 6. Baseline gate evidence

On the reconciled tree: `--qa` 2472 passed / 90.32% coverage; `--sec` 0
findings; `--rust` pass; `--integration` 603 passed / 90 skipped; PR 22
integration file 13 passed. PostgreSQL 18.6, migration head `0014`, runtime
allowlist 78. (See `PR22A_INTEGRATION_ACCEPTANCE_REPORT.md` for the final
post-split rerun.)

## 7. Discrepancies / notes

- The entitlement `REVOKED`-then-regrant and append-only semantics are
  verified; quota **consumption** is intentionally absent (BLOCKED).
- The earlier corruption (47 zero-byte loose objects, three truncated reports)
  is fully repaired; `git fsck --full` is clean.
- No STOP-0/STOP-7 condition applies: branch/tip match and integrity passes.
