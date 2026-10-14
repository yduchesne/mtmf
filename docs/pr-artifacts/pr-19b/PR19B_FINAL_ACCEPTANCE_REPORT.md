# PR 19B — Final Acceptance Report

- **Roadmap PR:** PR 19B — Security-state audit date partitioning
- **Status:** **DONE**
- **Date (UTC):** 2026-10-14
- **Base SHA:** `5979ddf8dca10f2b478a91cd141e6684294058f1`
- **Branch:** `dev/paritioned-audit-tables`
- **PostgreSQL:** 18.6 (`180006`)

## 1. Deliverables

| Deliverable | Path |
|---|---|
| Additive Alembic revision | `packages/mtmf-core/src/mtmf_core/persistence/postgres/migrations/versions/0013_security_mutation_audit_partitioning.py` |
| Migration SQL | `.../sql/v013/01_security_mutation_audit_partition_migration.sql` |
| Maintenance function | `.../sql/v013/02_security_mutation_audit_partition_maintenance.sql` |
| Grant posture | `.../sql/v013/03_security_mutation_audit_partition_grants.sql` |
| Assertions | `.../sql/v013/04_security_mutation_audit_partition_assertions.sql` |
| Acceptance tests | `tests/integration/postgres/test_pr19b_audit_partitioning.py` |
| Operations runbook | `docs/DATABASE.md` section 13 |
| Roadmap status | `docs/ROADMAP_V01.md` |
| Reports | `docs/pr-artifacts/pr-19b/` |

Also updated: `migration.py` `HEAD_REVISION = "0013"`; head-revision assertions
in six existing integration/unit test modules; and the PR 19C audit-conflict
regression to pin the server timestamp for a deterministic composite-key
collision.

## 2. Completion contract

- [x] The schema is natively monthly (UTC `RANGE (occurred_at)`) partitioned.
- [x] Pre-existing rows are provably unchanged (whole-row `EXCEPT ALL` equality
      and md5 equality in migration and P02).
- [x] Parent and direct-child append-only protections hold (SQLSTATE `MT033`,
      including per-child `TRUNCATE` guards).
- [x] Audited membership add remains atomic under success, duplicate, and
      partition-failure paths (P13/P14/P15).
- [x] The operator can idempotently provision the next months without runtime
      DDL (`ensure_security_mutation_audit_month`, P07/P08/P09/P10).
- [x] Privileges remain exact: 78-signature runtime allowlist unchanged; no
      PUBLIC/runtime audit table or maintenance-function access.
- [x] P01–P19 and the four canonical gates pass with zero P01–P19 skips.
- [x] Committed documentation truthfully reflects the composite-key limitation,
      the fixed 12-month horizon, and the absence of any retention deletion.

## 3. Gate results

| Gate | Result |
|---|---|
| `./build.sh --qa` | PASS — 2448 passed, coverage 90.36% |
| `./build.sh --sec` | PASS — 0 findings |
| `./build.sh --rust` | PASS |
| `./build.sh --integration` | PASS — 593 passed, 90 opt-in live skipped |
| `test_pr19b_audit_partitioning.py` | PASS — 19 passed |

## 4. Reviewer checklist

- [x] Latest merged PR 19C `main` baseline and migration head recorded.
- [x] New additive `v013` only; `v012` and `0001`–`0012` untouched.
- [x] Partitioned `occurred_at` monthly UTC; no DEFAULT; all historical months
      plus current + 12.
- [x] Existing rows preserved exactly and migration transactionally safe.
- [x] PK `(occurred_at, id)` and the global-uniqueness limitation explicitly
      documented.
- [x] Existing checks, indexes, trigger guards, table owner and privilege model
      preserved.
- [x] Runtime cannot create partitions or write audit directly; 78-signature
      manifest unchanged.
- [x] Owner-only idempotent maintenance; no automatic deletion/retention policy.
- [x] P01–P19 executed against real PostgreSQL 18 with zero skips.
- [x] PR 19C atomicity/no-op/denial regressions pass.
- [x] All four canonical gates pass on final HEAD.
- [x] Reports committed in `docs/pr-artifacts/pr-19b/`; roadmap marked DONE.

## 5. Deviations and residual limitations

- **Composite primary key:** `id` alone is no longer unique. This is mandated by
  the partitioning decision; identical `(occurred_at, id)` is rejected and the
  same `id` in different months is accepted. No global-id ledger was added.
- **PR 19C H04 adaptation:** the audit-conflict regression now pins the server
  timestamp so a composite-key collision is deterministic. The rollback
  contract it proves is unchanged.
- **Fixed horizon / manual operations:** the current+12 horizon requires a
  monthly privileged operator action; there is no scheduler and no automatic
  retention. This is deliberate and documented.
- **Live suites not run:** the opt-in deployed Keycloak/HTTP suites were skipped
  because their environment flags were unset; they are not PR 19B feature
  acceptance.

No STOP condition was encountered. PR 19B is DONE; PR 19C DONE is unchanged;
PR 19D remains conditional and not done.
