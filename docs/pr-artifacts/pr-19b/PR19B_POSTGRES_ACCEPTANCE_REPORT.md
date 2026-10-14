# PR 19B — PostgreSQL Acceptance Report

- **Date (UTC):** 2026-10-14
- **Base SHA:** `5979ddf8dca10f2b478a91cd141e6684294058f1`
- **PostgreSQL server:** 18.6 (Debian 18.6-1.pgdg13+2), `server_version_num = 180006`
- **Primary database:** MTMF-owned `mtmf` at `127.0.0.1:25432`
  (Podman container `mtmf_postgres_1`), reached through explicit `MTMF_*`
  configuration.
- **Disposable database:** `mtmf_pr19b_probe` (created with
  `OWNER mtmf_owner`) used for upgrade/rollback/concurrency probes.

## 1. Role and connection topology

| Identity | Role | Use |
|---|---|---|
| `mtmf` | administrator (superuser) | schema reset, fixture seeding, `db` fixture |
| `mtmf_migrator` | deployment login, `SET ROLE mtmf_owner` only | real migrations, post-upgrade verifier |
| `mtmf_owner` | NOLOGIN owner | owns every MTMF object; assumed only via `SET ROLE` |
| `mtmf_runtime` | restricted application login | privilege-denial subject |

No live Keycloak/deployed-HTTP environment was used for PR 19B feature
acceptance. The opt-in live suites (`MTMF_PR19C_LIVE`, `MTMF_PR17_LIVE`) were
unset and reported as **skipped**, never PASS. PR 19B does not change the
deployed mutation path, so P13–P15 plus the canonical integration gate are the
feature acceptance and the live suite is only an additional regression gate.

## 2. Direct acceptance run

Command:

```
uv run --no-sync pytest tests/integration/postgres/test_pr19b_audit_partitioning.py --no-cov -q
```

Result: **19 passed** (P01–P19, zero skips, zero xfail).

## 3. P01–P19 outcomes

| ID | Scenario | Outcome |
|---|---|---|
| P01 | Fresh install to `0013` | PASS — `relkind='p'`, `RANGE (occurred_at)`, PK `(occurred_at, id)`, exact 12 columns/3 CHECKs/default/indexes, current UTC + 12 partitions, no DEFAULT, no backup, parent and every child carry the three guards |
| P02 | Upgrade `0012 → 0013` with rows in ≥3 UTC months incl. leap-year February | PASS — count and whole-row md5 `af90b34ea819b9bfd20d608d385f4119` unchanged; original ids preserved; routing 2024-01/02/03 correct; zero parent-stored rows |
| P03 | Duplicate `(occurred_at, id)` | PASS — `23505`, one row remains |
| P04 | Same `id`, different months | PASS — allowed at the database level; non-global uniqueness documented |
| P05 | Before/at/after UTC month turnover with session `TimeZone='America/New_York'` | PASS — half-open UTC routing independent of session timezone |
| P06 | Current + 12 horizon | PASS — 13 months present; no DEFAULT; beyond-horizon insert raises `23514` |
| P07 | Privileged `ensure` twice | PASS — first creates exactly one child, second is a no-op; child has 3 guards |
| P08 | Ensure invalid/NULL/non-first-day/out-of-range | PASS — `22023` each time, no DDL |
| P09 | Ensure name collision / wrong attachment | PASS — `55000`, decoy table unchanged and unattached |
| P10 | Concurrent privileged `ensure` (two connections) | PASS — exactly one correctly attached partition; no duplicate/ambiguous DDL |
| P11 | `UPDATE`/`DELETE`/`TRUNCATE` via parent and direct child, owner-authorized | PASS — SQLSTATE `MT033` in all six cases; row unchanged |
| P12 | `mtmf_runtime` direct audit DML + maintenance `EXECUTE` | PASS — all denied; reviewed writers remain executable; allowlist exact |
| P13 | Real verified membership-add writer with available month | PASS — one membership + one audit row; duplicate is a no-op with no extra audit |
| P14 | Real writer with matching partition absent | PASS — audit insert fails, membership rolled back (`PersistenceError`), no orphan row |
| P15 | Audit insert failure after membership insert (pinned timestamp composite-key collision) | PASS — both writes rolled back, no orphan membership, audit count 1 |
| P16 | Migration rollback injection on isolated `0012` fixture | PASS — original table/rows/head restored; no committed half-swap; no backup table |
| P17 | Upgrade with open concurrent writer | PASS — `ACCESS EXCLUSIVE` blocks the migration until the writer commits; committed row preserved exactly once |
| P18 | Runtime allowlist and post-migration verifier | PASS — `verify_runtime_privileges` clean; exactly 78 approved signatures |
| P19 | Migration replay / head validation | PASS — `0013` sole head; repeated upgrade does not duplicate partitions or rows |

## 4. Canonical gates (final working tree)

| Gate | Command | Result |
|---|---|---|
| QA | `./build.sh --qa` | PASS — Ruff format/lint clean, strict Mypy clean, **2448 passed**, coverage **90.36%** (≥ 85%) |
| Security | `./build.sh --sec` | PASS — Bandit 0 Medium/High findings across `packages` and `tests`; Semgrep 297 rules / 224 targets, **0 findings** |
| Rust/native | `./build.sh --rust` | PASS — cargo fmt/clippy/test, `maturin develop`, installed-native probe, native boundary/differential/Authorizer suites, clean-wheel verification, benchmark smoke |
| Integration | `./build.sh --integration` | PASS — **593 passed, 90 skipped** in 494.10 s |

Note on skips: the 90 skipped integration tests are the pre-existing opt-in
PR 14/17/18/19/19C live suites whose environment flags were unset. P01–P19 have
zero skips.

## 5. Migration replay and head assertions

- `PostgresMigrationManager.head_revision == "0013"`.
- Already-head `upgrade_to_head()` reruns are idempotent and re-run the
  mandatory post-upgrade runtime privilege verifier.
- Existing tests that pinned the head to `0012` were updated to `0013`
  (`test_migrations`, `test_migration_privilege_lifecycle`,
  `test_runtime_privileges`, `test_postgres_runtime_security`,
  `test_postgres_role_assignments`, `test_postgres_migration`). No assertion
  was weakened, skipped, or deleted.

## 6. Unresolved issues

- `id` is not globally unique after partitioning; only identical
  `(occurred_at, id)` is rejected. Documented in `docs/DATABASE.md` section 13
  and `docs/ROADMAP_V01.md`. A proven global-uniqueness requirement would need
  a separately approved design.
- The 12-month horizon requires a monthly privileged operator action
  (`docs/DATABASE.md` section 13.4); there is no scheduler and no automatic
  retention. This is deliberate.
- The live deployed-HTTP regression suites were not executed in this
  environment; they are opt-in and not required for PR 19B feature acceptance.
