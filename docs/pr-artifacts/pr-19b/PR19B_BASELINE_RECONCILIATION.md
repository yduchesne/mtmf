# PR 19B — Baseline Reconciliation

- **Roadmap PR:** PR 19B — Security-state audit date partitioning
- **Artifact directory:** `docs/pr-artifacts/pr-19b/`
- **Repository base:** `5979ddf8dca10f2b478a91cd141e6684294058f1` (`main`, merged PR 19C)
- **Working branch:** `dev/paritioned-audit-tables`
- **Reconciliation date (UTC):** 2026-10-14
- **PostgreSQL server:** 18.6 (Debian 18.6-1.pgdg13+2), `server_version_num = 180006`
- **Database:** MTMF-owned `mtmf` on the canonical MTMF host-port prefix-2 endpoint
  (`127.0.0.1:25432`, container `mtmf_postgres_1`)

## 1. Migration head and revision graph

| Item | Value |
|---|---|
| Alembic current revision before PR 19B | `0012` |
| Revision `0012` predecessor | `0011` |
| Revision `0012` SQL resources | packaged `sql/v012/01..06` |
| Pre-existing `0013` revision | none |
| Canonical packaged-resource discovery | `mtmf_core.persistence.postgres.resources.sql_version_files` |

`packages/mtmf-core/src/mtmf_core/persistence/postgres/migration.py` declared
`HEAD_REVISION = "0012"`; the mandatory post-upgrade runtime privilege verifier
was already wired into every `upgrade_to_head()`.

## 2. v012 `mtmf.security_mutation_audit` definition (clean migrated DB)

Captured with `pg_catalog`/`information_schema` on a freshly reset and migrated
`mtmf` schema.

**Columns (12, in order):**

| # | Column | Type | NOT NULL | Default |
|---|---|---|---|---|
| 1 | `id` | `uuid` | yes | — |
| 2 | `occurred_at` | `timestamp with time zone` | yes | `clock_timestamp()` |
| 3 | `authorized_at` | `timestamp with time zone` | yes | — |
| 4 | `actor_identity_id` | `uuid` | yes | — |
| 5 | `actor_principal_id` | `uuid` | yes | — |
| 6 | `tenant_id` | `uuid` | yes | — |
| 7 | `application_id` | `uuid` | yes | — |
| 8 | `action_urn` | `text` | yes | — |
| 9 | `target_kind` | `text` | yes | — |
| 10 | `target_id` | `uuid` | yes | — |
| 11 | `subject_identity_id` | `uuid` | yes | — |
| 12 | `outcome` | `text` | yes | — |

**Constraints:**

- `security_mutation_audit_pk PRIMARY KEY (id)`
- `security_mutation_audit_outcome_check CHECK (outcome = 'CREATED')`
- `security_mutation_audit_target_kind_check CHECK (target_kind = 'identity_group_membership')`
- `security_mutation_audit_action_urn_check CHECK (action_urn = 'urn:mtmf:iam:actions:system:identity-group-membership:add-object')`

**Indexes:** `security_mutation_audit_pk (id)`,
`security_mutation_audit_tenant_occurred_idx (tenant_id, occurred_at DESC)`,
`security_mutation_audit_target_occurred_idx (target_kind, target_id, occurred_at DESC)`.

**Triggers** (all using `mtmf.guard_security_mutation_audit()`, enabled `O`):
`security_mutation_audit_update_guard` (`BEFORE UPDATE ... FOR EACH ROW`),
`security_mutation_audit_delete_guard` (`BEFORE DELETE ... FOR EACH ROW`),
`security_mutation_audit_truncate_guard` (`BEFORE TRUNCATE ... FOR EACH STATEMENT`).

**Owner / privileges:** table owner `mtmf_owner`; `relkind = 'r'`
(unpartitioned); `PUBLIC` revoked; `mtmf_runtime` holds no table privilege.
Runtime EXECUTE allowlist count was exactly **78**.

## 3. Data inventory on the clean canonical database

| Metric | Value |
|---|---|
| `count(*)` | 0 |
| `min(occurred_at)` / `max(occurred_at)` | `NULL` / `NULL` |
| duplicate `id` groups | 0 |
| distinct UTC months represented | 0 |

The canonical dev database was reset to an empty migrated schema before
capture, so the pre-migration row set is empty. Existing PR 19C acceptance
data lives in disposable acceptance/database fixtures, not the canonical
development database.

## 4. Dependency inspection (Step A2)

Catalog inspection with `pg_depend`, `pg_constraint`, `pg_trigger`,
`pg_indexes`, and `pg_publication_rel`:

| Dependency class | Count |
|---|---|
| Foreign keys referencing the table | 0 |
| Foreign keys from the table | 0 |
| Publication membership | 0 |
| Views/materialized views | 0 |
| `pg_depend` rows referencing the table OID | 30 |

All 30 `pg_depend` rows are internal (`deptype` `a`/`i`/`n`): the three CHECK
constraints, the primary-key/index objects, the `occurred_at` default, the
three guard triggers, the row type, and the TOAST relation. No external
object depends on `security_mutation_audit`, `security_mutation_audit_pk`, or
`id`-only uniqueness. No caller or schema object was found that relies on
database-global uniqueness of `id` alone. The rename-and-swap conversion is
therefore safe; no STOP condition (1) applies.

## 5. PostgreSQL 18 behaviour proof (Step A3, disposable `mtmf_pr19b_probe`)

The following were confirmed on a disposable MTMF-owned database created with
`CREATE DATABASE mtmf_pr19b_probe OWNER mtmf_owner` (never on the canonical
dev database):

1. **Row-level trigger propagation.** `BEFORE UPDATE`/`BEFORE DELETE` row
   triggers created on a partitioned parent are automatically cloned to
   existing and future partitions; direct child
   `UPDATE`/`DELETE` raise the guard.
2. **TRUNCATE is different.** A statement-level `BEFORE TRUNCATE` trigger on
   the parent fires for a parent `TRUNCATE`, but PostgreSQL does **not** clone
   it to partitions; a direct child `TRUNCATE` is unguarded unless each child
   carries its own `BEFORE TRUNCATE` trigger. PR 19B therefore creates the
   truncate guard explicitly on every child.
3. **Composite primary key.** `PRIMARY KEY (occurred_at, id)` on a parent
   partitioned by `RANGE (occurred_at)` is accepted and cloned (per-child
   index names differ). `id`-only uniqueness is not enforceable.
4. **Partition bounds.** `CREATE TABLE ... PARTITION OF ... FOR VALUES FROM
   (...) TO (...)` works with explicit timestamptz literals.
5. **Out-of-range fail-closed.** With no DEFAULT partition, an insert outside
   every range fails with SQLSTATE `23514` (`CheckViolation`, "no partition of
   relation ... found for row"); nothing is silently created.
6. **TZ independence.** `make_timestamptz(y, m, 1, 0, 0, 0, 'UTC')` produces
   the same instant under `SET TIME ZONE 'America/New_York'` and `'UTC'`.
   `pg_get_expr(relpartbound, oid)` rendering is session-timezone dependent, so
   the maintenance helper pins `TimeZone = 'UTC'` before comparing bounds.
7. **PL/pgSQL DDL rolls back** with the surrounding transaction.

## 6. Existing relevant test execution

- The merged `main` baseline is green per the PR 19C acceptance record
  (`docs/pr-artifacts/pr-19c/`), which reports the full integration suite.
- On the PR 19B working tree the PR 19C management, migration, migration
  privilege lifecycle, runtime privilege, runtime security, role assignment,
  and stored-function modules were executed and passed (`114 passed`), and the
  full canonical integration gate passed (`593 passed, 90 skipped`). See
  `PR19B_POSTGRES_ACCEPTANCE_REPORT.md`.
- The opt-in Keycloak/deployed-HTTP live suites were **not** run
  (`MTMF_PR19C_LIVE` / `MTMF_PR17_LIVE` unset); this is recorded as skipped,
  never as PASS. PR 19B changes only audit storage layout, not the deployed
  mutation path, so P13–P15 plus the canonical integration gate are the PR 19B
  feature acceptance and the live suite is an additional regression gate only.

## 7. Status classification carried into implementation

| Area | Baseline status |
|---|---|
| PR 19C audited write path | DONE + VERIFIED (retain/regress) |
| Audit table partitioning | NOT STARTED |
| Existing-row migration, boundary routing, privilege/guard inheritance, operational provisioning | NOT VERIFIED |

No STOP condition was encountered during baseline reconciliation.
