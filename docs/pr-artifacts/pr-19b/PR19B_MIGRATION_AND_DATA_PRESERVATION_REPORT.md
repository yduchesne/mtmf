# PR 19B — Migration and Data-Preservation Report

- **Revision:** `0013_security_mutation_audit_partitioning` (`down_revision = "0012"`)
- **Packaged resources:** `sql/v013/01..04` plus `__init__.py`
- **Downgrade:** none (upgrade-to-head only, consistent with the MTMF contract)
- **Base SHA:** `5979ddf8dca10f2b478a91cd141e6684294058f1`
- **PostgreSQL:** 18.6 (`180006`)

## 1. Conversion design

`01_security_mutation_audit_partition_migration.sql` runs as a single PL/pgSQL
`DO` block inside the Alembic revision transaction. Nothing is committed until
all of `01`–`04` succeed.

1. `SET LOCAL TimeZone = 'UTC'` for deterministic bound rendering and routing
   checks.
2. `LOCK TABLE mtmf.security_mutation_audit IN ACCESS EXCLUSIVE MODE`.
3. Record the old row count, UTC min/max, NULL-`occurred_at` count, duplicate
   `(occurred_at, id)` groups, and the historical UTC month span. The
   migration fails closed on NULL timestamps, duplicate keys, or a historical
   span **> 120** months (STOP policy); the span guard bounds the contiguous
   initial fill to at most 120 historical plus 13 current/future partitions.
4. Rename the v012 table to `security_mutation_audit_v012_backup` inside the
   transaction; drop the old primary key, the two secondary indexes, and the
   three old triggers so their names are free.
5. Create the partitioned parent with the exact 12 v012 columns/types/default
   and the three CHECK constraints, but `PRIMARY KEY (occurred_at, id)`,
   `PARTITION BY RANGE (occurred_at)`.
6. Create the two named parent indexes and the three parent append-only guard
   triggers using the existing `mtmf.guard_security_mutation_audit()` function.
7. Attach every represented historical UTC month plus the current UTC month and
   the next 12, with child names `security_mutation_audit_yYYYYmMM` and
   UTC-only bounds built with `make_timestamptz(..., 'UTC')`. Every child also
   gets its own `BEFORE TRUNCATE` guard and explicit owner/PUBLIC/runtime
   privilege normalization.
8. Copy every row with an **explicit** column list (never `SELECT *`, never
   `ON CONFLICT`).
9. Prove equality both directions with `EXCEPT ALL`, verify the copied count,
   verify no row is stored in the parent (`tableoid`), and verify every row is
   routed to its UTC month child.
10. Only then `DROP TABLE mtmf.security_mutation_audit_v012_backup` **without
    `CASCADE`**. A dependency failure aborts and rolls back the whole revision.

## 2. Data-preservation evidence (Step P02)

Executed on a disposable MTMF-owned database (`mtmf_pr19b_probe`), seeded at
revision `0012` with four valid audit rows spanning three UTC months including
leap-year February:

| Row | `occurred_at` (UTC) | Resulting partition |
|---|---|---|
| 1 | `2024-01-31T23:59:59.999+00` | `security_mutation_audit_y2024m01` |
| 2 | `2024-02-01T00:00:00+00` | `security_mutation_audit_y2024m02` |
| 3 | `2024-02-29T12:00:00+00` (leap day) | `security_mutation_audit_y2024m02` |
| 4 | `2024-03-01T00:00:00+00` | `security_mutation_audit_y2024m03` |

Whole-row aggregate equality (every one of the 12 columns, ordered by
`occurred_at, id`):

```
before (count, md5): (4, 'af90b34ea819b9bfd20d608d385f4119')
after  (count, md5): (4, 'af90b34ea819b9bfd20d608d385f4119')
equal: True
```

Original UUIDs and timestamps are preserved byte-for-byte (no provenance
rewrite, no re-identification). A sparse historical range is filled
month-by-month so every timestamp in the interval routes to a real partition;
after the upgrade the probe database held 46 attached partitions (2024-01
through 2027-10).

The integration test `test_p02_upgrade_from_0012_preserves_historical_rows`
asserts the full tuple list equality (`after == before`) and the original id
set, plus per-partition routing and zero parent-stored rows.

## 3. Rollback evidence (P16)

`test_p16_failed_conversion_restores_original_table` creates a dependent view
`mtmf.pr19b_probe_view AS SELECT * FROM mtmf.security_mutation_audit` on an
isolated `0012` fixture. The conversion reaches the final
`DROP TABLE ..._v012_backup` (no `CASCADE`) and fails. Assertions after the
failed `upgrade_to_head()`:

- `security_mutation_audit` is `relkind = 'r'` (still the original
  unpartitioned table);
- the full row snapshot equals the pre-migration snapshot;
- no `security_mutation_audit_v012_backup` table remains;
- `mtmf.alembic_version` is still `0012` (no committed half-swap).

No production failure-injection hook exists; the failure is created only in
the disposable test database via the dependent view.

## 4. Lock-contention evidence (P17)

`test_p17_upgrade_serializes_with_open_writer` opens a second connection,
inserts one v012 audit row, and holds the transaction open. The concurrent
`upgrade_to_head()` is confirmed to block on the migration's `ACCESS EXCLUSIVE`
lock (still unfinished after 1.5 s), then proceeds after the writer commits.
The committed row is present exactly once in the partitioned table afterwards.
No lost rows and no destructive action on a shared database.

## 5. Composite-key semantics

`id` is the application-generated per-attempt operation UUID, not a business
idempotency key. Revision `0013` changes the primary key from `(id)` to
`(occurred_at, id)`. PostgreSQL cannot enforce a partitioned UNIQUE/PK on `id`
alone. Consequences, all tested:

- identical `(occurred_at, id)` is rejected (`test_p03_duplicate_occurred_at_and_id_is_rejected`);
- the same `id` in two different UTC months is accepted at the database level
  (`test_p04_same_id_in_different_months_is_allowed`);
- `id` is **not** asserted to be globally unique and no secondary global-id
  ledger was added.

The PR 19C regression test
`test_db_h04_audit_conflict_rolls_back_the_membership` was adapted to pin the
server-assigned `occurred_at` default to a covered month so a deterministic
composite-key collision still proves whole-transaction rollback. This is a
direct consequence of the mandated key change and does not weaken any
documented invariant; `test_p15_audit_failure_after_membership_insert_rolls_back_both`
covers the same guarantee in PR 19B.

## 6. Shipped-resource immutability

No file under `sql/v001`–`sql/v012` or `migrations/versions/0001`–`0012` was
modified. Revision `0013` is purely additive. The append-only guard function
`mtmf.guard_security_mutation_audit()` and the verified membership-add writer
`mtmf.identity_group_membership_add_verified(...)` are unchanged.
