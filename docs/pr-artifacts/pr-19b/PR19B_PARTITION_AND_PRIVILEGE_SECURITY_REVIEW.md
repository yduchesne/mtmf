# PR 19B — Partition and Privilege Security Review

- **Scope:** append-only posture, owner-only partition DDL, runtime confinement,
  and retention boundaries for revision `0013`.
- **Review date (UTC):** 2026-10-14
- **PostgreSQL:** 18.6 (`180006`), real `mtmf_owner` / `mtmf_migrator` /
  `mtmf_runtime` login identities.

## 1. Append-only invariant

`mtmf.security_mutation_audit` remains append-only. Revision `0013` does not
create a new guard function; it reuses `mtmf.guard_security_mutation_audit()`
(unchanged, `SECURITY INVOKER`, fixed `search_path = ''`, `ERRCODE = 'MT033'`).

Verified against the real owner-authorized connection and direct children:

| Operation | Target | Result |
|---|---|---|
| `UPDATE` | partitioned parent | SQLSTATE `MT033` |
| `DELETE` | partitioned parent | SQLSTATE `MT033` |
| `TRUNCATE` | partitioned parent | SQLSTATE `MT033` |
| `UPDATE` | direct child | SQLSTATE `MT033` |
| `DELETE` | direct child | SQLSTATE `MT033` |
| `TRUNCATE` | direct child | SQLSTATE `MT033` |

`BEFORE UPDATE`/`BEFORE DELETE` row triggers are cloned to partitions by
PostgreSQL. Statement-level `BEFORE TRUNCATE` triggers are **not** cloned; the
migration and `ensure_security_mutation_audit_month` create a per-child
truncate guard so a direct child `TRUNCATE` cannot bypass the invariant. The
migration assertion verifies that every child carries all three guards, and
the runtime test verifies the parent/child behaviour on real PostgreSQL 18.

## 2. Partition provisioning helper

`mtmf.ensure_security_mutation_audit_month(p_month date) RETURNS void`

| Property | Value |
|---|---|
| Owner | `mtmf_owner` |
| Security | `SECURITY INVOKER` |
| `search_path` | `''` (fixed) |
| `PUBLIC` EXECUTE | revoked |
| `mtmf_runtime` EXECUTE | revoked |
| Dynamic SQL | only `%I`-quoted identifiers and `%L`/`sql.Literal`-quoted values from a validated month; no caller-supplied SQL fragment or table name |
| Concurrency | `pg_advisory_xact_lock(namespace=1297362758, ordinal=year*12+month)` acquired before state inspection |
| Bound construction | `make_timestamptz(..., 'UTC')` and `date`-based next-month arithmetic, independent of session `TimeZone` |
| Idempotency | existing correctly attached child with exact bounds → `RETURN` (no DDL) |
| Wrong object | same-named non-partition or wrongly bounded object → raise `55000`; never silently accept or replace |
| Overlap / DEFAULT | never creates overlapping bounds and never a DEFAULT partition |
| Retention | no `DROP`, `DETACH`, `TRUNCATE`, or deletion path |

Manual behavior probe (privileged owner connection):

| Input | Result |
|---|---|
| existing current month | no-op (`OK`) |
| missing future month | creates exactly one child (`OK`) |
| repeat same month | no-op (`OK`) |
| `NULL` | `22023` |
| non-first-of-month | `22023` |
| `9999-12-01` (next month would overflow) | `22023` |
| same-named unrelated table | `55000`, decoy untouched, not attached |

`test_p10_concurrent_ensure_creates_exactly_one_partition` runs two independent
owner connections with a barrier; both report success and exactly one
correctly attached partition exists.

## 3. Runtime confinement

Verified with the actual restricted `mtmf_runtime` login (never `SET ROLE` from
an owner session):

- `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE` on the parent → `42501`;
- `EXECUTE mtmf.ensure_security_mutation_audit_month(date)` → `42501`;
- the two reviewed PR 19C writer functions remain executable;
- the legacy `mtmf.identity_group_membership_add(uuid, uuid)` remains revoked;
- the effective runtime EXECUTE set equals `expected_runtime_signatures()`
  exactly (**78** signatures), and `verify_runtime_privileges` passes.

`mtmf_runtime` and `PUBLIC` hold no `SELECT`/`INSERT`/`UPDATE`/`DELETE`/
`TRUNCATE`/`REFERENCES`/`TRIGGER` privilege on the parent or any child. The
migration assertion re-checks this on the catalog, and the mandatory
post-upgrade verifier includes partitioned relations (`relkind IN ('r','p',
'v','m')`).

## 4. Fixed horizon and retention

- The migration attaches the current UTC month plus the following 12 months
  (13 months when there is no history). A write beyond the horizon fails with
  SQLSTATE `23514` and rolls back the calling transaction — no DEFAULT
  partition, no runtime auto-DDL.
- There is no automatic deletion, `DETACH`, `DROP`, TTL, or default retention
  period. Audit partitions are immutable evidence. Removing a partition
  requires a separately approved retention/legal policy and an explicit
  operator action.
- The 12-month horizon is an operator buffer. `docs/DATABASE.md` section 13
  defines the monthly privileged runbook and checklist.

## 5. Boundary disposition

- No new production HTTP route, Role, Action, Permission, runtime stored
  function grant, migration downgrade, or change to the verified membership-add
  writer.
- No cross-tenant analytics API and no cross-partition global `id` registry.
- PR 19D and auditing additional mutations remain out of scope.

No privilege or append-only STOP condition was encountered.
