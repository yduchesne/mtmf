# MTMF PostgreSQL Database Architecture and Privilege Model

## 1. Status, authority, and scope

**Status: implemented in PR 7A (Alembic revision `0003`); verified by real-role integration tests.**

This document is the authoritative PostgreSQL-specific design for MTMF's database roles, grants, stored-function execution boundary, migrations, connection handling, and privilege verification. Sections 3-10 describe implemented controls exercised by `tests/integration/postgres/test_runtime_privileges.py` (PRIV-01..PRIV-20), the existing membership-removal regression suite, and the canonical `./build.sh --qa`, `--sec`, and `--integration` gates.

Normative security invariants remain in [SECURITY_MODEL.md](SECURITY_MODEL.md); domain semantics in [DOMAIN_MODEL.md](DOMAIN_MODEL.md); application authorization in [AUTHORIZATION.md](AUTHORIZATION.md); component boundaries in [ARCHITECTURE.md](ARCHITECTURE.md). If this document conflicts with the security constitution, **SECURITY_MODEL.md wins**.

The PostgreSQL provider is an internal implementation of MTMF's persistence SPI. MTMF application code uses versioned stored functions for database operations; migrations are owned by the MTMF migration manager, not the runtime application identity.

## 2. Transition history (pre-PR 7A) and what replaced it

Before PR 7A, the schema and migrations operated under a single trusted database role; there was no separate restricted runtime role. The six membership removal functions were `SECURITY INVOKER` with `SET search_path = ''`, functions carried PostgreSQL's default `PUBLIC EXECUTE`, membership tables had no explicit grants (so only the owner held DML), and the membership DELETE/TRUNCATE triggers checked a transaction-local `mtmf.membership_removal` marker that a SQL-capable caller could forge. That posture was a transitional development assumption, not a production-ready privilege model, and it is no longer the operating model.

PR 7A (revision `0003`) replaced it with a demonstrably restricted runtime login, reviewed privileged entry points, and migration credentials isolated from runtime:

- `mtmf_owner` owns the `mtmf` schema and every MTMF object;
- `mtmf_migrator` runs migrations by `SET ROLE mtmf_owner` (INHERIT FALSE);
- `mtmf_runtime` has schema `USAGE` and `EXECUTE` on exactly the six approved removal signatures, with no direct table/sequence DML/SELECT, no schema CREATE, no audit write, no trigger or migration access, and no membership in owner/migrator;
- the six removal functions are owner-owned `SECURITY DEFINER` entry points with fixed `search_path = ''` and schema-qualified bodies;
- the transaction-local marker remains only as defense in depth; the enforced boundary is the runtime role's inability to issue direct DML.

The marker is still **not** an authorization boundary against a role able to run arbitrary SQL, and `SECURITY DEFINER` EXECUTE is database capability, not domain authorization (sections 6-7).

## 3. Implemented security invariants (PR 7A)

1. The application connects using a **non-owner, non-superuser, non-CREATEROLE, non-BYPASSRLS** runtime login with no schema creation, table mutation, trigger-management, or role-escalation privileges.
2. Runtime callers can invoke **only explicitly approved MTMF functions**. They cannot directly INSERT, UPDATE, DELETE, TRUNCATE, or otherwise mutate MTMF authoritative tables or audit tables.
3. Privileged writes occur only inside reviewed, narrowly scoped stored functions; no general-purpose arbitrary-SQL execution function is exposed.
4. A successful membership removal atomically performs its prescribed cascade and inserts exactly one operation-level audit row. Runtime callers cannot bypass either step or manufacture audit rows.
5. Migrations run with separate credentials, under controlled deployment operations; runtime credentials cannot migrate schema or grant themselves permissions.
6. MTMF authorization remains deny-by-default and Tenant-scoped. **SQL EXECUTE privilege is not a substitute for domain authorization**: application use cases must authorize the acting Identity, and security-critical invariants must be enforced at the appropriate trusted write boundary.
7. All PostgreSQL operations remain scoped to the MTMF-owned database/schema. Local Podman/Compose resources remain isolated from unrelated projects.

## 4. Roles, ownership, and bootstrap

| Role | LOGIN | Owns schema/tables | Primary use | Restrictions |
|---|---|---|---|---|
| `mtmf_owner` | NOLOGIN | Yes | Own MTMF schema, tables, functions, and audit | Not used for application connections |
| `mtmf_migrator` | LOGIN (deployment only) | No direct ownership; may `SET ROLE mtmf_owner` (`INHERIT FALSE`, `SET TRUE`) | Apply packaged Alembic revisions and grants | Credentials absent from application runtime |
| `mtmf_runtime` | LOGIN | No | Execute approved application stored functions | No direct table DML/DDL, no membership in owner/migrator roles |
| PostgreSQL administrator | Deployment-specific | Administrative | Provision roles/database and emergency recovery | Not used by MTMF application |

Roles are cluster-wide and are provisioned **outside** Alembic by an administrator-invoked, idempotent operation:

```text
uv run python scripts/mtmf-provision-roles.py
uv run python scripts/mtmf-provision-roles.py --adopt-existing-schema  # legacy handoff
```

`scripts/mtmf-provision-roles.py` reads the administrator connection from `MTMF_POSTGRES_*` / `MTMF_DATABASE_URL`, reads the deployment passwords from `MTMF_MIGRATOR_POSTGRES_PASSWORD` / `MTMF_RUNTIME_POSTGRES_PASSWORD`, and never logs a DSN. The shared implementation lives in `mtmf_core.persistence.postgres.roles`. Re-running it never errors or escalates rights. `mtmf_owner` alone receives database-level `CREATE` (it creates the `mtmf` schema); the runtime role receives none.

`--adopt-existing-schema` is the one-time administrator-approved ownership handoff for a database whose `mtmf` objects predate this model; it only touches objects inside the `mtmf` schema. Without it, `PostgresMigrationManager.upgrade_to_head` fails loudly before Alembic runs with an actionable message listing the non-owner objects (revision `0003` repeats the assertion as defense in depth), rather than silently reassigning ownership.

Migration ownership is deterministic: every migration connection (the plain-psycopg schema bootstrap and the SQLAlchemy Alembic connection) executes under `SET ROLE mtmf_owner`, so objects never default to the authenticating migrator login. `PostgresMigrationManager` rejects a configuration carrying the runtime role.

## 5. Privilege matrix

| Object / operation | Owner | Migrator (controlled deployment) | Runtime |
|---|---|---|---|
| `mtmf` schema USAGE | Yes | Yes | Yes |
| `mtmf` schema CREATE / ALTER / DROP | Yes | Via controlled owner role | **No** |
| MTMF table SELECT | Yes | Via controlled owner role | **No** |
| MTMF table INSERT / UPDATE / DELETE / TRUNCATE | Yes | Via controlled owner role | **No** |
| MTMF sequences USAGE / UPDATE | Yes | Via controlled owner role | **No** |
| Approved application function EXECUTE | Yes | Via controlled owner role | **Explicit allowlist only** |
| Internal trigger/helper function EXECUTE | Yes | Via controlled owner role | **No** |
| Audit table direct INSERT / UPDATE / DELETE / TRUNCATE | Yes | Via controlled owner role | **No** |
| Schema migration and Alembic version changes | Yes | Yes, controlled | **No** |
| Trigger disable, table ownership changes, arbitrary grants | Owner/admin | Controlled deployment | **No** |

Runtime reads use reviewed read functions in future PRs, not broad table SELECT grants, consistent with MTMF's stored-function-only persistence convention.

## 6. Function execution and ownership

### 6.1 Default-deny grants

- `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA mtmf FROM PUBLIC` removes existing PUBLIC grants.
- `ALTER DEFAULT PRIVILEGES FOR ROLE mtmf_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC` sets owner-global default privileges so newly created functions are not automatically executable by `PUBLIC`. A schema-scoped `ALTER DEFAULT PRIVILEGES` cannot negate the built-in global PUBLIC default, so the global form is required; both global and schema-scoped revokes are applied.
- Only the six public persistence entry-point signatures are granted `EXECUTE` to `mtmf_runtime`; internal functions are not granted merely because they live in `mtmf`.
- Runtime holds no schema CREATE, table DML, sequence write, or owner-role membership.
- Function privileges are signature-specific; grants enumerate the exact `(uuid, uuid, uuid)` removal signatures, and default-argument invocations resolve to those signatures.
- Revision `0003` asserts effective privileges (via `has_*_privilege` and `aclexplode`) inside the migration transaction and rolls back if the intended posture is not achieved.

### 6.2 SECURITY DEFINER boundary

The six membership-removal functions are converted to owner-owned `SECURITY DEFINER` entry points by revision `0003` (their bodies and `SET search_path = ''` are unchanged). Each:

- uses `SET search_path = ''` and schema-qualifies every referenced table, function, and type;
- uses no dynamic SQL and no caller-controllable object names;
- derives Tenant scope from authoritative entity rows (`organization.tenant_id`, `group.tenant_id`) rather than trusting a caller Tenant alone;
- preserves its row locks, cascade, actual affected-row counts, no-op semantics, and single atomic audit insert;
- has PUBLIC EXECUTE revoked before the runtime grant is issued.

No generic mutation, trigger-control, GUC-setting, or audit-insertion entry point is exposed. The function caller owns the transaction; no function commits independently.

`SECURITY DEFINER` elevates database permissions, **not application authorization**. Merely accepting an `actor_identity_id` parameter is not proof that the actor is authenticated or authorized (section 7).

### 6.3 Audit and removal functions

The six membership-removal entry points remain the supported deletion surface. They retain row locking, Tenant-scoped cascades, actual affected-row counts, no-op semantics, and one atomic audit insertion.

The transaction-local marker remains as **defense in depth**. The enforced boundary is that runtime cannot issue direct table DELETE/TRUNCATE or insert into audit tables; a forced marker still cannot bypass the privilege check. Tests exercise this with the actual runtime login, not with an owner connection (PRIV-06).

The migration/owner/admin roles are outside that adversarial guarantee; they require separate operational controls and audit.

## 7. Tenant isolation and authorization boundaries

- Domain authorization uses the acting Identity and active `(Tenant, Principal, Identity)` session; it is enforced by MTMF's authoritative Authorizer.
- Database stored functions enforce structural invariants and cross-Tenant constraints. They do not trust a caller-supplied Tenant when authoritative ownership data is available.
- A restricted runtime role shared across Tenants does **not** itself provide per-Tenant SQL isolation. A compromised holder of the shared runtime credential can invoke any granted function, so PR 7A does **not** claim per-Tenant protection at the database level (PRIV-14 is an explicit boundary-disclosure test).
- Row-level security, per-Tenant database roles, and authenticated database session identity are **not** implemented.
- PR 10 remains responsible for root/bootstrap and Tenant Stewardship semantics; no protected principal is inferred from names, UUIDs, or ownership fields.

## 8. Migration and default-privilege lifecycle

- Versioned SQL resources under `mtmf_core/persistence/postgres/sql/vNNN/` are installed through packaged Alembic revisions. Shipped `v001`, `v002`, and revisions `0001`/`0002` are never rewritten.
- Revision `0003` is additive: it normalizes ownership, revokes PUBLIC/runtime grants, sets default privileges, converts the six removal functions, grants runtime EXECUTE on exactly those signatures, and asserts the posture.
- Every migration creates objects under the owner role (via `SET ROLE`), revokes PUBLIC privileges, and applies explicit runtime grants.
- `ALTER DEFAULT PRIVILEGES` is scoped to the object-creating role; because all DDL runs as `mtmf_owner`, owner-scoped defaults cover every future MTMF object. Future grant changes are explicit migration responsibilities.
- Migration and runtime connection configurations are distinct. Application startup never silently migrates with privileged credentials.
- No migration discards authoritative Tenant, Principal, Identity, Group, Organization, membership, or audit data; upgrade-to-head is idempotent and preserves data.
- PostgreSQL DDL is transactional; the migration assertions roll back the whole revision on failure. Role provisioning is a separate, idempotent, non-Alembic administrator step.

## 9. Connection and deployment security

- Migration and runtime credentials are supplied through separate secrets (`MTMF_MIGRATOR_*`, `MTMF_RUNTIME_*`); the administrator security context uses `MTMF_POSTGRES_*` / `MTMF_DATABASE_URL`. Privileged credentials are never in application environment defaults and never committed.
- `PostgresConfig.from_env(PostgresRole)` reads explicitly role-scoped variables and fails closed on missing, malformed, or ambiguous configuration; it never falls back to another PostgreSQL instance.
- Runtime connection setup cannot escalate via role switching (`SET ROLE` is denied), untrusted `search_path`, unsafe extension installation, or object creation.
- Integration CI provisions temporary privileged roles to set up the database, but **the privilege-test subject connects as `mtmf_runtime`** and the fixture fails setup if the identity is elevated or a superuser.
- Local Compose/Podman setup retains MTMF resource isolation and the configured host-port prefix-2 convention.

## 10. Verification

`tests/integration/postgres/test_runtime_privileges.py` implements PRIV-01..PRIV-20 on the actual runtime login, asserting effective privileges (`has_table_privilege`, `has_sequence_privilege`, `has_function_privilege`, `has_schema_privilege`, `aclexplode`, role membership, `prosecdef`, and function/table ownership) as well as real SQL behavior. The existing membership removal, audit, concurrency, transaction, schema, and migration suites remain the behavioral regression baseline and now run on a migrations/owner-created schema.

| ID | Test using real PostgreSQL roles | Expected |
|---|---|---|
| PRIV-01 | Runtime attempts direct INSERT/UPDATE/DELETE/TRUNCATE on each membership table | Permission denied |
| PRIV-02 | Runtime attempts direct INSERT/UPDATE/DELETE/TRUNCATE on audit | Permission denied |
| PRIV-03 | Runtime invokes each approved membership removal entry point | Succeeds with prescribed cascade/leaf semantics and exactly one audit |
| PRIV-04 | Runtime invokes an internal helper/trigger function directly | Permission denied |
| PRIV-05 | Runtime invokes unapproved function or attempts arbitrary schema DDL | Permission denied |
| PRIV-06 | Runtime sets `mtmf.membership_removal=on` then attempts direct DELETE | Permission denied |
| PRIV-07 | Runtime attempts `SET ROLE mtmf_owner` or `mtmf_migrator` | Permission denied |
| PRIV-08 | Runtime queries/updates Alembic version table or disables triggers | Permission denied |
| PRIV-09 | Owner creates a new function without an explicit grant | Not PUBLIC executable; runtime denied; explicit grant works |
| PRIV-10 | Audit insert fails during approved removal | Whole removal rolls back |
| PRIV-11 | Runtime tries cross-Tenant or malformed membership operations | Documented no-op; no cross-Tenant deletion |
| PRIV-12 | Concurrent duplicate removals through restricted role | One removal and one audit |
| PRIV-13 | Runtime attempts table SELECT or sequence use without grants | Permission denied |
| PRIV-14 | Runtime supplies a fabricated `actor_identity_id` | Audit records the unverified caller assertion; no authentication/authorization claim |
| PRIV-15 | Introspect every owner, effective privilege, and `prosecdef` | Exactly the documented posture |
| PRIV-16 | Populated re-run of `upgrade_to_head` | Data/audit preserved; revision `0003`; no permission drift |
| PRIV-17 | Runtime config supplied to migration manager | Rejected; no schema mutation |
| PRIV-18 | New owner-created function after default-privilege setup | No PUBLIC EXECUTE without explicit grant |
| PRIV-19 | Non-owner, non-runtime login attempts an approved function | Denied |
| PRIV-20 | Runtime attempts GRANT, ALTER FUNCTION, CREATE FUNCTION, trigger disable, audit spoof | Denied |

A test that merely inspects missing ACLs does not prove effective denial. Run the normal QA and PostgreSQL integration gates without weakening thresholds.

## 11. Delivery sequence and acceptance

1. **Documentation (this document):** agree on roles, threat model, privilege matrix, function execution boundary, and testing contract.
2. **PR 7A (implemented):** role provisioning, migration/SQL revision `0003`, restricted runtime connectivity, grants, and real-role security tests.
3. **PR 7B:** implement production PostgreSQL repositories and UnitOfWork against that restricted runtime role.
4. **PR 10:** implement authoritative root/bootstrap and Tenant Stewardship protection and test it through the production write path.

PR 7A is complete when privileged migration access and restricted runtime access are operationally distinct, direct DML and audit bypass are denied under the runtime role, approved persistence operations succeed, and the privilege posture remains correct after subsequent migrations. PR 7B cannot claim security conformance until these real-role acceptance gates pass.

## 12. Residual trust limitations and open design decisions

- **Shared runtime login.** One runtime login is used for all Tenants. A compromised holder can invoke any granted function for any Tenant; per-Tenant isolation is not enforced at the database level. A trusted-identity/authentication design that binds authenticated acting-Identity context to stored-function calls without trusting caller-supplied IDs remains an explicit open decision.
- **Actor provenance is unverified.** `actor_identity_id` is provenance input, never authentication or Tenant authorization.
- **Write entry points.** PR 7B must add reviewed read/write functions under the same default-deny model; the exact set and whether every entry point uses `SECURITY DEFINER` remains PR 7B scope.
- **Credential rotation.** Deployment/rotation of role credentials without exposing privileged credentials to startup remains an operational concern.
- **Defense in depth.** The membership-removal GUC marker remains but is not an authorization boundary.

Do not let a coding agent silently resolve these security architecture choices by convenience.
