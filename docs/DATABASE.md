# MTMF PostgreSQL Database Architecture and Privilege Model

## 1. Status, authority, and scope

**Status: implemented in PR 7A (Alembic revision `0003`), hardened by PR 7A-1; verified by real-role integration tests.**

This document is the authoritative PostgreSQL-specific design for MTMF's database roles, grants, stored-function execution boundary, migrations, connection handling, and privilege verification. Sections 3-10 describe implemented controls exercised by `tests/integration/postgres/test_runtime_privileges.py` (PRIV-01..PRIV-20), `tests/integration/postgres/test_role_topology_security.py` (A1-01..A1-22), the existing membership-removal regression suite, and the canonical `./build.sh --qa`, `--sec`, and `--integration` gates. PR 7A-1 adds transitive role-topology verification, effective privilege verification, an authenticated migrator contract, and fresh/legacy privilege-matrix parity.

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

Migration ownership is deterministic: every migration connection (the plain-psycopg schema bootstrap/read and the SQLAlchemy Alembic connection) executes under `SET ROLE mtmf_owner`, so objects never default to the authenticating migrator login.

Provisioning validates the **effective** membership graph before and after mutation. A runtime login with **any** role membership (direct or transitive), or a migrator with any membership other than the intended `INHERIT FALSE, SET TRUE` owner grant, fails closed with the offending role path; provisioning never silently rewrites another role's memberships. `verify_role_topology` uses `pg_has_role` for effective `SET`/`USAGE`/`MEMBER` reachability as well as the direct `pg_auth_members` graph, because PostgreSQL role privileges are additive and a third-party grant can confer MTMF privileges even when no direct MTMF ACL row names runtime.

Authenticated migrator contract: `PostgresMigrationManager` accepts **only** `PostgresRole.MIGRATOR`. On every migration connection it verifies that `session_user` and `current_user` are `mtmf_migrator`, that the login is not superuser/`CREATEROLE`/`CREATEDB`/`BYPASSRLS`, and that it can `SET ROLE mtmf_owner` without inheriting (`USAGE`) owner privileges, **before** any `SET ROLE` or DDL. A configuration labelled `MIGRATOR` that authenticates as the administrator or runtime login is rejected. The administrator identity is reserved for provisioning and the ownership handoff.

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

### 6.4 Effective privilege verification

`mtmf_core.persistence.postgres.roles.verify_runtime_privileges` is a read-only, administrator-invoked check (also exposed as `scripts/mtmf-provision-roles.py --verify`) that runs after migration to head, for both fresh and legacy-handoff databases. It fails closed unless:

- the effective role topology is approved (see section 4);
- runtime has database `CONNECT` and schema `USAGE`, and no database/schema `CREATE`;
- runtime has no table/view/partition `SELECT`/`INSERT`/`UPDATE`/`DELETE`/`TRUNCATE`/`REFERENCES`/`TRIGGER` and no sequence `USAGE`/`SELECT`/`UPDATE`;
- runtime `EXECUTE` is exactly the six full removal signatures (compared by function identity, not count or a name pattern), with zero extra functions;
- no `PUBLIC` `EXECUTE` remains on MTMF functions and owner default privileges grant none;
- the Alembic migration table and the audit table are inaccessible.

Diagnostics name objects, privileges, and role paths but never credentials. Revision `0003`'s in-transaction assertions remain defense in depth, not the only check. A deliberate third-party grant (for example, runtime membership in a role with `SELECT` on `mtmf.tenant` or `EXECUTE` on an MTMF function) is detected even though the direct ACL does not name runtime.

`verify_runtime_privileges` is invoked **automatically** at the end of every successful `PostgresMigrationManager.upgrade_to_head()` (section 8), including already-head no-op upgrades. `scripts/mtmf-provision-roles.py --verify` is an additional read-only operator/CI diagnostic, not the only mandatory check.

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
- **Mandatory post-upgrade verification:** every successful `PostgresMigrationManager.upgrade_to_head()` opens a fresh connection authenticated as `mtmf_migrator`, verifies the identity, assumes `mtmf_owner` only through the authorized `SET ROLE`, and runs `verify_runtime_privileges` before returning. This runs for fresh installs, populated upgrades, and already-head no-op upgrades; it is not conditional on an Alembic revision change. No administrator credentials are required in the migration process.
- **Post-commit failure semantics:** if the postflight fails, `upgrade_to_head()` raises `MigrationError` explaining that the migration reached the Alembic stage and the mandatory post-upgrade runtime privilege verification failed, that migrations may already be committed, and that the operator must correct the discrepancy and rerun `upgrade_to_head()`. It never claims or attempts an automatic rollback/downgrade and never repairs grants automatically.

### 8.1 Lifecycle verification phases

| Phase | Topology preflight/postflight | Ownership postcondition | Full runtime privilege verifier |
|---|---|---|---|
| `provision_roles` (empty database) | Yes | n/a | **No** (schema/functions may not exist) |
| `adopt_existing_schema` | Yes (documented caller contract: roles provisioned first) | Yes | **No** (pre-head privileges may legitimately differ) |
| `upgrade_to_head` | Yes (migrator identity + legacy ownership preflight) | Yes (via `0003`) | **Yes, mandatory** |
| CLI `--verify` | Yes | n/a | Yes (read-only, optional; requires migrated schema) |

Legacy adoption does not demand head-level runtime ACLs before the upgrade. Provisioning an empty database runs topology checks only and must not require the `mtmf` schema, revision `0003`, or the six functions to exist.

## 9. Connection and deployment security

- Migration and runtime credentials are supplied through separate secrets (`MTMF_MIGRATOR_*`, `MTMF_RUNTIME_*`); the administrator security context uses `MTMF_POSTGRES_*` / `MTMF_DATABASE_URL`. Privileged credentials are never in application environment defaults and never committed.
- `PostgresConfig.from_env(PostgresRole)` reads explicitly role-scoped variables and fails closed on missing, malformed, or ambiguous configuration; it never falls back to another PostgreSQL instance.
- Runtime connection setup cannot escalate via role switching (`SET ROLE` is denied), untrusted `search_path`, unsafe extension installation, or object creation.
- In production, a runtime process receives **only** `MTMF_RUNTIME_*` credentials; `MTMF_POSTGRES_*` (administrator) and `MTMF_MIGRATOR_*` belong to provisioning/deployment contexts and must not be present in the application runtime environment. The integration CI job necessarily carries all three identities to create fixtures; that is a test-harness exception and does not establish production secret isolation.
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

### 10.1 PR 7A-1 role-topology and credential-boundary verification

`tests/integration/postgres/test_migration_privilege_lifecycle.py` implements I01..I14: the mandatory postflight runs on fresh and already-head upgrades; a contaminated table grant, unauthorized function `EXECUTE`, or hostile runtime membership makes an already-head no-op migration fail and recover after remediation; legacy adoption reaches the verified head posture without losing data/audit; the ownership postcondition names non-owner objects; and the CLI `--verify` is read-only and fails before head without auto-provisioning or migrating.

`tests/integration/postgres/test_role_topology_security.py` implements A1-01..A1-22 against real PostgreSQL 18 logins. It injects hostile direct and transitive memberships and third-party grants into uniquely named, disposable test roles, asserts fail-closed diagnostics (naming role paths, never credentials), and restores every grant/membership in a `finally` block. It also compares a normalized effective-privilege snapshot between a clean fresh `0001->0002->0003` install and a legacy `0002` ownership handoff, requiring equivalent security semantics (role attributes, direct memberships, ownership, runtime database/schema/table/sequence/function privileges, the EXECUTE allowlist, PUBLIC function ACLs, and owner default ACLs). No OIDs or generated identifiers are compared.

| ID | Scenario | Required outcome |
|---|---|---|
| A1-01 | Fresh provisioning repeated twice | Exact roles/attributes/membership; idempotent |
| A1-02 | Runtime direct membership in owner | Provisioning rejects before credential mutation |
| A1-03 | Runtime -> intermediate -> owner with `SET TRUE` | Fail closed; path identified |
| A1-04 | Runtime -> intermediate -> owner with `INHERIT TRUE` | Fail closed; effective owner rights rejected |
| A1-05 | Runtime -> unrelated role (no MTMF grants) | Fail closed per strict topology contract |
| A1-06 | Runtime -> unrelated role with MTMF `SELECT` grant | Fail closed; effective `SELECT` detected |
| A1-07 | Runtime -> unrelated role with MTMF function `EXECUTE` | Fail closed; extra signature detected |
| A1-08 | Migrator belongs to another role | Fail closed |
| A1-09 | Migrator -> owner incorrectly inherits | Normalized; `USAGE` false, `SET` true |
| A1-10 | Runtime `SET ROLE` owner/migrator | Both rejected by PostgreSQL |
| A1-11 | Migrator authenticated before `SET ROLE` | Identity matches; not elevated |
| A1-12 | `MIGRATOR`-labelled config with administrator credentials | Rejected before any DDL |
| A1-13 | `MIGRATOR`-labelled config with runtime credentials | Rejected before any DDL |
| A1-14 | `ADMIN`-labelled config attempts migration | Rejected; provisioning still supported |
| A1-15 | Alembic connection authenticates as wrong user | Rejected before migration DDL |
| A1-16 | Runtime effective privilege inventory | Exactly approved schema/function access |
| A1-17 | New owner-created function | Not PUBLIC/runtime executable by default |
| A1-18 | Clean fresh vs legacy handoff | Equivalent normalized privilege snapshots |
| A1-19 | Runtime removal/audit and rollback regression | Existing PR 7A tests still pass |
| A1-20 | Verification/provisioning error | Actionable, secret-free diagnostic |
| A1-21 | Contaminated topology with autocommit provisioning | Preflight failure leaves passwords unchanged; partial-effect limitation documented |
| A1-22 | Runtime-only deployment environment | Runtime config works alone; migration/provisioning cannot fall back |

## 11. Delivery sequence and acceptance

1. **Documentation (this document):** agree on roles, threat model, privilege matrix, function execution boundary, and testing contract.
2. **PR 7A (implemented):** role provisioning, migration/SQL revision `0003`, restricted runtime connectivity, grants, and real-role security tests.
3. **PR 7B:** implement production PostgreSQL repositories and UnitOfWork against that restricted runtime role.
4. **PR 10:** implement authoritative root/bootstrap and Tenant Stewardship protection and test it through the production write path.

PR 7A is complete when privileged migration access and restricted runtime access are operationally distinct, direct DML and audit bypass are denied under the runtime role, approved persistence operations succeed, and the privilege posture remains correct after subsequent migrations. PR 7B cannot claim security conformance until these real-role acceptance gates pass.

## 12. Residual trust limitations and open design decisions

- **Shared runtime login.** One runtime login is used for all Tenants. A compromised holder can invoke any granted function for any Tenant; per-Tenant isolation is not enforced at the database level. A trusted-identity/authentication design that binds authenticated acting-Identity context to stored-function calls without trusting caller-supplied IDs remains an explicit open decision.
- **Actor provenance is unverified.** `actor_identity_id` is provenance input, never authentication or Tenant authorization.
- **Administrators are trusted.** A superuser or another legitimate cluster administrator can always alter objects and triggers. The verification/`provision_roles` checks fail closed on an unsafe MTMF topology and refuse to silently rewrite unrelated roles, but they do not police arbitrary superuser accounts; that is an operational trust boundary.
- **Provisioning is not all-or-nothing.** It runs with `autocommit`; the preflight topology check happens before credential mutation, but a later SQL failure leaves earlier role/attribute/password changes in place. Operators review and re-run provisioning after remediation. `PRIV-21`/`A1-21` record the preflight-failure behavior.
- **Write entry points.** PR 7B must add reviewed read/write functions under the same default-deny model; the exact set and whether every entry point uses `SECURITY DEFINER` remains PR 7B scope.
- **Credential rotation.** Deployment/rotation of role credentials without exposing privileged credentials to startup remains an operational concern.
- **Defense in depth.** The membership-removal GUC marker remains but is not an authorization boundary.

Do not let a coding agent silently resolve these security architecture choices by convenience.
