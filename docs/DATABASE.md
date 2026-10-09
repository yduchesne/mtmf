# MTMF PostgreSQL Database Architecture and Privilege Model

## 1. Status, authority, and scope

**Status: proposed target architecture for PR 7A; not yet implemented.**

This document is the authoritative PostgreSQL-specific design for MTMF's database roles, grants, stored-function execution boundary, migrations, connection handling, and privilege verification. It does **not** assert that these controls already exist.

Normative security invariants remain in [SECURITY_MODEL.md](SECURITY_MODEL.md); domain semantics in [DOMAIN_MODEL.md](DOMAIN_MODEL.md); application authorization in [AUTHORIZATION.md](AUTHORIZATION.md); component boundaries in [ARCHITECTURE.md](ARCHITECTURE.md). If this document conflicts with the security constitution, **SECURITY_MODEL.md wins**.

The PostgreSQL provider is an internal implementation of MTMF's persistence SPI. MTMF application code uses versioned stored functions for database operations; migrations are owned by the MTMF migration manager, not the runtime application identity.

## 2. Current implementation and known gaps (PR 6B / 6B1)

As of the PR 6B/6B1 implementation on `dev/db-adjustments` (not yet incorporated into `main` at the time this document was authored):

- Schema and migrations operate under a single trusted database role; there is no separate restricted runtime role.
- Six membership removal functions use `SECURITY INVOKER` and `SET search_path = ''`.
- Functions have no explicit ACLs, leaving PostgreSQL's default `PUBLIC EXECUTE` behavior in effect.
- Membership tables have no explicit grants; the owner can directly mutate them.
- Membership DELETE and TRUNCATE triggers check the transaction-local `mtmf.membership_removal` marker. A SQL-capable caller can set this custom GUC, so it is **not** an adversarial authorization boundary.
- An append-only audit trigger blocks ordinary UPDATE/DELETE/TRUNCATE, but a privileged table owner or superuser can disable triggers; a role with INSERT can forge audit records.
- Root/bootstrap and Tenant Stewardship protection is **not** enforced by these structural removal functions; PR 10 must add authoritative state and protection.

**Never describe the current marker-based guard as a security boundary against arbitrary SQL.** The current operating assumption is that unrestricted SQL is available only to trusted persistence code. This is a transitional development posture, not a production-ready privilege model.

## 3. Target security invariants (PR 7A)

1. The application connects using a **non-owner, non-superuser, non-CREATEROLE, non-BYPASSRLS** runtime login with no schema creation, table mutation, trigger-management, or role-escalation privileges.
2. Runtime callers can invoke **only explicitly approved MTMF functions**. They cannot directly INSERT, UPDATE, DELETE, TRUNCATE, or otherwise mutate MTMF authoritative tables or audit tables.
3. Privileged writes occur only inside reviewed, narrowly scoped stored functions; no general-purpose arbitrary-SQL execution function is exposed.
4. A successful membership removal atomically performs its prescribed cascade and inserts exactly one operation-level audit row. Runtime callers cannot bypass either step or manufacture audit rows.
5. Migrations run with separate credentials, under controlled deployment operations; runtime credentials cannot migrate schema or grant themselves permissions.
6. MTMF authorization remains deny-by-default and Tenant-scoped. **SQL EXECUTE privilege is not a substitute for domain authorization**: application use cases must authorize the acting Identity, and security-critical invariants must be enforced at the appropriate trusted write boundary.
7. All PostgreSQL operations remain scoped to the MTMF-owned database/schema. Local Podman/Compose resources remain isolated from unrelated projects.

## 4. Roles and ownership

| Role | LOGIN | Owns schema/tables | Primary use | Restrictions |
|---|---|---|---|---|
| `mtmf_owner` | NOLOGIN (preferred) | Yes | Own MTMF schema, tables, functions, and audit | Not used for application connections |
| `mtmf_migrator` | LOGIN (deployment only) | No direct ownership required; controlled ability to `SET ROLE mtmf_owner` | Apply packaged Alembic revisions and grants | Credentials absent from application runtime |
| `mtmf_runtime` | LOGIN | No | Execute approved application stored functions | No direct table DML/DDL, no membership in owner/migrator roles |
| PostgreSQL administrator | Deployment-specific | Administrative | Provision roles/database and emergency recovery | Not used by MTMF application |

These are **logical role names**; deployment may namespace them. PR 7A must explicitly settle and test PostgreSQL's role membership and `SET ROLE` semantics for the chosen PostgreSQL 18 configuration. `mtmf_owner` should own security-definer functions; `mtmf_runtime` must never inherit or assume that owner role.

Migration ownership must be deterministic: avoid object ownership accidentally defaulting to `mtmf_migrator` when the intended owner is `mtmf_owner`. Bootstrap role creation may require an administrator and must not be attempted by an ordinary runtime process.

## 5. Target privilege matrix

| Object / operation | Owner | Migrator (controlled deployment) | Runtime |
|---|---|---|---|
| `mtmf` schema USAGE | Yes | Yes | Yes |
| `mtmf` schema CREATE / ALTER / DROP | Yes | Via controlled owner role | **No** |
| MTMF table SELECT | Yes | Via controlled owner role | **No by default** |
| MTMF table INSERT / UPDATE / DELETE / TRUNCATE | Yes | Via controlled owner role | **No** |
| MTMF sequences USAGE / UPDATE | Yes | Via controlled owner role | **No by default** |
| Approved application function EXECUTE | Yes | Via controlled owner role | **Explicit allowlist only** |
| Internal trigger/helper function EXECUTE | Yes | Via controlled owner role | **No** |
| Audit table direct INSERT / UPDATE / DELETE / TRUNCATE | Yes | Via controlled owner role | **No** |
| Schema migration and Alembic version changes | Yes | Yes, controlled | **No** |
| Trigger disable, table ownership changes, arbitrary grants | Owner/admin | Controlled deployment | **No** |

Runtime reads should use reviewed read functions, not broad table SELECT grants, consistent with MTMF's stored-function-only persistence convention. If PR 7A identifies a required exception, it must be justified, documented, and covered by tests before approval.

## 6. Function execution and ownership

### 6.1 Default-deny grants

- Revoke `EXECUTE ON ALL FUNCTIONS IN SCHEMA mtmf FROM PUBLIC` for existing functions and set **default privileges for each object-creating role** so newly created functions are not automatically executable by `PUBLIC`.
- Grant `EXECUTE` on an **enumerated set of public persistence entry-point signatures** to `mtmf_runtime`; internal functions are not granted merely because they live in `mtmf`.
- Do not grant schema CREATE, table DML, sequence write, or membership in the owner role to runtime.
- Account for overloads and default arguments when enumerating signatures: PostgreSQL function privileges are signature-specific.
- Review grants on every migration and assert effective privileges, not merely the presence/absence of ACL text.

### 6.2 SECURITY DEFINER boundary

Current membership functions are `SECURITY INVOKER`; revoking table DELETE from runtime would break them. PR 7A must deliberately establish a privileged execution boundary, normally by converting approved write entry points to tightly reviewed `SECURITY DEFINER` functions owned by `mtmf_owner`, or by another demonstrably equivalent least-privilege design.

For each `SECURITY DEFINER` function:

- Use `SET search_path = ''` and schema-qualify every referenced table, function, type, and sequence as applicable.
- Do not use untrusted dynamic SQL or caller-controllable object names.
- Keep function scope narrow and input validation explicit; derive Tenant from authoritative rows.
- Review any nested function calls and object resolution for privilege escalation.
- Revoke default PUBLIC EXECUTE before exposing the function; explicitly grant only approved signatures.
- Do not expose generic mutation, trigger-control, GUC-setting, or audit-insertion entry points.
- Preserve transaction ownership by the caller: the function must not independently commit.
- Audit any changes to function ownership or execution rights as part of migration review.

`SECURITY DEFINER` elevates database permissions, **not application authorization**. PR 7A must decide whether a function is safe to expose to any holder of runtime credentials or must require additional trusted context/authorization. Merely accepting an `actor_identity_id` parameter is not proof that the actor is authenticated or authorized. If the design cannot enforce the necessary trust boundary, **STOP** rather than treating function EXECUTE as an authorization decision.

### 6.3 Audit and removal functions

The six membership-removal entry points remain the supported deletion surface. They must retain row locking, Tenant-scoped cascades, actual affected-row counts, no-op semantics, and one atomic audit insertion.

The transaction-local marker may remain as **defense in depth**, but the enforced boundary must be runtime's inability to issue direct table DELETE/TRUNCATE or insert into audit tables. Test this with the actual runtime login, not with an owner connection. An attacker able to issue arbitrary SQL using runtime credentials must still be unable to bypass the audited removal functions.

The migration/owner/admin roles are outside that adversarial guarantee; they require separate operational controls and audit.

## 7. Tenant isolation and authorization boundaries

- Domain authorization uses the acting Identity and active `(Tenant, Principal, Identity)` session; it is enforced by MTMF's authoritative Authorizer.
- Database stored functions enforce structural invariants and cross-Tenant constraints. They must not trust a caller-supplied Tenant when authoritative ownership data is available.
- A restricted runtime role shared across Tenants does **not** itself provide per-Tenant SQL isolation. A compromised runtime credential can invoke any granted function unless the function or trusted caller context enforces a narrower boundary.
- Do not claim row-level security (RLS), per-Tenant database roles, or authenticated database session identity is implemented unless a separate approved design actually introduces it.
- PR 10 remains responsible for root/bootstrap and Tenant Stewardship semantics; do not infer protected principals from names, UUIDs, or ownership fields.

## 8. Migration and default-privilege lifecycle

- Versioned SQL resources under `mtmf_core/persistence/postgres/sql/vNNN/` are installed through packaged Alembic revisions. Do not rewrite shipped `v001`, `v002`, or `0001`/ `0002` revisions to retrofit security.
- PR 7A introduces a new additive migration and versioned SQL where appropriate, with a repeatable owner/grant bootstrap procedure.
- Ensure every migration creates objects under the intended owner role, revokes PUBLIC privileges, and applies explicit runtime grants.
- PostgreSQL `ALTER DEFAULT PRIVILEGES` is scoped to the object-creating role; test it under the actual migration role-switching flow.
- Migration and runtime connection configurations must be distinct. An application startup must not silently migrate with privileged credentials.
- No migration may discard authoritative Tenant, Principal, Identity, Group, Organization, membership, or audit data.
- Rollback/retry failures must not leave a partially applied privilege posture; document PostgreSQL transactional DDL and any nontransactional bootstrap steps.

## 9. Connection and deployment security

- Supply migration and runtime credentials through separate secrets; never commit passwords or put privileged credentials in application environment defaults.
- Prefer least-privilege login roles, TLS as appropriate to deployment, bounded connection pools, and explicit connection timeout settings.
- Runtime connection setup must not permit privilege escalation via role switching, untrusted `search_path`, unsafe extension installation, or object creation.
- Integration CI may provision temporary privileged roles to set up the database, but **the test subject must connect as `mtmf_runtime`**.
- Local Compose/Podman setup must retain MTMF resource isolation and configured host-port conventions; CI PostgreSQL service port may differ from local host ports.

## 10. Required PR 7A verification

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
| PRIV-09 | Fresh migration creates a new function | Not PUBLIC executable; only explicitly approved grants work |
| PRIV-10 | Audit insert fails during approved removal | Whole removal rolls back |
| PRIV-11 | Runtime tries cross-Tenant or malformed membership operations | Structural rules fail closed |
| PRIV-12 | Concurrent duplicate removals through restricted role | At most one removal and one audit |
| PRIV-13 | Runtime attempts table SELECT or sequence use without grants | Permission denied |
| PRIV-14 | Caller spoofs an actor Identity or Tenant | No unauthorized domain action; test at the correct trusted application boundary |

Tests must introspect `has_table_privilege`, `has_function_privilege`, role membership, function owner/`prosecdef`, schema privileges, and actual behavior. A test that merely inspects missing ACLs does **not** prove effective denial. Run the normal QA and PostgreSQL integration gates without weakening thresholds.

## 11. Delivery sequence and acceptance

1. **Documentation PR (this document):** agree on roles, threat model, privilege matrix, function execution boundary, and testing contract.
2. **PR 7A:** implement role provisioning, new migration/SQL, restricted runtime connectivity, grants, and real-role security tests.
3. **PR 7B:** implement production PostgreSQL repositories and UnitOfWork against that restricted runtime role.
4. **PR 10:** implement authoritative root/bootstrap and Tenant Stewardship protection and test it through the production write path.

PR 7A is not complete until privileged migration access and restricted runtime access are operationally distinct, direct DML and audit bypass are denied under the runtime role, approved persistence operations succeed, and the privilege posture remains correct after subsequent migrations.

## 12. Open design decisions requiring explicit review before PR 7A

- Whether one shared runtime login is sufficient for the threat model, or whether stronger Tenant isolation is required at the database level.
- How authenticated acting-Identity context is bound to stored-function calls without trusting arbitrary caller-supplied actor IDs.
- Whether all public write entry points use `SECURITY DEFINER` or a more granular equivalent; the exact owner/migrator membership configuration.
- How to deploy role bootstrap and credential rotation without exposing privileged credentials to application startup.
- Whether the membership-removal GUC guard remains as defense in depth after privilege separation.

Do not let a coding agent silently resolve these security architecture choices by convenience.
