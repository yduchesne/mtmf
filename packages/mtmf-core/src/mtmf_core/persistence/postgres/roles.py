"""MTMF PostgreSQL role provisioning and security verification.

MTMF separates three cluster-wide login/ownership roles:

- ``mtmf_owner`` — ``NOLOGIN``; owns the ``mtmf`` schema and every MTMF
  object. It is only ever assumed through a controlled ``SET ROLE``.
- ``mtmf_migrator`` — deployment-only ``LOGIN`` with membership in
  ``mtmf_owner`` that permits ``SET ROLE`` but does **not** inherit owner
  privileges automatically (PostgreSQL ``INHERIT FALSE`` / ``SET TRUE``).
- ``mtmf_runtime`` — restricted application ``LOGIN`` with no ownership
  and no membership in the owner or migrator roles.

Role creation is a cluster-level administrator operation and is
deliberately **outside** Alembic: a deployment runs
:func:`provision_roles` (repeatably) before migrating. The functions here
never drop roles and never touch a non-MTMF role.

``adopt_existing_schema`` is the administrator-approved one-time
ownership handoff for a database whose ``mtmf`` objects predate this
model (for example, objects created by a single trusted migration login).
It is an explicit operator action, never part of a normal runtime path.

This module also contains read-only *verifiers*:

- :func:`verify_role_topology` validates the effective membership graph
  (direct and transitive) and role attributes, failing closed on any
  unexpected path. It never rewrites another role's memberships.
- :func:`verify_runtime_privileges` validates the effective privilege
  surface after migration (database/schema/table/sequence/function, the
  exact runtime EXECUTE allowlist, PUBLIC function EXECUTE, and owner
  default privileges).
- :func:`verify_migrator_connection` asserts that a migration connection
  authenticated as ``mtmf_migrator`` and is not elevated before it may
  ``SET ROLE mtmf_owner``.

PostgreSQL role privileges are additive: revoking a grant from one role
does not cancel another role's grant. These verifiers therefore check the
effective reachability (``pg_has_role``) and the effective privilege
inventory, not merely the absence of a direct ACL row.

All SQL is composed with :mod:`psycopg.sql` identifiers and literals,
which are safely quoted by the driver; no caller-controlled value is ever
interpolated as SQL text. Statements are built by small helpers so the
composition is reviewable and testable.
"""

from __future__ import annotations

import psycopg
from psycopg import sql

SCHEMA = "mtmf"
OWNER_ROLE = "mtmf_owner"
MIGRATOR_ROLE = "mtmf_migrator"
RUNTIME_ROLE = "mtmf_runtime"

_LOGIN_ATTRIBUTES = "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"

#: The exact approved runtime persistence entry points. Function privileges
#: are signature-specific, so the verifier compares full identities rather
#: than a name pattern or a count.
_REMOVAL_FUNCTION_ARGUMENTS = {
    "remove_principal_tenant_membership": (
        "principal_id_value uuid, tenant_id_value uuid, actor_identity_id_value uuid"
    ),
    "remove_identity_tenant_membership": (
        "identity_id_value uuid, tenant_id_value uuid, actor_identity_id_value uuid"
    ),
    "remove_group_tenant_membership": (
        "group_id_value uuid, tenant_id_value uuid, actor_identity_id_value uuid"
    ),
    "remove_identity_group_membership": (
        "identity_id_value uuid, group_id_value uuid, actor_identity_id_value uuid"
    ),
    "remove_identity_org_membership": (
        "identity_id_value uuid, organization_id_value uuid, actor_identity_id_value uuid"
    ),
    "remove_group_org_membership": (
        "group_id_value uuid, organization_id_value uuid, actor_identity_id_value uuid"
    ),
}

#: Exact approved runtime EXECUTE signatures introduced by revision 0004.
_REPOSITORY_FUNCTION_ARGUMENTS = {
    "tenant_add": (
        "id_value uuid, name_value text, scope_value smallint, "
        "owner_identity_id_value uuid, lifecycle_value smallint, "
        "deletion_status_value smallint, extension_value jsonb"
    ),
    "tenant_get": ("id_value uuid"),
    "tenant_save": (
        "id_value uuid, name_value text, lifecycle_value smallint, "
        "deletion_status_value smallint, extension_value jsonb"
    ),
    "organization_add": (
        "id_value uuid, tenant_id_value uuid, name_value text, "
        "owner_identity_id_value uuid, deletion_status_value smallint, extension_value jsonb"
    ),
    "organization_get": ("id_value uuid"),
    "organization_save": (
        "id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb"
    ),
    "principal_add": (
        "id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb"
    ),
    "principal_get": ("id_value uuid"),
    "principal_save": (
        "id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb"
    ),
    "identity_add": (
        "id_value uuid, principal_id_value uuid, name_value text, "
        "origin_value smallint, deletion_status_value smallint, extension_value jsonb"
    ),
    "identity_get": ("id_value uuid"),
    "identity_save": (
        "id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb"
    ),
    "group_add": (
        "id_value uuid, tenant_id_value uuid, name_value text, "
        "deletion_status_value smallint, extension_value jsonb"
    ),
    "group_get": ("id_value uuid"),
    "group_save": (
        "id_value uuid, name_value text, deletion_status_value smallint, extension_value jsonb"
    ),
    "action_add": ("urn_value text"),
    "action_get": ("urn_value text"),
    "role_add": ("payload_value jsonb"),
    "role_get": ("urn_value text"),
    "role_save": ("payload_value jsonb"),
    "principal_tenant_membership_add": ("principal_id_value uuid, tenant_id_value uuid"),
    "principal_tenant_membership_get": ("principal_id_value uuid, tenant_id_value uuid"),
    "principal_tenant_membership_find_by_principal": ("principal_id_value uuid"),
    "principal_tenant_membership_find_by_tenant": ("tenant_id_value uuid"),
    "identity_tenant_membership_add": ("identity_id_value uuid, tenant_id_value uuid"),
    "identity_tenant_membership_get": ("identity_id_value uuid, tenant_id_value uuid"),
    "identity_tenant_membership_find_by_identity": ("identity_id_value uuid"),
    "identity_tenant_membership_find_by_tenant": ("tenant_id_value uuid"),
    "group_tenant_membership_add": ("group_id_value uuid, tenant_id_value uuid"),
    "group_tenant_membership_get": ("group_id_value uuid, tenant_id_value uuid"),
    "group_tenant_membership_find_by_group": ("group_id_value uuid"),
    "group_tenant_membership_find_by_tenant": ("tenant_id_value uuid"),
    "identity_group_membership_add": ("identity_id_value uuid, group_id_value uuid"),
    "identity_group_membership_get": ("identity_id_value uuid, group_id_value uuid"),
    "identity_group_membership_find_by_identity": ("identity_id_value uuid"),
    "identity_group_membership_find_by_group": ("group_id_value uuid"),
    "identity_org_membership_add": ("identity_id_value uuid, organization_id_value uuid"),
    "identity_org_membership_get": ("identity_id_value uuid, organization_id_value uuid"),
    "identity_org_membership_find_by_identity": ("identity_id_value uuid"),
    "identity_org_membership_find_by_organization": ("organization_id_value uuid"),
    "group_org_membership_add": ("group_id_value uuid, organization_id_value uuid"),
    "group_org_membership_get": ("group_id_value uuid, organization_id_value uuid"),
    "group_org_membership_find_by_group": ("group_id_value uuid"),
    "group_org_membership_find_by_organization": ("organization_id_value uuid"),
}

#: Exact approved runtime EXECUTE signatures introduced by revision 0005
#: (the eight typed Role-assignment read/write entry points). The three
#: Role-assignment validation helpers are private and are never granted.
_ROLE_ASSIGNMENT_FUNCTION_ARGUMENTS = {
    "identity_role_assignment_add": (
        "id_value uuid, tenant_id_value uuid, identity_id_value uuid, "
        "role_urn_value text, organization_id_value uuid"
    ),
    "identity_role_assignment_get": ("id_value uuid"),
    "identity_role_assignment_find_by_tenant_and_identity": (
        "tenant_id_value uuid, identity_id_value uuid"
    ),
    "identity_role_assignment_remove": ("id_value uuid"),
    "group_role_assignment_add": (
        "id_value uuid, tenant_id_value uuid, group_id_value uuid, "
        "role_urn_value text, organization_id_value uuid"
    ),
    "group_role_assignment_get": ("id_value uuid"),
    "group_role_assignment_find_by_tenant_and_group": ("tenant_id_value uuid, group_id_value uuid"),
    "group_role_assignment_remove": ("id_value uuid"),
}


class RoleProvisioningError(RuntimeError):
    """The MTMF role topology or effective privileges are unsafe."""


class MigrationIdentityError(RoleProvisioningError):
    """A migration connection did not authenticate as the intended migrator."""


class PrivilegeVerificationError(RoleProvisioningError):
    """Effective MTMF privileges do not match the required runtime posture."""


def expected_removal_signatures() -> frozenset[str]:
    """Return the full ``schema.name(args)`` identities of the approved removal entry points."""
    return frozenset(
        f"{SCHEMA}.{name}({arguments})" for name, arguments in _REMOVAL_FUNCTION_ARGUMENTS.items()
    )


def expected_runtime_signatures() -> frozenset[str]:
    """Return the reviewed runtime EXECUTE allowlist through revision 0005.

    This is the six membership-removal entry points plus the 44 repository
    read/write functions introduced through v004, plus the eight typed
    Role-assignment entry points introduced by v005. The mandatory
    post-upgrade verifier compares the runtime's effective EXECUTE set
    against exactly this manifest, so a function is only approved when both
    the migration grants and this manifest are updated in the same
    migration.
    """
    arguments = {
        **_REMOVAL_FUNCTION_ARGUMENTS,
        **_REPOSITORY_FUNCTION_ARGUMENTS,
        **_ROLE_ASSIGNMENT_FUNCTION_ARGUMENTS,
    }
    return frozenset(
        f"{SCHEMA}.{name}({arguments_text})" for name, arguments_text in arguments.items()
    )


# --- Quoting-safe statement builders ---------------------------------------


def _create_role_statement(role: str, *, can_login: bool) -> sql.Composed:
    login = sql.SQL("LOGIN" if can_login else "NOLOGIN")
    return sql.SQL(f"CREATE ROLE {{}} {{}} {_LOGIN_ATTRIBUTES}").format(sql.Identifier(role), login)


def _normalize_role_statement(role: str, *, can_login: bool) -> sql.Composed:
    login = sql.SQL("LOGIN" if can_login else "NOLOGIN")
    return sql.SQL(f"ALTER ROLE {{}} WITH {{}} {_LOGIN_ATTRIBUTES}").format(
        sql.Identifier(role), login
    )


def _set_password_statement(role: str, password: str) -> sql.Composed:
    return sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(
        sql.Identifier(role), sql.Literal(password)
    )


def _grant_owner_statement() -> sql.Composed:
    return sql.SQL("GRANT {} TO {} WITH INHERIT FALSE, SET TRUE").format(
        sql.Identifier(OWNER_ROLE), sql.Identifier(MIGRATOR_ROLE)
    )


def _revoke_membership_statement(granted: str, grantee: str) -> sql.Composed:
    return sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(granted), sql.Identifier(grantee))


def _grant_database_statement(privilege: str, database: str, role: str) -> sql.Composed:
    return sql.SQL("GRANT {} ON DATABASE {} TO {}").format(
        sql.SQL(privilege), sql.Identifier(database), sql.Identifier(role)
    )


def _adopt_schema_statement() -> sql.Composed:
    return sql.SQL("ALTER SCHEMA {} OWNER TO {}").format(
        sql.Identifier(SCHEMA), sql.Identifier(OWNER_ROLE)
    )


def _adopt_relation_statement(relation: str, *, sequence: bool) -> sql.Composed:
    verb = sql.SQL("ALTER SEQUENCE" if sequence else "ALTER TABLE")
    return sql.SQL("{} {}.{} OWNER TO {}").format(
        verb, sql.Identifier(SCHEMA), sql.Identifier(relation), sql.Identifier(OWNER_ROLE)
    )


def _adopt_function_statement(signature: str) -> sql.Composed:
    return sql.SQL("ALTER FUNCTION {} OWNER TO {}").format(
        sql.SQL(signature), sql.Identifier(OWNER_ROLE)
    )


# --- Read-only verification queries ----------------------------------------


def _role_attributes(connection: psycopg.Connection) -> list[tuple[object, ...]]:
    return connection.execute(
        "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolbypassrls "
        "FROM pg_catalog.pg_roles WHERE rolname = ANY(%s) ORDER BY rolname",
        ([OWNER_ROLE, MIGRATOR_ROLE, RUNTIME_ROLE],),
    ).fetchall()


def _membership_rows(connection: psycopg.Connection) -> list[tuple[object, ...]]:
    return connection.execute(
        "SELECT m.rolname AS member, r.rolname AS granted, "
        "       am.inherit_option, am.set_option, am.admin_option "
        "FROM pg_catalog.pg_auth_members am "
        "JOIN pg_catalog.pg_roles m ON m.oid = am.member "
        "JOIN pg_catalog.pg_roles r ON r.oid = am.roleid "
        "WHERE m.rolname IN (%s, %s) "
        "ORDER BY m.rolname, r.rolname",
        (MIGRATOR_ROLE, RUNTIME_ROLE),
    ).fetchall()


def _reachability_row(connection: psycopg.Connection) -> tuple[object, ...] | None:
    return connection.execute(
        "SELECT "
        "pg_has_role(%s, %s, 'SET'), pg_has_role(%s, %s, 'USAGE'), "
        "pg_has_role(%s, %s, 'MEMBER'), "
        "pg_has_role(%s, %s, 'SET'), pg_has_role(%s, %s, 'USAGE'), "
        "pg_has_role(%s, %s, 'MEMBER'), "
        "pg_has_role(%s, %s, 'MEMBER')",
        (
            MIGRATOR_ROLE,
            OWNER_ROLE,
            MIGRATOR_ROLE,
            OWNER_ROLE,
            MIGRATOR_ROLE,
            OWNER_ROLE,
            RUNTIME_ROLE,
            OWNER_ROLE,
            RUNTIME_ROLE,
            OWNER_ROLE,
            RUNTIME_ROLE,
            OWNER_ROLE,
            RUNTIME_ROLE,
            MIGRATOR_ROLE,
        ),
    ).fetchone()


# --- Pure diagnostics (unit-testable) --------------------------------------


def _unexpected_membership_problems(memberships: list[tuple[object, ...]]) -> list[str]:
    """Problems for memberships that must not exist regardless of current grants."""
    problems: list[str] = []
    for member, granted, inherit, set_option, _admin in memberships:
        if member == RUNTIME_ROLE:
            problems.append(
                f"unexpected role membership: {RUNTIME_ROLE} is a member of {granted} "
                f"(inherit={inherit}, set={set_option}); the runtime login must have no memberships"
            )
        elif member == MIGRATOR_ROLE and granted != OWNER_ROLE:
            problems.append(
                f"unexpected role membership: {MIGRATOR_ROLE} is a member of {granted} "
                f"(inherit={inherit}, set={set_option}); only the intended {OWNER_ROLE} "
                "membership is allowed"
            )
    return problems


def _topology_problems(
    role_attributes: list[tuple[object, ...]],
    memberships: list[tuple[object, ...]],
    reachability: tuple[object, ...] | None,
) -> list[str]:
    """Return fail-closed topology problems from catalog rows (empty if safe)."""
    problems: list[str] = []
    attributes = {str(row[0]): row for row in role_attributes}
    for role in (OWNER_ROLE, MIGRATOR_ROLE, RUNTIME_ROLE):
        row = attributes.get(role)
        if row is None:
            problems.append(f"required role {role} does not exist")
            continue
        _name, superuser, createrole, createdb, can_login, bypassrls = row
        if superuser or createrole or createdb or bypassrls:
            problems.append(f"role {role} must not have SUPERUSER/CREATEROLE/CREATEDB/BYPASSRLS")
        if role == OWNER_ROLE and can_login:
            problems.append(f"role {role} must be NOLOGIN")
        if role != OWNER_ROLE and not can_login:
            problems.append(f"role {role} must be a LOGIN role")

    problems.extend(_unexpected_membership_problems(memberships))

    owner_rows = [row for row in memberships if row[0] == MIGRATOR_ROLE and row[1] == OWNER_ROLE]
    if not owner_rows:
        problems.append(f"the intended {OWNER_ROLE} membership for {MIGRATOR_ROLE} is missing")
    for _member, _granted, inherit, set_option, admin in owner_rows:
        if inherit or not set_option or admin:
            problems.append(
                f"the {MIGRATOR_ROLE}->{OWNER_ROLE} membership must be "
                "INHERIT FALSE, SET TRUE, ADMIN FALSE"
            )

    if reachability is None:
        problems.append("effective role reachability could not be determined")
        return problems
    (
        migrator_set,
        migrator_usage,
        migrator_member,
        runtime_owner_set,
        runtime_owner_usage,
        runtime_owner_member,
        runtime_migrator_member,
    ) = reachability
    if not migrator_set:
        problems.append(f"{MIGRATOR_ROLE} must be able to SET ROLE {OWNER_ROLE}")
    if migrator_usage:
        problems.append(f"{MIGRATOR_ROLE} must not inherit (USAGE) {OWNER_ROLE}")
    if not migrator_member:
        problems.append(f"{MIGRATOR_ROLE} must be a member of {OWNER_ROLE}")
    if runtime_owner_set or runtime_owner_usage or runtime_owner_member:
        problems.append(f"{RUNTIME_ROLE} must not reach {OWNER_ROLE} by SET, USAGE, or MEMBER")
    if runtime_migrator_member:
        problems.append(f"{RUNTIME_ROLE} must not be a member of {MIGRATOR_ROLE}")
    return problems


def _privilege_problems(
    *,
    schema_exists: bool,
    database_privileges: tuple[object, object] | None,
    schema_privileges: tuple[object, object] | None,
    table_offenders: list[tuple[object, ...]],
    sequence_offenders: list[tuple[object, ...]],
    executable_signatures: set[str],
    public_execute_count: int,
    default_public_execute_count: int,
) -> list[str]:
    """Return effective-privilege problems from catalog rows (empty if safe)."""
    problems: list[str] = []
    if not schema_exists:
        problems.append(
            f"the {SCHEMA} schema does not exist; run migrations to head before verification"
        )
        return problems
    if database_privileges is None:
        problems.append("database privileges could not be determined")
    else:
        connect, create = database_privileges
        if not connect:
            problems.append(f"{RUNTIME_ROLE} is missing CONNECT on the MTMF database")
        if create:
            problems.append(f"{RUNTIME_ROLE} must not have CREATE on the MTMF database")
    if schema_privileges is None:
        problems.append("schema privileges could not be determined")
    else:
        usage, create = schema_privileges
        if not usage:
            problems.append(f"{RUNTIME_ROLE} is missing USAGE on schema {SCHEMA}")
        if create:
            problems.append(f"{RUNTIME_ROLE} must not have CREATE on schema {SCHEMA}")
    for relation, privilege in table_offenders:
        problems.append(f"{RUNTIME_ROLE} has {privilege} on table/view {relation}")
    for relation, privilege in sequence_offenders:
        problems.append(f"{RUNTIME_ROLE} has {privilege} on sequence {relation}")
    expected = expected_runtime_signatures()
    extra = executable_signatures - expected
    missing = expected - executable_signatures
    for signature in sorted(extra):
        problems.append(f"{RUNTIME_ROLE} can EXECUTE unapproved function {signature}")
    for signature in sorted(missing):
        problems.append(f"{RUNTIME_ROLE} cannot EXECUTE approved function {signature}")
    if public_execute_count:
        problems.append(
            f"PUBLIC can EXECUTE {public_execute_count} MTMF function(s); "
            "PUBLIC EXECUTE must be absent"
        )
    if default_public_execute_count:
        problems.append("owner default privileges still grant PUBLIC EXECUTE on new functions")
    return problems


# --- Verifiers --------------------------------------------------------------


def verify_role_topology(connection: psycopg.Connection) -> None:
    """Fail closed when the effective MTMF role topology is not the approved one.

    Checks role attributes, the direct membership graph, the intended
    ``mtmf_migrator`` -> ``mtmf_owner`` options, and effective
    ``pg_has_role`` SET/USAGE/MEMBER reachability. It never removes another
    role's memberships; remediation is an explicit administrator action.

    :raises RoleProvisioningError: with role names/paths but no credentials.
    """
    problems = _topology_problems(
        _role_attributes(connection),
        _membership_rows(connection),
        _reachability_row(connection),
    )
    if problems:
        raise RoleProvisioningError("unsafe MTMF role topology: " + "; ".join(problems))


def _database_privileges(
    connection: psycopg.Connection,
) -> tuple[object, object] | None:
    return connection.execute(
        "SELECT has_database_privilege(%s, current_database(), 'CONNECT'), "
        "       has_database_privilege(%s, current_database(), 'CREATE')",
        (RUNTIME_ROLE, RUNTIME_ROLE),
    ).fetchone()


def _schema_privileges(connection: psycopg.Connection) -> tuple[object, object] | None:
    return connection.execute(
        "SELECT has_schema_privilege(%s, %s, 'USAGE'), "
        "       has_schema_privilege(%s, %s, 'CREATE')",
        (RUNTIME_ROLE, SCHEMA, RUNTIME_ROLE, SCHEMA),
    ).fetchone()


def _table_offenders(connection: psycopg.Connection) -> list[tuple[object, ...]]:
    return connection.execute(
        "SELECT format('%%I.%%I', n.nspname, c.relname), p.privilege "
        "FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "CROSS JOIN unnest(ARRAY["
        "'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'"
        "]) AS p(privilege) "
        "WHERE n.nspname = %s AND c.relkind IN ('r', 'p', 'v', 'm') "
        "AND has_table_privilege(%s, c.oid, p.privilege) "
        "ORDER BY 1, 2",
        (SCHEMA, RUNTIME_ROLE),
    ).fetchall()


def _sequence_offenders(connection: psycopg.Connection) -> list[tuple[object, ...]]:
    return connection.execute(
        "SELECT format('%%I.%%I', n.nspname, c.relname), p.privilege "
        "FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "CROSS JOIN unnest(ARRAY['USAGE', 'SELECT', 'UPDATE']) AS p(privilege) "
        "WHERE n.nspname = %s AND c.relkind = 'S' "
        "AND has_sequence_privilege(%s, c.oid, p.privilege) "
        "ORDER BY 1, 2",
        (SCHEMA, RUNTIME_ROLE),
    ).fetchall()


def _executable_signatures(connection: psycopg.Connection) -> set[str]:
    rows = connection.execute(
        "SELECT format('%%I.%%I(%%s)', n.nspname, p.proname, "
        "              pg_get_function_identity_arguments(p.oid)) "
        "FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s AND has_function_privilege(%s, p.oid, 'EXECUTE') "
        "ORDER BY 1",
        (SCHEMA, RUNTIME_ROLE),
    ).fetchall()
    return {str(row[0]) for row in rows}


def _public_execute_count(connection: psycopg.Connection) -> int:
    row = connection.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s AND EXISTS ("
        "  SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a "
        "  WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')",
        (SCHEMA,),
    ).fetchone()
    if row is None:
        return 0
    return int(row[0])


def _default_public_execute_count(connection: psycopg.Connection) -> int:
    row = connection.execute(
        "SELECT count(*) FROM pg_catalog.pg_default_acl d "
        "JOIN pg_catalog.pg_roles r ON r.oid = d.defaclrole "
        "CROSS JOIN LATERAL aclexplode(d.defaclacl) a "
        "WHERE r.rolname = %s AND d.defaclobjtype = 'f' "
        "AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'",
        (OWNER_ROLE,),
    ).fetchone()
    if row is None:
        return 0
    return int(row[0])


def verify_runtime_privileges(connection: psycopg.Connection) -> None:
    """Fail closed when the effective runtime privilege surface is not exact.

    Intended to run from a trusted administrator connection after migration
    to head. It checks the effective role topology and the runtime's
    database/schema/table/sequence/function privileges, the exact EXECUTE
    allowlist, PUBLIC function EXECUTE, and owner default privileges.

    :raises PrivilegeVerificationError: naming objects/privileges, never
        credentials.
    """
    schema_row = connection.execute(
        "SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = %s", (SCHEMA,)
    ).fetchone()
    schema_exists = schema_row is not None
    problems: list[str] = []
    if schema_exists:
        problems.extend(
            _topology_problems(
                _role_attributes(connection),
                _membership_rows(connection),
                _reachability_row(connection),
            )
        )
    else:
        problems.append(
            f"the {SCHEMA} schema does not exist; run migrations to head before verification"
        )
        raise PrivilegeVerificationError(
            "MTMF runtime privilege verification failed: " + "; ".join(problems)
        )
    problems.extend(
        _privilege_problems(
            schema_exists=True,
            database_privileges=_database_privileges(connection),
            schema_privileges=_schema_privileges(connection),
            table_offenders=_table_offenders(connection),
            sequence_offenders=_sequence_offenders(connection),
            executable_signatures=_executable_signatures(connection),
            public_execute_count=_public_execute_count(connection),
            default_public_execute_count=_default_public_execute_count(connection),
        )
    )
    if problems:
        raise PrivilegeVerificationError(
            "MTMF runtime privilege verification failed: " + "; ".join(problems)
        )


def verify_migrator_connection(connection: psycopg.Connection) -> None:
    """Assert a migration connection authenticated as the MTMF migrator.

    Must be called *before* ``SET ROLE mtmf_owner`` on every migration
    connection (psycopg bootstrap/read and Alembic's SQLAlchemy
    connection). Checks ``session_user``/``current_user``, role
    attributes, and that the login can ``SET ROLE`` owner without
    inheriting (``USAGE``) owner privileges.

    :raises MigrationIdentityError: without credentials in the message.
    """
    row = connection.execute(
        "SELECT session_user, current_user, "
        "       r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls, "
        "       pg_has_role(session_user, %s, 'SET'), "
        "       pg_has_role(session_user, %s, 'USAGE') "
        "FROM pg_catalog.pg_roles r "
        "WHERE r.rolname = session_user",
        (OWNER_ROLE, OWNER_ROLE),
    ).fetchone()
    if row is None:
        raise MigrationIdentityError("migration connection identity could not be determined")
    (
        session_user,
        current_user,
        superuser,
        createrole,
        createdb,
        bypassrls,
        owner_set,
        owner_usage,
    ) = row
    problems: list[str] = []
    if session_user != MIGRATOR_ROLE:
        problems.append(f"session_user must be {MIGRATOR_ROLE}, got {session_user!r}")
    if current_user != MIGRATOR_ROLE:
        problems.append(
            f"current_user must be {MIGRATOR_ROLE} before SET ROLE, got {current_user!r}"
        )
    if superuser or createrole or createdb or bypassrls:
        problems.append("migration login must not be elevated")
    if not owner_set:
        problems.append(f"migration login must be able to SET ROLE {OWNER_ROLE}")
    if owner_usage:
        problems.append(f"migration login must not inherit (USAGE) {OWNER_ROLE}")
    if problems:
        raise MigrationIdentityError("refusing MTMF migration connection: " + "; ".join(problems))


def provision_roles(
    connection: psycopg.Connection,
    *,
    migrator_password: str,
    runtime_password: str,
) -> None:
    """Create or normalize the three MTMF roles, idempotently.

    Re-running this function never errors and never escalates rights: it
    creates missing roles, re-asserts restrictive attributes, sets the
    deployment passwords, grants owner membership to the migrator with
    ``INHERIT FALSE`` / ``SET TRUE``, and ensures the runtime role is not
    a member of the owner or migrator roles.

    The unexpected-membership graph is validated **before** any credential
    or membership mutation. A contaminated cluster fails closed with the
    offending role path; the administrator must remove the contamination.
    Provisioning runs with ``autocommit`` and is therefore not
    all-or-nothing: if a later SQL statement fails, earlier role/attribute
    changes remain and must be reviewed before retrying.
    """
    preexisting = _unexpected_membership_problems(_membership_rows(connection))
    if preexisting:
        raise RoleProvisioningError(
            "unsafe MTMF role topology; an administrator must remove the unexpected "
            "membership(s): " + "; ".join(preexisting)
        )

    for role, can_login in (
        (OWNER_ROLE, False),
        (MIGRATOR_ROLE, True),
        (RUNTIME_ROLE, True),
    ):
        if not _role_exists(connection, role):
            create_statement = _create_role_statement(role, can_login=can_login)
            connection.execute(create_statement)
        normalize_statement = _normalize_role_statement(role, can_login=can_login)
        connection.execute(normalize_statement)

    set_migrator_password = _set_password_statement(MIGRATOR_ROLE, migrator_password)
    connection.execute(set_migrator_password)
    set_runtime_password = _set_password_statement(RUNTIME_ROLE, runtime_password)
    connection.execute(set_runtime_password)

    # The migrator may assume the owner only through an explicit SET ROLE;
    # INHERIT FALSE keeps its own session least-privileged.
    connection.execute(_grant_owner_statement())
    # The runtime role must never hold either elevated membership.
    connection.execute(_revoke_membership_statement(OWNER_ROLE, RUNTIME_ROLE))
    connection.execute(_revoke_membership_statement(MIGRATOR_ROLE, RUNTIME_ROLE))

    # The owner creates the MTMF schema itself, which requires database-level
    # CREATE. This is granted to the owner only; the runtime role gets none.
    # Every MTMF identity also receives an explicit database CONNECT.
    database = connection.execute("SELECT current_database()").fetchone()
    if database is not None:
        name = str(database[0])
        connection.execute(_grant_database_statement("CREATE", name, OWNER_ROLE))
        for role in (OWNER_ROLE, MIGRATOR_ROLE, RUNTIME_ROLE):
            connection.execute(_grant_database_statement("CONNECT", name, role))

    # Postflight: the resulting effective topology must be exactly approved.
    verify_role_topology(connection)


def _role_exists(connection: psycopg.Connection, role: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = %s", (role,)
    ).fetchone()
    return row is not None


def find_non_owner_objects(connection: psycopg.Connection) -> str | None:
    """Return a summary of ``mtmf`` schema/objects/functions not owned by the owner.

    Catalog-only and read-only; returns ``None`` when every supported MTMF
    object (plus the schema and functions) is owned by ``mtmf_owner``.
    Indexes follow their table's ownership, so transferring tables transfers
    the indexes that belong to them.
    """
    # ``%%s`` is psycopg's escape for a literal ``%s`` (the SQL ``format()``
    # placeholder); the six ``%s`` tokens are the bound schema/owner values.
    row = connection.execute(
        """
        SELECT string_agg(obj, ', ')
          FROM (
                SELECT format('schema mtmf (%%s)', pg_get_userbyid(nspowner)) AS obj
                  FROM pg_catalog.pg_namespace
                 WHERE nspname = %s AND pg_get_userbyid(nspowner) <> %s
                UNION ALL
                SELECT format('%%s (%%s)', c.relname, pg_get_userbyid(c.relowner))
                  FROM pg_catalog.pg_class c
                  JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = %s AND pg_get_userbyid(c.relowner) <> %s
                UNION ALL
                SELECT format('function %%s (%%s)', p.proname, pg_get_userbyid(p.proowner))
                  FROM pg_catalog.pg_proc p
                  JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                 WHERE n.nspname = %s AND pg_get_userbyid(p.proowner) <> %s
               ) AS offenders
        """,
        (SCHEMA, OWNER_ROLE, SCHEMA, OWNER_ROLE, SCHEMA, OWNER_ROLE),
    ).fetchone()
    if row is None or row[0] is None:
        return None
    return str(row[0])


def _verify_schema_ownership(connection: psycopg.Connection) -> None:
    """Fail closed when any MTMF object is still not owned by ``mtmf_owner``."""
    offenders = find_non_owner_objects(connection)
    if offenders is not None:
        raise RoleProvisioningError(
            f"ownership adoption did not transfer these {SCHEMA} objects to "
            f"{OWNER_ROLE}: {offenders}. Earlier autocommit ownership changes are "
            "not rolled back; review the objects and retry."
        )


def adopt_existing_schema(connection: psycopg.Connection) -> None:
    """Administrator-only ownership handoff for a pre-existing ``mtmf`` schema.

        Transfers the ``mtmf`` schema, its tables/views/sequences, and its
        functions to ``mtmf_owner``. Only objects inside the ``mtmf`` schema
        are touched; no other schema, role, or database is modified.

        The documented caller contract is that the three MTMF roles have
    already been provisioned (the CLI provisions first). After adoption this
        function asserts that every supported MTMF object is owner-owned and
        re-runs the role-topology verifier. It deliberately does **not** run the
        full runtime privilege verifier: a pre-head schema may legitimately
        differ from the head privilege contract.

        When the ``mtmf`` schema does not exist, this is a no-op and no
        topology check runs. On ownership-postcondition failure the earlier
        autocommit ownership changes are **not** rolled back.
    """
    schema_exists = connection.execute(
        "SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = %s", (SCHEMA,)
    ).fetchone()
    if schema_exists is None:
        return
    connection.execute(_adopt_schema_statement())
    relations = connection.execute(
        "SELECT c.relname, c.relkind FROM pg_catalog.pg_class c "
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
        "WHERE n.nspname = %s AND c.relkind IN ('r', 'p', 'v', 'm', 'S')",
        (SCHEMA,),
    ).fetchall()
    for name, kind in relations:
        relation = _adopt_relation_statement(str(name), sequence=kind == "S")
        connection.execute(relation)
    functions = connection.execute(
        "SELECT p.oid::regprocedure::text FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = %s",
        (SCHEMA,),
    ).fetchall()
    for (signature,) in functions:
        function = _adopt_function_statement(str(signature))
        connection.execute(function)
    _verify_schema_ownership(connection)
    verify_role_topology(connection)
