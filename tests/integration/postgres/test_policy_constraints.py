"""Policy constraint tests (POL).

Role -> PermissionSet -> Permission is a physical ownership aggregate:
Role carries canonical URN identity and definition-tenancy agreement,
PermissionSet carries the ALLOW/DENY effect and per-Role positional
order, and Permission URNs are matcher semantics that are intentionally
not globally unique. Action uses its exact URN as canonical identity.
Nothing here encodes authorization precedence, and no RoleAssignment or
independently assignable PermissionSet/Permission surface exists.
"""

from __future__ import annotations

import helpers
import psycopg
import psycopg.errors
import pytest

SYSTEM_ROLE = "urn:mtmf:iam:roles:system:integration-role"
ROLE_NAME = "Integration Role"

ACTION = helpers.ACTION_URN


def _insert_role(connection: psycopg.Connection, urn: str, *, defining_tenant: str | None) -> None:
    connection.execute(
        "INSERT INTO mtmf.role (urn, name, defining_tenant_id) VALUES (%s, %s, %s)",
        (urn, ROLE_NAME, defining_tenant),
    )


def test_pol01_system_role_with_null_defining_tenant_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
    finally:
        connection.close()


def test_pol02_system_role_with_defining_tenant_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=helpers.TENANT_A)
    finally:
        connection.close()


def test_pol03_matching_tenant_role_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    tenant_urn = f"urn:mtmf:iam:roles:tenant:{helpers.TENANT_A}:owner"
    try:
        with connection.transaction():
            _insert_role(connection, tenant_urn, defining_tenant=helpers.TENANT_A)
    finally:
        connection.close()


def test_pol04_tenant_role_with_null_defining_tenant_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    tenant_urn = f"urn:mtmf:iam:roles:tenant:{helpers.TENANT_A}:owner"
    try:
        with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
            _insert_role(connection, tenant_urn, defining_tenant=None)
    finally:
        connection.close()


def test_pol05_mismatched_tenant_role_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    tenant_urn = f"urn:mtmf:iam:roles:tenant:{helpers.TENANT_A}:owner"
    try:
        with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
            _insert_role(connection, tenant_urn, defining_tenant=helpers.TENANT_B)
    finally:
        connection.close()


def test_pol06_duplicate_role_urn_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
    finally:
        connection.close()


def test_pol07_duplicate_role_display_name_allowed(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            _insert_role(
                connection,
                "urn:mtmf:iam:roles:system:second-role",
                defining_tenant=None,
            )
    finally:
        connection.close()


def _seed_role_with_sets(
    connection: psycopg.Connection,
    *,
    positions: tuple[int, ...] = (0,),
    effect: str = "allow",
) -> str:
    _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
    set_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    for index, position in enumerate(positions):
        current_id = set_id if index == 0 else helpers.new_id()
        connection.execute(
            "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
            "VALUES (%s, %s, %s, %s)",
            (current_id, SYSTEM_ROLE, effect, position),
        )
    return set_id


def test_pol08_permission_set_requires_role(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
                "VALUES (%s, 'urn:mtmf:iam:roles:system:missing', 'allow', 0)",
                (helpers.new_id(),),
            )
    finally:
        connection.close()


@pytest.mark.parametrize("effect", ("allow", "deny"))
def test_pol09b_valid_effects_accepted(db, dsn: str, effect: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with connection.transaction():
            _seed_role_with_sets(connection, effect=effect)
    finally:
        connection.close()


def test_pol09_invalid_permission_set_effect_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            connection.execute(
                "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
                "VALUES (%s, %s, 'maybe', 0)",
                (helpers.new_id(), SYSTEM_ROLE),
            )
    finally:
        connection.close()


def test_pol10_permission_set_positions_unique_per_role(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            connection.execute(
                "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
                "VALUES (%s, %s, 'allow', 0)",
                (helpers.new_id(), SYSTEM_ROLE),
            )
            connection.execute(
                "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
                "VALUES (%s, %s, 'deny', 0)",
                (helpers.new_id(), SYSTEM_ROLE),
            )
    finally:
        connection.close()


def test_pol11_permission_requires_permission_set(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            connection.execute(
                "INSERT INTO mtmf.permission "
                "(id, permission_set_id, urn, position) "
                "VALUES (%s, %s, %s, 0)",
                (helpers.new_id(), helpers.new_id(), helpers.PERMISSION_URN_EXACT),
            )
    finally:
        connection.close()


def test_pol012_permission_positions_unique_per_permission_set(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    set_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    try:
        with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            connection.execute(
                "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
                "VALUES (%s, %s, 'allow', 0)",
                (set_id, SYSTEM_ROLE),
            )
            connection.execute(
                "INSERT INTO mtmf.permission (id, permission_set_id, urn, position) "
                "VALUES (%s, %s, %s, 0)",
                (helpers.new_id(), set_id, helpers.PERMISSION_URN_EXACT),
            )
            connection.execute(
                "INSERT INTO mtmf.permission (id, permission_set_id, urn, position) "
                "VALUES (%s, %s, %s, 0)",
                (helpers.new_id(), set_id, helpers.PERMISSION_URN_WILDCARD),
            )
    finally:
        connection.close()


def test_pol013_duplicate_permission_uuid_rejected(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    set_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    try:
        with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            connection.execute(
                "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
                "VALUES (%s, %s, 'allow', 0)",
                (set_id, SYSTEM_ROLE),
            )
            permission_id = helpers.new_id()
            connection.execute(
                "INSERT INTO mtmf.permission (id, permission_set_id, urn, position) "
                "VALUES (%s, %s, %s, 0)",
                (permission_id, set_id, helpers.PERMISSION_URN_EXACT),
            )
            connection.execute(
                "INSERT INTO mtmf.permission (id, permission_set_id, urn, position) "
                "VALUES (%s, %s, %s, 1)",
                (permission_id, set_id, helpers.PERMISSION_URN_WILDCARD),
            )
    finally:
        connection.close()


def test_pol014_duplicate_permission_urn_on_distinct_uuids_accepted(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    set_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    try:
        with connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            connection.execute(
                "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
                "VALUES (%s, %s, 'allow', 0)",
                (set_id, SYSTEM_ROLE),
            )
            connection.execute(
                "INSERT INTO mtmf.permission (id, permission_set_id, urn, position) "
                "VALUES (%s, %s, %s, 0)",
                (helpers.new_id(), set_id, helpers.PERMISSION_URN_EXACT),
            )
            connection.execute(
                "INSERT INTO mtmf.permission (id, permission_set_id, urn, position) "
                "VALUES (%s, %s, %s, 1)",
                (helpers.new_id(), set_id, helpers.PERMISSION_URN_EXACT),
            )
    finally:
        connection.close()


def test_pol015_permission_has_no_effect_column(db) -> None:
    assert "effect" not in helpers.columns_of(db, "permission")


def test_pol016_no_independent_permission_set_or_permission_assignment_table(db) -> None:
    actual = helpers.tables(db)
    assert "role_assignment" not in actual
    assert "permission_assignment" not in actual
    assert "policy_assignment" not in actual


def test_pol017_and_pol018_action_urn_is_primary_identity(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.UniqueViolation), connection.transaction():
            connection.execute("INSERT INTO mtmf.action (urn) VALUES (%s)", (ACTION,))
            connection.execute("INSERT INTO mtmf.action (urn) VALUES (%s)", (ACTION,))
    finally:
        connection.close()


def test_pol019_action_has_only_its_exact_urn(db) -> None:
    assert helpers.columns_of(db, "action") == {"urn": "text"}


def test_pol020_order_is_persisted_without_authorization_semantics(db) -> None:
    # Positional order is structural state: it exists only as a bounded
    # non-negative integer column, never as an evaluation precedence.
    assert helpers.columns_of(db, "permission_set")["position"] == "integer"
    assert helpers.columns_of(db, "permission")["position"] == "integer"
    # No effect column exists anywhere except PermissionSet.
    for table in ("role", "permission", "action"):
        assert "effect" not in helpers.columns_of(db, table)


def test_role_structural_immutability(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with connection.transaction():
            _insert_role(connection, SYSTEM_ROLE, defining_tenant=None)
            connection.execute(
                "UPDATE mtmf.role SET name = 'Renamed' WHERE urn = %s", (SYSTEM_ROLE,)
            )
        with pytest.raises(psycopg.errors.RaiseException), connection.transaction():
            connection.execute(
                "UPDATE mtmf.role SET defining_tenant_id = %s WHERE urn = %s",
                (helpers.TENANT_A, SYSTEM_ROLE),
            )
    finally:
        connection.close()
