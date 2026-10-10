"""Approved Gate M built-in IAM seed and protection (revision 0006).

These tests exercise the literal PR #38 seed on real PostgreSQL: exactly
eleven SYSTEM-owned Roles, eleven ALLOW PermissionSets, eleven exact
Permissions, and three shared Action definitions, with the 22 published
UUIDs. They also prove the database-enforced protection that stops the
ordinary runtime login from rewriting a built-in definition, and that the
installation-only seed installer is not runtime-executable.

The ``db`` fixture migrates a freshly reset schema through ``0006`` with the
real migrator identity (including the mandatory privilege postflight), so
every test starts from the installed seed.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg.types.json import Jsonb

# (role suffix, human name, permission suffix, permission-set UUID, permission UUID)
APPROVED_SEED = (
    (
        "system-administrator",
        "System Administrator",
        "tenant:get-object",
        "b04f0a3d-5d52-5c14-bb45-6ee07169eec0",
        "fa32a700-21d8-55fb-8e50-46f6d236d731",
    ),
    (
        "system-security-administrator",
        "System Security Administrator",
        "role:get-object",
        "b72dfbeb-59b4-5e36-bcd1-d707bc80571a",
        "747273b4-90b8-53da-b67b-029b3b336ac1",
    ),
    (
        "system-reader",
        "System Reader",
        "tenant:get-object",
        "1f9a65c9-cf69-516b-86f3-6cb459ae0b5e",
        "894a1b10-2e42-51d0-a21b-cd9b15676a69",
    ),
    (
        "tenant-administrator",
        "Tenant Administrator",
        "tenant:get-object",
        "187bc3cd-993d-5660-a226-113411121fed",
        "e7943319-187f-55b4-835a-059bf4ab7206",
    ),
    (
        "tenant-security-administrator",
        "Tenant Security Administrator",
        "role:get-object",
        "1526c205-21da-551f-8048-493467be2e19",
        "ac9ee2ad-87f0-5fe8-a273-fe3b70a3edc2",
    ),
    (
        "tenant-contributor",
        "Tenant Contributor",
        "tenant:get-object",
        "aded7e13-b6de-54fd-8ddd-de1009611179",
        "713c550d-b88c-5ec8-882e-7c592884bebd",
    ),
    (
        "tenant-reader",
        "Tenant Reader",
        "tenant:get-object",
        "babc80ad-448a-5533-81c0-a558b43f2434",
        "8260fdea-7bb7-5b4c-9433-44006e39fdf3",
    ),
    (
        "organization-administrator",
        "Organization Administrator",
        "organization:get-object",
        "ea4c7027-67f1-52f5-b249-3006c41b122b",
        "9e6153ad-0071-5a89-a322-a69185b9e32a",
    ),
    (
        "organization-security-administrator",
        "Organization Security Administrator",
        "role:get-object",
        "3d7d1473-bdba-53fa-a841-8ec02ce326db",
        "92ca8929-3563-5387-92a7-bf0679a10132",
    ),
    (
        "organization-contributor",
        "Organization Contributor",
        "organization:get-object",
        "2cab5378-81e9-53e6-966e-9aa7813e96d9",
        "40fcf83f-37d6-5a50-aa60-d371dc739aad",
    ),
    (
        "organization-reader",
        "Organization Reader",
        "organization:get-object",
        "2d937b29-264e-578a-83d1-21cd13c6923e",
        "d18a1bd3-dc89-5e64-a019-64a419dd3f75",
    ),
)

APPROVED_ACTIONS = {
    "urn:mtmf:iam:actions:system:tenant:get-object",
    "urn:mtmf:iam:actions:system:role:get-object",
    "urn:mtmf:iam:actions:system:organization:get-object",
}

_UUID_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/yduchesne/mtmf/pr10/builtin-policy/v1"
)


def _role_urn(suffix: str) -> str:
    return f"urn:mtmf:iam:roles:system:{suffix}"


def _permission_urn(suffix: str) -> str:
    return f"urn:mtmf:iam:permissions:system:{suffix}"


def _installed_rows(db: psycopg.Connection) -> list[tuple[str, str, str, str, str]]:
    return [
        (str(row[0]), str(row[1]), str(row[2]), str(row[3]), str(row[4]))
        for row in db.execute(
            "SELECT r.urn, ps.id, ps.effect, p.id, p.urn "
            "FROM mtmf.builtin_role AS br "
            "JOIN mtmf.role AS r ON r.urn = br.role_urn "
            "JOIN mtmf.permission_set AS ps ON ps.role_urn = r.urn "
            "JOIN mtmf.permission AS p ON p.permission_set_id = ps.id "
            "ORDER BY r.urn"
        ).fetchall()
    ]


def test_bp01_exact_approved_seed_is_installed(db: psycopg.Connection) -> None:
    expected = {
        (_role_urn(role), set_id, "allow", permission_id, _permission_urn(permission))
        for role, _name, permission, set_id, permission_id in APPROVED_SEED
    }
    installed = set(_installed_rows(db))
    assert installed == expected
    assert len(installed) == 11

    actions = {
        str(row[0])
        for row in db.execute(
            "SELECT urn FROM mtmf.action WHERE urn = ANY(%s)", (list(APPROVED_ACTIONS),)
        ).fetchall()
    }
    assert actions == APPROVED_ACTIONS
    assert db.execute("SELECT count(*) FROM mtmf.builtin_role").fetchone()[0] == 11
    assert db.execute("SELECT count(*) FROM mtmf.action").fetchone()[0] == 3
    # No built-in matcher contains a wildcard.
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.permission AS p "
            "JOIN mtmf.permission_set AS ps ON ps.id = p.permission_set_id "
            "JOIN mtmf.builtin_role AS br ON br.role_urn = ps.role_urn "
            "WHERE p.urn LIKE '%%*%%'"
        ).fetchone()[0]
        == 0
    )


def test_bp02_seed_ids_match_published_uuidv5_derivation(db: psycopg.Connection) -> None:
    for role, _name, permission, set_id, permission_id in APPROVED_SEED:
        role_urn = _role_urn(role)
        permission_urn = _permission_urn(permission)
        assert set_id == str(uuid.uuid5(_UUID_NAMESPACE, f"permission-set:{role_urn}"))
        assert permission_id == str(
            uuid.uuid5(_UUID_NAMESPACE, f"permission:{role_urn}:{permission_urn}")
        )


def test_bp03_identical_replay_is_idempotent(db: psycopg.Connection) -> None:
    before = _installed_rows(db)
    db.execute("SELECT mtmf.install_builtin_policy()")
    assert _installed_rows(db) == before
    assert db.execute("SELECT count(*) FROM mtmf.builtin_role").fetchone()[0] == 11


def test_bp04_conflicting_existing_definition_fails_closed(db: psycopg.Connection) -> None:
    approved_permission = APPROVED_SEED[0][4]
    target_set = APPROVED_SEED[0][3]
    conflicting_urn = _permission_urn("tenant:update-object")
    # Replace the approved Permission with the same object identity but a
    # conflicting exact matcher. A replay must detect the mismatch, refuse
    # to "repair" it, and roll back its own work.
    db.execute("DELETE FROM mtmf.permission WHERE permission_set_id = %s", (target_set,))
    db.execute(
        "INSERT INTO mtmf.permission (id, permission_set_id, urn, position) VALUES (%s, %s, %s, 0)",
        (approved_permission, target_set, conflicting_urn),
    )
    with pytest.raises(psycopg.Error) as captured:
        db.execute("SELECT mtmf.install_builtin_policy()")
    assert captured.value.sqlstate == "MT010"
    # The failed install never repaired the conflicting row.
    assert (
        db.execute(
            "SELECT urn FROM mtmf.permission WHERE permission_set_id = %s", (target_set,)
        ).fetchone()[0]
        == conflicting_urn
    )


def test_bp05_runtime_cannot_save_a_builtin_role(runtime_connection: psycopg.Connection) -> None:
    role_urn = _role_urn("tenant-administrator")
    payload = {
        "urn": role_urn,
        "name": "Hijacked",
        "description": "",
        "defining_tenant_id": None,
        "extension": {},
        "permission_sets": [],
    }
    with pytest.raises(psycopg.Error) as captured:
        runtime_connection.execute("SELECT mtmf.role_save(%s)", (Jsonb(payload),))
    assert captured.value.sqlstate == "MT010"
    runtime_connection.rollback()


def test_bp06_runtime_cannot_execute_the_seed_installer(
    runtime_connection: psycopg.Connection,
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("SELECT mtmf.install_builtin_policy()")
    runtime_connection.rollback()


def test_bp07_runtime_cannot_read_the_builtin_registry(
    runtime_connection: psycopg.Connection,
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("SELECT * FROM mtmf.builtin_role")
    runtime_connection.rollback()


def test_bp08_role_add_cannot_replace_a_builtin_definition(
    runtime_connection: psycopg.Connection, db: psycopg.Connection
) -> None:
    payload = {
        "urn": "urn:mtmf:iam:roles:system:tenant-administrator",
        "name": "Hijacked",
        "description": "",
        "defining_tenant_id": None,
        "extension": {},
        "permission_sets": [],
    }
    result = runtime_connection.execute("SELECT mtmf.role_add(%s)", (Jsonb(payload),)).fetchone()[0]
    # ON CONFLICT DO NOTHING: the existing built-in definition is untouched.
    assert result is False
    runtime_connection.rollback()
    assert (
        db.execute(
            "SELECT name FROM mtmf.role "
            "WHERE urn = 'urn:mtmf:iam:roles:system:tenant-administrator'"
        ).fetchone()[0]
        == "Tenant Administrator"
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.permission_set ps "
            "JOIN mtmf.builtin_role br ON br.role_urn = ps.role_urn"
        ).fetchone()[0]
        == 11
    )
