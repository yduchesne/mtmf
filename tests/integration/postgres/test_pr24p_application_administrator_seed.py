"""Real-PostgreSQL acceptance for the approved 0017 Application Administrator seed."""

from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest

ROLE = "urn:mtmf:iam:roles:system:application-administrator"
SET_ID = "ef895e22-cc8b-53db-a804-7ef11cffcb60"
NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/yduchesne/mtmf/pr10/builtin-policy/v1"
)
PERMISSIONS = (
    (
        "25a2f2f4-f32d-5447-bf39-578b4b4c312c",
        "urn:mtmf:iam:permissions:system:application:create-object",
    ),
    (
        "da26e3bd-b3cb-5232-9910-3bc5b7f7fdda",
        "urn:mtmf:iam:permissions:system:application:get-object",
    ),
    (
        "1ed11804-0a69-5a0f-89eb-3665b7c6cef4",
        "urn:mtmf:iam:permissions:system:application:suspend-object",
    ),
    (
        "84ec050a-8732-51c5-9ca0-304e8347f642",
        "urn:mtmf:iam:permissions:system:application:resume-object",
    ),
    (
        "62ce5487-bbb9-5c3b-ae91-d6fcd560a7bf",
        "urn:mtmf:iam:permissions:system:application:retire-object",
    ),
    (
        "ca253e75-2bb6-58c1-88db-02a191412018",
        "urn:mtmf:iam:permissions:system:application-tenant-registration:add-object",
    ),
    (
        "49b322cf-6b12-5ec2-ae07-71aa541280c8",
        "urn:mtmf:iam:permissions:system:application-tenant-registration:get-object",
    ),
    (
        "ea1a042a-dc5a-5e5c-aab9-a19d995d2e58",
        "urn:mtmf:iam:permissions:system:application-tenant-registration:revoke-object",
    ),
    (
        "909403b6-cb5c-5722-91f6-fac47e86fb15",
        "urn:mtmf:iam:permissions:system:application-onboarding-entitlement:grant-object",
    ),
    (
        "4a07317d-5c71-5118-9b95-899745a404f9",
        "urn:mtmf:iam:permissions:system:application-onboarding-entitlement:revoke-object",
    ),
    (
        "77915183-0f56-5329-8669-f1958d354cf1",
        "urn:mtmf:iam:permissions:system:application-onboarding-entitlement:get-object",
    ),
)
SEED_SQL = Path(
    "packages/mtmf-core/src/mtmf_core/persistence/postgres/sql/"
    "v017/01_application_administrator_seed.sql"
)


def test_pr24p_seed_exact_rows_and_uuidv5(db: psycopg.Connection) -> None:
    row = db.execute(
        "SELECT urn, name, description, defining_tenant_id, extension "
        "FROM mtmf.role WHERE urn = %s",
        (ROLE,),
    ).fetchone()
    assert row == (ROLE, "Application Administrator", "", None, {})
    assert db.execute(
        "SELECT id, role_urn, effect, position FROM mtmf.permission_set WHERE role_urn = %s",
        (ROLE,),
    ).fetchall() == [(uuid.UUID(SET_ID), ROLE, "allow", 0)]
    rows = db.execute(
        "SELECT p.id, p.urn, p.position FROM mtmf.permission p "
        "JOIN mtmf.permission_set ps ON ps.id = p.permission_set_id "
        "WHERE ps.role_urn = %s ORDER BY p.position",
        (ROLE,),
    ).fetchall()
    assert [(str(r[0]), r[1], r[2]) for r in rows] == [
        (permission_id, urn, index) for index, (permission_id, urn) in enumerate(PERMISSIONS)
    ]
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.builtin_role WHERE role_urn = %s", (ROLE,)
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.action WHERE urn = ANY(%s)",
            (
                [
                    urn.replace("urn:mtmf:iam:permissions:", "urn:mtmf:iam:actions:")
                    for _id, urn in PERMISSIONS
                ],
            ),
        ).fetchone()[0]
        == 11
    )
    assert db.execute("SELECT count(*) FROM mtmf.system_operator_assignment").fetchone()[0] == 0


def test_pr24p_seed_uuid_derivation_and_replay(db: psycopg.Connection) -> None:
    assert str(uuid.uuid5(NAMESPACE, f"permission-set:{ROLE}")) == SET_ID
    for permission_id, urn in PERMISSIONS:
        assert permission_id == str(uuid.uuid5(NAMESPACE, f"permission:{ROLE}:{urn}"))
    before = db.execute("SELECT count(*) FROM mtmf.permission").fetchone()[0]
    db.execute(SEED_SQL.read_text(encoding="utf-8"))
    assert db.execute("SELECT count(*) FROM mtmf.permission").fetchone()[0] == before


def test_pr24p_seed_drift_fails_closed_without_repair(db: psycopg.Connection) -> None:
    db.execute("BEGIN")
    db.execute("DELETE FROM mtmf.permission WHERE id = %s", (PERMISSIONS[0][0],))
    with pytest.raises(psycopg.Error) as captured:
        db.execute(SEED_SQL.read_text(encoding="utf-8"))
    assert captured.value.sqlstate == "MT010"
    db.execute("ROLLBACK")
    assert (
        db.execute(
            "SELECT urn FROM mtmf.permission WHERE id = %s", (PERMISSIONS[0][0],)
        ).fetchone()[0]
        == PERMISSIONS[0][1]
    )
