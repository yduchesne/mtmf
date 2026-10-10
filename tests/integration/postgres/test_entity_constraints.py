"""Entity structural-integrity tests (LIFE, EXT, TEN).

Lifecycle: deletion_status values are exactly DELETED=1 / NOT_DELETED=2;
0, arbitrary values, and NULL are rejected. Extension: application-owned
extension is object-constrained ``jsonb`` (default ``{}``; nested JSON
null accepted; top-level null/array/scalar and SQL NULL rejected) on
every extension-bearing table, and Permission/PermissionSet carry no
extension. TEN: Tenant scope, foreign keys, non-cascading deletes,
non-unique display names, and the absence of a Tenant column on global
Principal/Identity.
"""

from __future__ import annotations

import helpers
import psycopg
import psycopg.errors
import psycopg.sql
import pytest

# --- LIFE: lifecycle ----------------------------------------------------------


def _row_builder(table: str) -> psycopg.sql.SQL:
    """An INSERT head for one deletion-status-bearing table.

    The identity columns are always fresh (the ``%s`` placeholders from
    the caller supply them) so the row never collides with the seeded
    base graph. The caller passes (fresh_id, deletion_value). Table
    names are composed with :class:`psycopg.sql.Identifier`.
    """
    identifier = psycopg.sql.Identifier(table)
    if table == "tenant":
        return psycopg.sql.SQL(
            "INSERT INTO mtmf.{} "
            "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
            "VALUES (%s, 'T', 2, {}, 1, %s)"
        ).format(identifier, psycopg.sql.Literal(helpers.IDENTITY_A))
    if table == "organization":
        return psycopg.sql.SQL(
            "INSERT INTO mtmf.{} "
            "(id, tenant_id, name, owner_identity_id, deletion_status) "
            "VALUES (%s, {}, 'O', {}, %s)"
        ).format(
            identifier,
            psycopg.sql.Literal(helpers.TENANT_A),
            psycopg.sql.Literal(helpers.IDENTITY_A),
        )
    if table == "principal":
        return psycopg.sql.SQL(
            "INSERT INTO mtmf.{} (id, name, deletion_status) VALUES (%s, 'P', %s)"
        ).format(identifier)
    if table == "identity":
        return psycopg.sql.SQL(
            "INSERT INTO mtmf.{} "
            "(id, principal_id, name, origin, deletion_status) VALUES (%s, {}, 'I', 1, %s)"
        ).format(identifier, psycopg.sql.Literal(helpers.PRINCIPAL))
    return psycopg.sql.SQL(
        "INSERT INTO mtmf.{} (id, tenant_id, name, deletion_status) VALUES (%s, {}, 'G', %s)"
    ).format(identifier, psycopg.sql.Literal(helpers.TENANT_A))


@pytest.mark.parametrize("table", sorted(helpers.DELETION_TABLES))
def test_life01_and_life02_legal_deletion_values_accepted(db, dsn: str, table: str) -> None:
    helpers.seed_base_entities(db)
    for value in (1, 2):
        connection = psycopg.connect(dsn)
        try:
            with connection.transaction():
                connection.execute(_row_builder(table), (helpers.new_id(), value))
        finally:
            connection.close()


@pytest.mark.parametrize("table", sorted(helpers.DELETION_TABLES))
@pytest.mark.parametrize("invalid", (0, 9, -1))
def test_life03_and_life04_invalid_deletion_values_rejected(
    db, dsn: str, table: str, invalid: int
) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
            connection.execute(_row_builder(table), (helpers.new_id(), invalid))
    finally:
        connection.close()


@pytest.mark.parametrize("table", sorted(helpers.DELETION_TABLES))
def test_life05_null_deletion_status_rejected(db, dsn: str, table: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.NotNullViolation), connection.transaction():
            connection.execute(_row_builder(table), (helpers.new_id(), None))
    finally:
        connection.close()


# --- EXT: extension JSON ------------------------------------------------------


def _extension_where_column(table: str) -> str:
    """The identity column of one extension-bearing table."""
    return "urn" if table == "role" else "id"


def _extension_target(table: str) -> str:
    return {
        "tenant": "44444444-4444-4444-8444-444444444444",
        "organization": "66666666-6666-4666-8666-666666666666",
        "principal": "11111111-1111-4111-8111-111111111111",
        "identity": "22222222-2222-4222-8222-222222222222",
        "group": "88888888-8888-4888-8888-888888888888",
        "role": "urn:mtmf:iam:roles:system:integration-role",
    }[table]


def _seed_role_row_if_required(db, table: str, target: str) -> None:
    """Ensure the extension-bearing role row exists for role tests."""
    if table == "role":
        db.execute(
            "INSERT INTO mtmf.role (urn, name) VALUES (%s, 'Integration Role')",
            (target,),
        )


@pytest.mark.parametrize("table", sorted(helpers.EXTENSION_TABLES))
def test_ext01_empty_object_default(db, dsn: str, table: str) -> None:
    helpers.seed_base_entities(db)
    target = _extension_target(table)
    _seed_role_row_if_required(db, table, target)
    connection = psycopg.connect(dsn)
    where = _extension_where_column(table)
    try:
        with connection.transaction():
            composed = psycopg.sql.SQL(
                "UPDATE mtmf.{} SET extension = {}::jsonb WHERE {} = %s"
            ).format(
                psycopg.sql.Identifier(table),
                psycopg.sql.Literal("{}"),
                psycopg.sql.Identifier(where),
            )
            connection.execute(composed, (target,))
            select = psycopg.sql.SQL("SELECT extension FROM mtmf.{} WHERE {} = %s").format(
                psycopg.sql.Identifier(table), psycopg.sql.Identifier(where)
            )
            loaded = connection.execute(select, (target,)).fetchone()[0]
            assert loaded == {}
    finally:
        connection.close()


@pytest.mark.parametrize("table", sorted(helpers.EXTENSION_TABLES))
@pytest.mark.parametrize(
    ("value", "accepted"),
    [
        ('{"a": 1}', True),  # EXT02 non-empty object accepted
        ('{"outer": {"inner": [1, null, {"deep": null}]}}', True),  # EXT03 nested null
        ("null", False),  # EXT04 top-level JSON null rejected
        ("[1, 2]", False),  # EXT05 array rejected
        ('"scalar"', False),  # EXT06 scalar rejected
    ],
)
def test_ext02_to_ext06_extension_shape_enforced(
    db, dsn: str, table: str, value: str, accepted: bool
) -> None:
    helpers.seed_base_entities(db)
    target = _extension_target(table)
    _seed_role_row_if_required(db, table, target)
    connection = psycopg.connect(dsn)
    where = _extension_where_column(table)
    try:
        with connection.transaction():
            composed = psycopg.sql.SQL(
                "UPDATE mtmf.{} SET extension = %s::jsonb WHERE {} = %s"
            ).format(
                psycopg.sql.Identifier(table),
                psycopg.sql.Identifier(where),
            )
            if accepted:
                connection.execute(composed, (value, target))
            else:
                with pytest.raises(psycopg.errors.CheckViolation):
                    connection.execute(composed, (value, target))
    finally:
        connection.close()


@pytest.mark.parametrize("table", sorted(helpers.EXTENSION_TABLES))
def test_ext07_sql_null_extension_rejected(db, dsn: str, table: str) -> None:
    helpers.seed_base_entities(db)
    target = _extension_target(table)
    _seed_role_row_if_required(db, table, target)
    connection = psycopg.connect(dsn)
    where = _extension_where_column(table)
    try:
        composed = psycopg.sql.SQL("UPDATE mtmf.{} SET extension = NULL WHERE {} = %s").format(
            psycopg.sql.Identifier(table),
            psycopg.sql.Identifier(where),
        )
        with pytest.raises(psycopg.errors.NotNullViolation), connection.transaction():
            connection.execute(composed, (target,))
    finally:
        connection.close()


def test_ext_permission_and_permission_set_have_no_extension(db) -> None:
    for table in ("permission", "permission_set"):
        assert "extension" not in helpers.columns_of(db, table)


# --- TEN: entity structural integrity ----------------------------------------


@pytest.mark.parametrize("scope", (0, 2))
def test_ten01_and_ten02_tenant_legal_scopes_accepted(db, dsn: str, scope: int) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.tenant "
                "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
                "VALUES (%s, 'T', %s, %s, 1, 2)",
                (helpers.new_id(), scope, helpers.IDENTITY_A),
            )
    finally:
        connection.close()


@pytest.mark.parametrize("scope", (1, 3, 5))
def test_ten03_system_and_organization_tenant_scopes_rejected(db, dsn: str, scope: int) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.CheckViolation), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.tenant "
                "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
                "VALUES (%s, 'T', %s, %s, 1, 2)",
                (helpers.new_id(), scope, helpers.IDENTITY_A),
            )
    finally:
        connection.close()


def test_ten04_organization_requires_tenant(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.organization "
                "(id, tenant_id, name, owner_identity_id, deletion_status) "
                "VALUES (%s, %s, 'O', %s, 2)",
                (helpers.new_id(), helpers.new_id(), helpers.IDENTITY_A),
            )
    finally:
        connection.close()


def test_ten05_identity_requires_principal(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
                "VALUES (%s, %s, 'I', 1, 2)",
                (helpers.new_id(), helpers.new_id()),
            )
    finally:
        connection.close()


def test_ten06_group_requires_tenant(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) "
                "VALUES (%s, %s, 'G', 2)",
                (helpers.new_id(), helpers.new_id()),
            )
    finally:
        connection.close()


def test_ten07_owner_identity_fks_enforced(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.tenant "
                "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
                "VALUES (%s, 'T', 2, %s, 1, 2)",
                (helpers.new_id(), helpers.new_id()),
            )
    finally:
        connection.close()


def test_ten08_hard_delete_does_not_cascade(db, dsn: str) -> None:
    # Soft deletion is the domain model: hard DELETEs of referenced rows
    # are blocked by restrictive FKs, never cascaded.
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            connection.execute("DELETE FROM mtmf.principal WHERE id = %s", (helpers.PRINCIPAL,))
    finally:
        connection.close()


def test_ten09_duplicate_display_names_allowed(db, dsn: str) -> None:
    helpers.seed_base_entities(db)
    connection = psycopg.connect(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "INSERT INTO mtmf.tenant "
                "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
                "VALUES (%s, 'Tenant A', 2, %s, 1, 2)",
                (helpers.new_id(), helpers.IDENTITY_A),
            )
            connection.execute(
                "INSERT INTO mtmf.tenant "
                "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
                "VALUES (%s, 'Tenant A', 2, %s, 1, 2)",
                (helpers.new_id(), helpers.IDENTITY_A),
            )
    finally:
        connection.close()


def test_ten10_principal_and_identity_have_no_tenant_ownership_column(db) -> None:
    for table in ("principal", "identity"):
        assert "tenant_id" not in helpers.columns_of(db, table)
