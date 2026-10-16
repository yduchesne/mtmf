"""PR 19B PostgreSQL 18 acceptance for security-mutation-audit partitioning.

Runs against a real, explicitly configured MTMF PostgreSQL 18 database. The
suite proves the P01-P19 acceptance matrix: the native monthly ``RANGE
(occurred_at)`` conversion, exact historical-row preservation, half-open UTC
boundary routing, append-only guard inheritance across parent and direct
children, the confined fixed-depth partition horizon, owner-only idempotent
provisioning, concurrency, and the unchanged runtime privilege surface.

No fake database, fake authorization, or monkeypatched SQL execution is used
for feature acceptance. The real PR 19C repository/stored-function writer is
exercised unchanged.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import helpers
import psycopg
import pytest
from psycopg import sql

from mtmf_core import DomainId
from mtmf_core.domain.iam_urn import ActionUrn
from mtmf_core.persistence.errors import PersistenceError
from mtmf_core.persistence.postgres import (
    MigrationError,
    PostgresConfig,
    PostgresMigrationManager,
    expected_runtime_signatures,
)
from mtmf_core.persistence.spi import MtmfSpi

PARENT = "security_mutation_audit"
_TENANT_ADMIN_URN = "urn:mtmf:iam:roles:system:tenant-administrator"
_ACTION_URN = ActionUrn("urn:mtmf:iam:actions:system:identity-group-membership:add-object")
_AUDIT_COLUMNS = (
    "id",
    "occurred_at",
    "authorized_at",
    "actor_identity_id",
    "actor_principal_id",
    "tenant_id",
    "application_id",
    "action_urn",
    "target_kind",
    "target_id",
    "subject_identity_id",
    "outcome",
)
_AUDIT_SELECT = (
    "SELECT id, occurred_at, authorized_at, actor_identity_id, actor_principal_id, "
    "tenant_id, application_id, action_urn, target_kind, target_id, "
    "subject_identity_id, outcome FROM mtmf.security_mutation_audit "
    "ORDER BY occurred_at, id"
)


# --- fixtures and helpers ----------------------------------------------------


@pytest.fixture
def owner(migrator_config: PostgresConfig) -> psycopg.Connection:
    """An autocommit connection operating as ``mtmf_owner`` (privileged DDL)."""
    connection = psycopg.connect(migrator_config.psycopg_dsn, autocommit=True)
    connection.execute("SET ROLE mtmf_owner")
    try:
        yield connection
    finally:
        connection.close()


def _sid() -> str:
    return str(uuid.uuid4())


def _current_month_start() -> datetime:
    now = datetime.now(UTC)
    return datetime(now.year, now.month, 1, tzinfo=UTC)


def _next_month(moment: datetime) -> datetime:
    if moment.month == 12:
        return datetime(moment.year + 1, 1, 1, tzinfo=UTC)
    return datetime(moment.year, moment.month + 1, 1, tzinfo=UTC)


def _after_months(moment: datetime, count: int) -> datetime:
    for _ in range(count):
        moment = _next_month(moment)
    return moment


def _month_partition_name(moment: datetime) -> str:
    return f"{PARENT}_y{moment.year:04d}m{moment.month:02d}"


def _partition_rows(connection: psycopg.Connection) -> list[tuple[str, str]]:
    return [
        (str(row[0]), str(row[1]))
        for row in connection.execute(
            "SELECT c.relname, pg_get_expr(c.relpartbound, c.oid) "
            "FROM pg_catalog.pg_inherits AS i "
            "JOIN pg_catalog.pg_class AS c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'mtmf.security_mutation_audit'::regclass "
            "AND c.relkind = 'r' ORDER BY c.relname"
        ).fetchall()
    ]


def _partition_name_set(connection: psycopg.Connection) -> set[str]:
    return {name for name, _bound in _partition_rows(connection)}


def _insert_audit(
    connection: psycopg.Connection,
    *,
    occurred_at: datetime | str,
    operation_id: str | None = None,
) -> str:
    operation_id = operation_id or _sid()
    connection.execute(
        "INSERT INTO mtmf.security_mutation_audit "
        "(id, occurred_at, authorized_at, actor_identity_id, actor_principal_id, "
        " tenant_id, application_id, action_urn, target_kind, target_id, "
        " subject_identity_id, outcome) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'identity_group_membership', %s, %s, 'CREATED')",
        (
            operation_id,
            occurred_at,
            occurred_at,
            _sid(),
            _sid(),
            _sid(),
            _sid(),
            "urn:mtmf:iam:actions:system:identity-group-membership:add-object",
            _sid(),
            _sid(),
        ),
    )
    return operation_id


def _seed_v012_rows(
    connection: psycopg.Connection, timestamps: list[datetime]
) -> list[tuple[object, ...]]:
    for moment in timestamps:
        _insert_audit(connection, occurred_at=moment)
    return _snapshot(connection)


def _snapshot(connection: psycopg.Connection) -> list[tuple[object, ...]]:
    return list(connection.execute(_AUDIT_SELECT).fetchall())


def _reset_to_revision(config: PostgresConfig, migrator: PostgresConfig, revision: str) -> None:
    with psycopg.connect(config.psycopg_dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
        connection.execute("CREATE SCHEMA IF NOT EXISTS mtmf")
        connection.execute("ALTER SCHEMA mtmf OWNER TO mtmf_owner")
    helpers.upgrade_to_revision(migrator, revision)


def _assert_mt033(connection: psycopg.Connection, statement: sql.SQL | sql.Composed | str) -> None:
    with pytest.raises(psycopg.Error) as excinfo:
        connection.execute(statement)
    assert excinfo.value.sqlstate == "MT033", excinfo.value


# --- P01: fresh install ------------------------------------------------------


def test_p01_fresh_install_is_partitioned_parent(db: psycopg.Connection) -> None:
    parent = db.execute(
        "SELECT relkind FROM pg_catalog.pg_class "
        "WHERE oid = 'mtmf.security_mutation_audit'::regclass"
    ).fetchone()[0]
    assert parent == "p"
    assert (
        db.execute("SELECT pg_get_partkeydef('mtmf.security_mutation_audit'::regclass)").fetchone()[
            0
        ]
        == "RANGE (occurred_at)"
    )
    assert [
        row[0]
        for row in db.execute(
            "SELECT a.attname FROM pg_catalog.pg_constraint con "
            "JOIN pg_catalog.pg_attribute a ON a.attrelid = con.conrelid "
            "  AND a.attnum = ANY(con.conkey) "
            "WHERE con.conrelid = 'mtmf.security_mutation_audit'::regclass "
            "AND con.contype = 'p' ORDER BY array_position(con.conkey, a.attnum)"
        ).fetchall()
    ] == ["occurred_at", "id"]

    columns = db.execute(
        "SELECT column_name, data_type, is_nullable FROM information_schema.columns "
        "WHERE table_schema = 'mtmf' AND table_name = 'security_mutation_audit' "
        "ORDER BY ordinal_position"
    ).fetchall()
    assert [row[0] for row in columns] == list(_AUDIT_COLUMNS)
    assert len(columns) == 12
    assert (
        db.execute(
            "SELECT pg_get_expr(d.adbin, d.adrelid) FROM pg_attrdef d "
            "JOIN pg_attribute a ON a.attrelid = d.adrelid AND a.attnum = d.adnum "
            "WHERE d.adrelid = 'mtmf.security_mutation_audit'::regclass "
            "AND a.attname = 'occurred_at'"
        ).fetchone()[0]
        == "clock_timestamp()"
    )
    checks = {
        row[0]
        for row in db.execute(
            "SELECT conname FROM pg_catalog.pg_constraint "
            "WHERE conrelid = 'mtmf.security_mutation_audit'::regclass AND contype = 'c'"
        ).fetchall()
    }
    assert checks == {
        "security_mutation_audit_outcome_check",
        "security_mutation_audit_target_kind_check",
        "security_mutation_audit_action_urn_check",
    }
    index_defs = {
        row[0]: row[1]
        for row in db.execute(
            "SELECT i.relname, pg_get_indexdef(i.oid) FROM pg_index x "
            "JOIN pg_class i ON i.oid = x.indexrelid "
            "WHERE x.indrelid = 'mtmf.security_mutation_audit'::regclass"
        ).fetchall()
    }
    assert "security_mutation_audit_tenant_occurred_idx" in index_defs
    assert "security_mutation_audit_target_occurred_idx" in index_defs

    months: set[datetime] = set()
    cursor = _current_month_start()
    for _ in range(13):
        months.add(cursor)
        cursor = _next_month(cursor)
    present = _partition_name_set(db)
    for month in months:
        assert _month_partition_name(month) in present
    assert all(bound != "DEFAULT" for _name, bound in _partition_rows(db))
    assert (
        db.execute("SELECT to_regclass('mtmf.security_mutation_audit_v012_backup')").fetchone()[0]
        is None
    )

    # Append-only guards exist on the parent and on every child.
    parent_triggers = {
        row[0]
        for row in db.execute(
            "SELECT tgname FROM pg_catalog.pg_trigger "
            "WHERE tgrelid = 'mtmf.security_mutation_audit'::regclass AND NOT tgisinternal"
        ).fetchall()
    }
    assert parent_triggers == {
        "security_mutation_audit_update_guard",
        "security_mutation_audit_delete_guard",
        "security_mutation_audit_truncate_guard",
    }
    for name, _bound in _partition_rows(db):
        child_triggers = {
            row[0]
            for row in db.execute(
                "SELECT tgname FROM pg_catalog.pg_trigger "
                "WHERE tgrelid = %s::regclass AND NOT tgisinternal",
                (f"mtmf.{name}",),
            ).fetchall()
        }
        assert child_triggers == parent_triggers


# --- P02: upgrade from 0012 with historical rows -----------------------------


def test_p02_upgrade_from_0012_preserves_historical_rows(
    mtmf_config: PostgresConfig, migrator_config: PostgresConfig
) -> None:
    _reset_to_revision(mtmf_config, migrator_config, "0012")
    connection = psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True)
    try:
        assert (
            connection.execute(
                "SELECT relkind FROM pg_catalog.pg_class "
                "WHERE oid = 'mtmf.security_mutation_audit'::regclass"
            ).fetchone()[0]
            == "r"
        )
        timestamps = [
            datetime(2024, 1, 31, 23, 59, 59, 999000, tzinfo=UTC),
            datetime(2024, 2, 1, 0, 0, tzinfo=UTC),
            datetime(2024, 2, 29, 12, 0, tzinfo=UTC),
            datetime(2024, 3, 1, 0, 0, tzinfo=UTC),
        ]
        before = _seed_v012_rows(connection, timestamps)
        original_ids = {row[0] for row in before}
        PostgresMigrationManager(migrator_config).upgrade_to_head()
        after = _snapshot(connection)
        assert after == before
        assert {row[0] for row in after} == original_ids
        routing = dict(
            connection.execute(
                "SELECT c.relname, count(*) FROM mtmf.security_mutation_audit a "
                "JOIN pg_catalog.pg_class c ON c.oid = a.tableoid GROUP BY c.relname"
            ).fetchall()
        )
        assert routing.get("security_mutation_audit_y2024m01") == 1
        assert routing.get("security_mutation_audit_y2024m02") == 2
        assert routing.get("security_mutation_audit_y2024m03") == 1
        assert (
            connection.execute(
                "SELECT count(*) FROM mtmf.security_mutation_audit "
                "WHERE tableoid = 'mtmf.security_mutation_audit'::regclass"
            ).fetchone()[0]
            == 0
        )
    finally:
        connection.close()


# --- P03/P04: uniqueness semantics ------------------------------------------


def test_p03_duplicate_occurred_at_and_id_is_rejected(db: psycopg.Connection) -> None:
    moment = _current_month_start() + timedelta(days=3)
    operation_id = _sid()
    _insert_audit(db, occurred_at=moment, operation_id=operation_id)
    with pytest.raises(psycopg.errors.UniqueViolation):
        _insert_audit(db, occurred_at=moment, operation_id=operation_id)
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 1


def test_p04_same_id_in_different_months_is_allowed(db: psycopg.Connection) -> None:
    operation_id = _sid()
    first = _current_month_start() + timedelta(days=3)
    second = _next_month(_current_month_start()) + timedelta(days=3)
    _insert_audit(db, occurred_at=first, operation_id=operation_id)
    _insert_audit(db, occurred_at=second, operation_id=operation_id)
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 2


# --- P05: UTC half-open boundary routing -------------------------------------


def test_p05_boundaries_route_in_utc_independent_of_session_timezone(
    db: psycopg.Connection,
) -> None:
    turn = _next_month(_current_month_start())
    just_before = turn - timedelta(microseconds=1)
    db.execute("SET TIME ZONE 'America/New_York'")
    try:
        _insert_audit(db, occurred_at=just_before)  # current month
        _insert_audit(db, occurred_at=turn)  # next month (at)
        _insert_audit(db, occurred_at=turn + timedelta(microseconds=1))  # next month (after)
    finally:
        db.execute("SET TIME ZONE 'UTC'")
    routing = dict(
        db.execute(
            "SELECT c.relname, count(*) FROM mtmf.security_mutation_audit a "
            "JOIN pg_catalog.pg_class c ON c.oid = a.tableoid GROUP BY c.relname"
        ).fetchall()
    )
    assert routing == {
        _month_partition_name(_current_month_start()): 1,
        _month_partition_name(turn): 2,
    }


# --- P06: fixed horizon ------------------------------------------------------


def test_p06_horizon_covers_thirteen_months_and_rejects_beyond(db: psycopg.Connection) -> None:
    present = _partition_name_set(db)
    cursor = _current_month_start()
    for _ in range(13):
        assert _month_partition_name(cursor) in present
        cursor = _next_month(cursor)
    beyond = cursor + timedelta(days=3)  # one month past the horizon
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        _insert_audit(db, occurred_at=beyond)
    assert all(bound != "DEFAULT" for _name, bound in _partition_rows(db))


# --- P07/P08/P09: privileged provisioning -----------------------------------


def test_p07_privileged_ensure_is_idempotent(
    db: psycopg.Connection, owner: psycopg.Connection
) -> None:
    target = _after_months(_current_month_start(), 13)
    name = _month_partition_name(target)
    assert name not in _partition_name_set(db)
    owner.execute("SELECT mtmf.ensure_security_mutation_audit_month(%s)", (target.date(),))
    assert name in _partition_name_set(db)
    assert (
        db.execute(
            "SELECT count(*) FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class c "
            "ON c.oid = i.inhrelid WHERE i.inhparent = 'mtmf.security_mutation_audit'::regclass "
            "AND c.relname = %s",
            (name,),
        ).fetchone()[0]
        == 1
    )
    owner.execute("SELECT mtmf.ensure_security_mutation_audit_month(%s)", (target.date(),))
    assert sum(1 for candidate, _bound in _partition_rows(db) if candidate == name) == 1
    assert (
        db.execute(
            "SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgrelid = %s::regclass "
            "AND NOT tgisinternal",
            (f"mtmf.{name}",),
        ).fetchone()[0]
        == 3
    )


def test_p08_ensure_rejects_invalid_inputs_without_ddl(owner: psycopg.Connection) -> None:
    before = _partition_rows(owner)
    for argument in ("NULL", "DATE '2030-03-15'", "DATE '9999-12-01'"):
        with pytest.raises(psycopg.Error) as excinfo:
            owner.execute(f"SELECT mtmf.ensure_security_mutation_audit_month({argument})")
        assert excinfo.value.sqlstate == "22023", excinfo.value
    assert _partition_rows(owner) == before


def test_p09_ensure_rejects_wrongly_attached_name(
    db: psycopg.Connection, owner: psycopg.Connection
) -> None:
    target = _after_months(_current_month_start(), 13)
    name = _month_partition_name(target)
    owner.execute(sql.SQL("CREATE TABLE mtmf.{} (sentinel integer)").format(sql.Identifier(name)))
    try:
        with pytest.raises(psycopg.Error) as excinfo:
            owner.execute("SELECT mtmf.ensure_security_mutation_audit_month(%s)", (target.date(),))
        assert excinfo.value.sqlstate == "55000"
        columns = helpers.columns_of(db, name)
        assert columns == {"sentinel": "integer"}
        assert (
            db.execute(
                "SELECT count(*) FROM pg_catalog.pg_inherits WHERE inhrelid = %s::regclass",
                (f"mtmf.{name}",),
            ).fetchone()[0]
            == 0
        )
    finally:
        owner.execute(sql.SQL("DROP TABLE mtmf.{}").format(sql.Identifier(name)))


# --- P10: concurrent provisioning -------------------------------------------


def test_p10_concurrent_ensure_creates_exactly_one_partition(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    target = _after_months(_current_month_start(), 14)
    month = target.date()
    barrier = threading.Barrier(2)
    results: dict[str, str] = {}

    def worker(name: str) -> None:
        connection = psycopg.connect(migrator_config.psycopg_dsn, autocommit=True)
        connection.execute("SET ROLE mtmf_owner")
        try:
            barrier.wait(timeout=10)
            connection.execute("SELECT mtmf.ensure_security_mutation_audit_month(%s)", (month,))
            results[name] = "ok"
        except Exception as exc:  # pragma: no cover - diagnostic
            results[name] = type(exc).__name__
        finally:
            connection.close()

    threads = [threading.Thread(target=worker, args=(name,)) for name in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert results == {"a": "ok", "b": "ok"}, results
    name = _month_partition_name(target)
    assert sum(1 for candidate, _bound in _partition_rows(db) if candidate == name) == 1


# --- P11: append-only guards -------------------------------------------------


def test_p11_append_only_guards_cover_parent_and_children(
    db: psycopg.Connection, owner: psycopg.Connection
) -> None:
    _insert_audit(db, occurred_at=_current_month_start() + timedelta(days=1))
    child = _month_partition_name(_current_month_start())
    _assert_mt033(
        owner, sql.SQL("UPDATE mtmf.{} SET outcome = 'CREATED'").format(sql.Identifier(child))
    )
    _assert_mt033(owner, sql.SQL("DELETE FROM mtmf.{}").format(sql.Identifier(child)))
    _assert_mt033(owner, sql.SQL("TRUNCATE mtmf.{}").format(sql.Identifier(child)))
    _assert_mt033(owner, "UPDATE mtmf.security_mutation_audit SET outcome = 'CREATED'")
    _assert_mt033(owner, "DELETE FROM mtmf.security_mutation_audit")
    _assert_mt033(owner, "TRUNCATE mtmf.security_mutation_audit")
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 1


# --- P12: runtime privilege confinement -------------------------------------


def test_p12_runtime_cannot_touch_audit_or_provision(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    statements = (
        "SELECT count(*) FROM mtmf.security_mutation_audit",
        "INSERT INTO mtmf.security_mutation_audit (id, authorized_at, actor_identity_id, "
        "actor_principal_id, tenant_id, application_id, action_urn, target_kind, target_id, "
        "subject_identity_id, outcome) VALUES (gen_random_uuid(), now(), gen_random_uuid(), "
        "gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 'x', "
        "'identity_group_membership', gen_random_uuid(), gen_random_uuid(), 'CREATED')",
        "UPDATE mtmf.security_mutation_audit SET outcome = 'CREATED'",
        "DELETE FROM mtmf.security_mutation_audit",
        "TRUNCATE mtmf.security_mutation_audit",
        "SELECT mtmf.ensure_security_mutation_audit_month(DATE '2030-01-01')",
    )
    for statement in statements:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute(statement)
        runtime_connection.rollback()

    executable = {
        row[0]
        for row in db.execute(
            "SELECT format('%I.%I(%s)', n.nspname, p.proname, "
            "pg_get_function_identity_arguments(p.oid)) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'mtmf' AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')"
        ).fetchall()
    }
    assert executable == set(expected_runtime_signatures())


# --- P13/P14/P15: the real audited writer -----------------------------------


def _seed_writer_graph(db: psycopg.Connection) -> dict[str, str]:
    tenant, other_tenant = _sid(), _sid()
    principal, actor, subject, group, application = (_sid() for _ in range(5))
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (principal,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'Actor', 2, 2), (%s, %s, 'Subject', 2, 2)",
        (actor, principal, subject, principal),
    )
    db.execute(
        "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'T', 2, %s, 1, 2), (%s, 'Other', 2, %s, 1, 2)",
        (tenant, actor, other_tenant, actor),
    )
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s, %s, 'G', 2)",
        (group, tenant),
    )
    db.execute("INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)", (principal, tenant))
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s), (%s, %s)",
        (actor, tenant, subject, tenant),
    )
    db.execute("INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)", (group, tenant))
    db.execute(
        "INSERT INTO mtmf.identity_role_assignment (id, tenant_id, identity_id, role_urn) "
        "VALUES (%s, %s, %s, %s)",
        (_sid(), tenant, actor, _TENANT_ADMIN_URN),
    )
    db.execute(
        "INSERT INTO mtmf.stewardship_designation "
        "(tenant_id, steward_principal_id, designated_identity_id, version) VALUES (%s, %s, %s, 1)",
        (tenant, principal, actor),
    )
    return {
        "tenant": tenant,
        "principal": principal,
        "actor": actor,
        "subject": subject,
        "group": group,
        "application": application,
    }


def _add_verified(
    spi: MtmfSpi,
    ids: dict[str, str],
    *,
    subject: str | None = None,
    group: str | None = None,
    operation_id: uuid.UUID | None = None,
) -> bool:
    subject = subject or ids["subject"]
    group = group or ids["group"]
    with spi.create_unit_of_work() as uow:
        repository = spi.create_identity_group_membership_repository(uow)
        repository.lock_verified_add(
            tenant_id=DomainId.from_str(ids["tenant"]),
            actor_identity_id=DomainId.from_str(ids["actor"]),
            subject_identity_id=DomainId.from_str(subject),
            group_id=DomainId.from_str(group),
        )
        created = repository.add_verified(
            identity_id=DomainId.from_str(subject),
            group_id=DomainId.from_str(group),
            operation_id=operation_id or uuid.uuid4(),
            actor_identity_id=DomainId.from_str(ids["actor"]),
            actor_principal_id=DomainId.from_str(ids["principal"]),
            tenant_id=DomainId.from_str(ids["tenant"]),
            application_id=DomainId.from_str(ids["application"]),
            action_urn=_ACTION_URN,
            target_kind="identity_group_membership",
            target_id=DomainId.from_str(group),
            authorized_at=datetime.now(UTC),
        )
        uow.commit()
        return created


def test_p13_real_writer_appends_one_audit_row(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed_writer_graph(db)
    assert _add_verified(postgres_spi, ids) is True
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 1
    assert _add_verified(postgres_spi, ids) is False
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 1


def test_p14_missing_partition_rolls_back_the_membership(
    db: psycopg.Connection, owner: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed_writer_graph(db)
    child = _month_partition_name(_current_month_start())
    owner.execute(sql.SQL("DROP TABLE mtmf.{}").format(sql.Identifier(child)))
    assert child not in _partition_name_set(db)
    with pytest.raises(PersistenceError):
        _add_verified(postgres_spi, ids)
    assert db.execute("SELECT count(*) FROM mtmf.identity_group_membership").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 0


def test_p15_audit_failure_after_membership_insert_rolls_back_both(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed_writer_graph(db)
    # Pin the server-assigned audit timestamp to a covered month so two
    # attempts collide on the composite (occurred_at, id) primary key.
    pinned = _current_month_start() + timedelta(days=15)
    db.execute(
        sql.SQL(
            "ALTER TABLE mtmf.security_mutation_audit ALTER COLUMN occurred_at SET DEFAULT {}"
        ).format(sql.Literal(pinned))
    )
    operation_id = uuid.uuid4()
    assert _add_verified(postgres_spi, ids, operation_id=operation_id) is True

    extra_subject, extra_group = _sid(), _sid()
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'Extra', 2, 2)",
        (extra_subject, ids["principal"]),
    )
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
        (extra_subject, ids["tenant"]),
    )
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s, %s, 'G', 2)",
        (extra_group, ids["tenant"]),
    )
    db.execute(
        "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)", (extra_group, ids["tenant"])
    )
    with pytest.raises(PersistenceError):
        _add_verified(
            postgres_spi,
            ids,
            subject=extra_subject,
            group=extra_group,
            operation_id=operation_id,
        )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.identity_group_membership "
            "WHERE identity_id = %s AND group_id = %s",
            (extra_subject, extra_group),
        ).fetchone()[0]
        == 0
    )
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 1


# --- P16: migration rollback ------------------------------------------------


def test_p16_failed_conversion_restores_original_table(
    mtmf_config: PostgresConfig, migrator_config: PostgresConfig
) -> None:
    _reset_to_revision(mtmf_config, migrator_config, "0012")
    connection = psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True)
    try:
        before = _seed_v012_rows(connection, [_current_month_start() + timedelta(days=2)])
        # A dependent view makes the final DROP TABLE (no CASCADE) fail, so the
        # whole conversion must roll back and leave the v012 table intact.
        connection.execute(
            "CREATE VIEW mtmf.pr19b_probe_view AS SELECT * FROM mtmf.security_mutation_audit"
        )
        with pytest.raises(MigrationError):
            PostgresMigrationManager(migrator_config).upgrade_to_head()
        assert (
            connection.execute(
                "SELECT relkind FROM pg_catalog.pg_class "
                "WHERE oid = 'mtmf.security_mutation_audit'::regclass"
            ).fetchone()[0]
            == "r"
        )
        assert _snapshot(connection) == before
        assert (
            connection.execute(
                "SELECT to_regclass('mtmf.security_mutation_audit_v012_backup')"
            ).fetchone()[0]
            is None
        )
        assert (
            connection.execute("SELECT version_num FROM mtmf.alembic_version").fetchone()[0]
            == "0012"
        )
    finally:
        connection.execute("DROP VIEW IF EXISTS mtmf.pr19b_probe_view")
        connection.close()
    PostgresMigrationManager(migrator_config).upgrade_to_head()


# --- P17: upgrade serialized against an open writer --------------------------


def test_p17_upgrade_serializes_with_open_writer(
    mtmf_config: PostgresConfig, migrator_config: PostgresConfig
) -> None:
    _reset_to_revision(mtmf_config, migrator_config, "0012")
    writer = psycopg.connect(migrator_config.psycopg_dsn)
    writer.execute("SET ROLE mtmf_owner")
    operation_id = _sid()
    writer.execute(
        "INSERT INTO mtmf.security_mutation_audit "
        "(id, occurred_at, authorized_at, actor_identity_id, actor_principal_id, tenant_id, "
        " application_id, action_urn, target_kind, target_id, subject_identity_id, outcome) "
        "VALUES (%s, now(), now(), %s, %s, %s, %s, "
        " 'urn:mtmf:iam:actions:system:identity-group-membership:add-object', "
        " 'identity_group_membership', %s, %s, 'CREATED')",
        (operation_id, _sid(), _sid(), _sid(), _sid(), _sid(), _sid()),
    )
    result: dict[str, object] = {}

    def run_migration() -> None:
        try:
            PostgresMigrationManager(migrator_config).upgrade_to_head()
            result["ok"] = True
        except Exception as exc:  # pragma: no cover - diagnostic
            result["error"] = repr(exc)

    thread = threading.Thread(target=run_migration)
    thread.start()
    time.sleep(1.5)
    assert not result, "migration must block on the open writer's lock"
    writer.commit()
    writer.close()
    thread.join(timeout=60)
    assert result.get("ok") is True, result
    connection = psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True)
    try:
        assert (
            connection.execute(
                "SELECT count(*) FROM mtmf.security_mutation_audit WHERE id = %s",
                (operation_id,),
            ).fetchone()[0]
            == 1
        )
    finally:
        connection.close()


# --- P18/P19: allowlist and replay -------------------------------------------


def test_p18_runtime_allowlist_and_post_verifier_unchanged(db: psycopg.Connection) -> None:
    from mtmf_core.persistence.postgres import roles as pg_roles

    pg_roles.verify_runtime_privileges(db)
    executable = {
        row[0]
        for row in db.execute(
            "SELECT format('%I.%I(%s)', n.nspname, p.proname, "
            "pg_get_function_identity_arguments(p.oid)) FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'mtmf' AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')"
        ).fetchall()
    }
    assert executable == set(expected_runtime_signatures())
    assert len(executable) == 78


def test_p19_repeated_upgrade_does_not_duplicate_partitions(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    before_partitions = _partition_name_set(db)
    before_rows = _snapshot(db)
    manager = PostgresMigrationManager(migrator_config)
    manager.upgrade_to_head()
    manager.upgrade_to_head()
    assert manager.current_revision() == "0014"
    assert _partition_name_set(db) == before_partitions
    assert _snapshot(db) == before_rows
