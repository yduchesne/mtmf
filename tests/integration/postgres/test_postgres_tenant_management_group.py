"""TenantManagementGroup persistence, security, and vertical-slice tests (0009).

These run on real PostgreSQL with the established administrator/migrator/
runtime topology. Privileged management mutations are exercised through the
administrator connection; the restricted ``mtmf_runtime`` login is used for
the authorization read path and to prove privileged mutation denial.
"""

from __future__ import annotations

import threading
import uuid

import psycopg
import pytest

from mtmf_core import (
    ROOT_MANAGEMENT_ROLE_URN,
    SYSTEM_MANAGEMENT_ROLE_URN,
    Action,
    ActionUrn,
    AuthorizationRequest,
    Authorizer,
    DomainId,
    ManagementAuthorizationResolver,
    SessionContext,
)
from mtmf_core.persistence.postgres import PostgresMtmfSpi

_TENANT_SCOPE = 2  # scope value used by the raw fixture INSERTs below
_ACTIVE = 1
_NOT_DELETED = 2


def _uuid() -> str:
    return str(uuid.uuid4())


def make_id_like(value: str) -> DomainId:
    return DomainId.from_str(value)


def _bootstrap_root(db: psycopg.Connection) -> tuple[str, str, str]:
    tenant_id, principal_id, identity_id = _uuid(), _uuid(), _uuid()
    db.execute(
        "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
        (tenant_id, principal_id, identity_id),
    )
    return tenant_id, principal_id, identity_id


def _seed_tenant(db: psycopg.Connection) -> tuple[str, str, str]:
    principal_id, identity_id, tenant_id = _uuid(), _uuid(), _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (principal_id,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', 1, 2)",
        (identity_id, principal_id),
    )
    db.execute(
        "INSERT INTO mtmf.tenant "
        "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'T', 2, %s, 1, 2)",
        (tenant_id, identity_id),
    )
    db.execute(
        "INSERT INTO mtmf.principal_tenant_membership (principal_id, tenant_id) VALUES (%s, %s)",
        (principal_id, tenant_id),
    )
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id) VALUES (%s, %s)",
        (identity_id, tenant_id),
    )
    return tenant_id, principal_id, identity_id


def _create_system_group(db: psycopg.Connection, manager_tenant_id: str) -> str:
    group_id = _uuid()
    db.execute(
        "SELECT mtmf.create_tenant_management_group(%s, %s, %s, %s::smallint)",
        (group_id, manager_tenant_id, SYSTEM_MANAGEMENT_ROLE_URN, 1),
    )
    return group_id


def test_tmg01_root_bootstrap_creates_single_root_group(db: psycopg.Connection) -> None:
    _bootstrap_root(db)
    rows = db.execute(
        "SELECT id, manager_tenant_id, management_role_urn, scope "
        "FROM mtmf.tenant_management_group WHERE scope = 0"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][2] == ROOT_MANAGEMENT_ROLE_URN
    # A second bootstrap with the same canonical IDs is idempotent.
    first = db.execute(
        "SELECT root_tenant_id, root_principal_id, root_identity_id "
        "FROM mtmf.root_registry WHERE singleton"
    ).fetchone()
    db.execute("SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')", first)
    assert (
        db.execute("SELECT count(*) FROM mtmf.tenant_management_group WHERE scope = 0").fetchone()[
            0
        ]
        == 1
    )


def test_tmg02_second_root_group_is_rejected(db: psycopg.Connection) -> None:
    root_tenant, _, _ = _bootstrap_root(db)
    with pytest.raises(psycopg.Error):
        db.execute(
            "SELECT mtmf.create_tenant_management_group(%s, %s, %s, %s::smallint)",
            (_uuid(), root_tenant, ROOT_MANAGEMENT_ROLE_URN, 0),
        )


def test_tmg03_root_explicit_membership_is_rejected(db: psycopg.Connection) -> None:
    _bootstrap_root(db)
    _, _, target = _seed_tenant(db)
    group_id = db.execute("SELECT id FROM mtmf.tenant_management_group WHERE scope = 0").fetchone()[
        0
    ]
    with pytest.raises(psycopg.Error) as excinfo:
        db.execute(
            "SELECT mtmf.add_tenant_management_group_membership(%s, %s, %s)",
            (_uuid(), group_id, target),
        )
    assert excinfo.value.sqlstate == "MT034"


def test_tmg04_system_group_membership_and_duplicates(db: psycopg.Connection) -> None:
    _bootstrap_root(db)
    manager, _, _ = _seed_tenant(db)
    target, _, _ = _seed_tenant(db)
    group_id = _create_system_group(db, manager)
    assert (
        db.execute(
            "SELECT mtmf.add_tenant_management_group_membership(%s, %s, %s)",
            (_uuid(), group_id, target),
        ).fetchone()[0]
        is True
    )
    # Duplicate logical relationship does not create a second row.
    assert (
        db.execute(
            "SELECT mtmf.add_tenant_management_group_membership(%s, %s, %s)",
            (_uuid(), group_id, target),
        ).fetchone()[0]
        is False
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.tenant_management_group_membership "
            "WHERE management_group_id = %s AND tenant_id = %s",
            (group_id, target),
        ).fetchone()[0]
        == 1
    )


def test_tmg05_system_group_rejects_root_target(db: psycopg.Connection) -> None:
    root_tenant, _, _ = _bootstrap_root(db)
    manager, _, _ = _seed_tenant(db)
    group_id = _create_system_group(db, manager)
    with pytest.raises(psycopg.Error) as excinfo:
        db.execute(
            "SELECT mtmf.add_tenant_management_group_membership(%s, %s, %s)",
            (_uuid(), group_id, root_tenant),
        )
    assert excinfo.value.sqlstate == "MT034"


def test_tmg06_privileged_functions_are_not_runtime_executable(
    runtime_connection: psycopg.Connection, db: psycopg.Connection
) -> None:
    manager, _, _ = _seed_tenant(db)
    with pytest.raises(psycopg.Error):
        runtime_connection.execute(
            "SELECT mtmf.create_tenant_management_group(%s, %s, %s, %s::smallint)",
            (_uuid(), manager, SYSTEM_MANAGEMENT_ROLE_URN, 1),
        )
    with pytest.raises(psycopg.Error):
        runtime_connection.execute(
            "SELECT mtmf.add_tenant_management_group_membership(%s, %s, %s)",
            (_uuid(), _uuid(), manager),
        )


def test_tmg07_privileged_remove_is_not_runtime_executable(
    runtime_connection: psycopg.Connection, db: psycopg.Connection
) -> None:
    _bootstrap_root(db)
    manager, _, _ = _seed_tenant(db)
    target, _, _ = _seed_tenant(db)
    group_id = _create_system_group(db, manager)
    db.execute(
        "SELECT mtmf.add_tenant_management_group_membership(%s, %s, %s)",
        (_uuid(), group_id, target),
    )
    with pytest.raises(psycopg.Error):
        runtime_connection.execute(
            "SELECT mtmf.remove_tenant_management_group_membership(%s, %s)",
            (group_id, target),
        )


def test_tmg08_runtime_reads_are_granted(
    runtime_connection: psycopg.Connection, db: psycopg.Connection
) -> None:
    _bootstrap_root(db)
    manager, _, _ = _seed_tenant(db)
    group_id = _create_system_group(db, manager)
    payload = runtime_connection.execute(
        "SELECT mtmf.tenant_management_group_get(%s)", (group_id,)
    ).fetchone()[0]
    assert payload["management_role_urn"] == SYSTEM_MANAGEMENT_ROLE_URN
    found = runtime_connection.execute(
        "SELECT mtmf.tenant_management_group_find_by_manager(%s)", (manager,)
    ).fetchall()
    assert len(found) == 1
    root = runtime_connection.execute("SELECT mtmf.root_registry_get()").fetchone()[0]
    assert root is not None


def _runtime_objects(spi: PostgresMtmfSpi, tenant_id, principal_id, identity_id):
    with spi.create_unit_of_work() as uow:
        tenant = spi.create_tenant_repository(uow).get(make_id_like(tenant_id))
        principal = spi.create_principal_repository(uow).get(make_id_like(principal_id))
        identity = spi.create_identity_repository(uow).get(make_id_like(identity_id))
        ptms = spi.create_principal_tenant_membership_repository(uow).find_by_principal(
            make_id_like(principal_id)
        )
        itms = spi.create_identity_tenant_membership_repository(uow).find_by_identity(
            make_id_like(identity_id)
        )
    assert tenant is not None and principal is not None and identity is not None
    return tenant, principal, identity, ptms, itms


def test_tmg09_vertical_slice_positive_and_negative(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    root_tenant, _, root_identity = _bootstrap_root(db)
    manager, principal, identity = _seed_tenant(db)
    target, _, _ = _seed_tenant(db)
    unlisted, _, _ = _seed_tenant(db)
    group_id = _create_system_group(db, manager)
    db.execute(
        "SELECT mtmf.add_tenant_management_group_membership(%s, %s, %s)",
        (_uuid(), group_id, target),
    )
    eligibility_id = _uuid()
    db.execute(
        "SELECT mtmf.add_tenant_management_group_actor_eligibility(%s, %s, %s)",
        (eligibility_id, group_id, identity),
    )

    tenant, principal_obj, identity_obj, ptms, itms = _runtime_objects(
        postgres_spi, manager, principal, identity
    )
    session = SessionContext(tenant.id, principal_obj.id, identity_obj.id)
    resolver = ManagementAuthorizationResolver(postgres_spi)

    positive = resolver.resolve(
        session=session,
        target_tenant_id=make_id_like(target),
        manager_tenant=tenant,
        manager_principal=principal_obj,
        manager_identity=identity_obj,
        principal_tenant_memberships=ptms,
        identity_tenant_memberships=itms,
        target_tenant=_load_tenant(postgres_spi, target),
        canonical_root_tenant_id=make_id_like(root_tenant),
        canonical_root_identity_id=make_id_like(root_identity),
    )
    assert positive.is_elevated is True
    action = Action(ActionUrn("urn:mtmf:iam:actions:system:tenant:get-object"))
    allowed = Authorizer().authorize(
        AuthorizationRequest(
            positive.context,
            action,
            make_id_like(target),
            management_scope=positive.management_scope,
        )
    )
    assert allowed.allowed is True

    # Unlisted target: no coverage, no delegated ALLOW.
    denied = resolver.resolve(
        session=session,
        target_tenant_id=make_id_like(unlisted),
        manager_tenant=tenant,
        manager_principal=principal_obj,
        manager_identity=identity_obj,
        principal_tenant_memberships=ptms,
        identity_tenant_memberships=itms,
        target_tenant=_load_tenant(postgres_spi, unlisted),
        canonical_root_tenant_id=make_id_like(root_tenant),
        canonical_root_identity_id=make_id_like(root_identity),
    )
    assert denied.is_elevated is False

    # Removing eligibility revokes coverage for subsequent decisions.
    db.execute(
        "SELECT mtmf.remove_tenant_management_group_actor_eligibility(%s, %s)", (group_id, identity)
    )
    revoked = resolver.resolve(
        session=session,
        target_tenant_id=make_id_like(target),
        manager_tenant=tenant,
        manager_principal=principal_obj,
        manager_identity=identity_obj,
        principal_tenant_memberships=ptms,
        identity_tenant_memberships=itms,
        target_tenant=_load_tenant(postgres_spi, target),
        canonical_root_tenant_id=make_id_like(root_tenant),
        canonical_root_identity_id=make_id_like(root_identity),
    )
    assert revoked.is_elevated is False


def _load_tenant(spi: PostgresMtmfSpi, tenant_id: str):
    with spi.create_unit_of_work() as uow:
        return spi.create_tenant_repository(uow).get(make_id_like(tenant_id))


def _race(dsn: str, workers: list[tuple[str, object]]) -> dict[str, str]:
    barrier = threading.Barrier(len(workers))
    outcomes: dict[str, str] = {}

    def make(name: str, fn):
        def run() -> None:
            try:
                with psycopg.connect(dsn, autocommit=True) as connection:
                    connection.execute("SET statement_timeout = '20s'")
                    connection.execute("SET lock_timeout = '15s'")
                    barrier.wait(timeout=20)
                    fn(connection)
                outcomes[name] = "ok"
            except psycopg.Error as exc:
                outcomes[name] = getattr(exc, "sqlstate", None) or type(exc).__name__

        return run

    threads = [threading.Thread(target=make(name, fn)) for name, fn in workers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads)
    return outcomes


def test_tmg10_concurrent_root_bootstrap_single_group(db: psycopg.Connection, dsn: str) -> None:
    tenant_id, principal_id, identity_id = _uuid(), _uuid(), _uuid()

    def worker(connection: psycopg.Connection) -> None:
        connection.execute(
            "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
            (tenant_id, principal_id, identity_id),
        )

    for _ in range(5):
        outcomes = _race(dsn, [("a", worker), ("b", worker)])
        assert outcomes == {"a": "ok", "b": "ok"}, outcomes
        assert (
            db.execute(
                "SELECT count(*) FROM mtmf.tenant_management_group WHERE scope = 0"
            ).fetchone()[0]
            == 1
        )


def test_tmg11_concurrent_membership_insert_yields_one_row(
    db: psycopg.Connection, dsn: str
) -> None:
    _bootstrap_root(db)
    manager, _, _ = _seed_tenant(db)
    target, _, _ = _seed_tenant(db)
    group_id = _create_system_group(db, manager)
    first = _uuid()
    second = _uuid()

    def worker(membership_id: str):
        def run(connection: psycopg.Connection) -> None:
            connection.execute(
                "SELECT mtmf.add_tenant_management_group_membership(%s, %s, %s)",
                (membership_id, group_id, target),
            )

        return run

    for _ in range(5):
        outcomes = _race(dsn, [("a", worker(first)), ("b", worker(second))])
        assert outcomes == {"a": "ok", "b": "ok"}, outcomes
        assert (
            db.execute(
                "SELECT count(*) FROM mtmf.tenant_management_group_membership "
                "WHERE management_group_id = %s AND tenant_id = %s",
                (group_id, target),
            ).fetchone()[0]
            == 1
        )
        db.execute(
            "SELECT mtmf.remove_tenant_management_group_membership(%s, %s)",
            (group_id, target),
        )


def test_tmg12_root_recovery_replaces_eligible_actor(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    root_tenant, root_principal, old_identity = _bootstrap_root(db)
    new_identity = _uuid()
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'Root I2', 1, 2)",
        (new_identity, root_principal),
    )
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id) VALUES (%s, %s)",
        (new_identity, root_tenant),
    )
    db.execute("SELECT mtmf.recover_root_identity(%s, 'rotation', 'test')", (new_identity,))

    tenant, principal_obj, _, ptms, _ = _runtime_objects(
        postgres_spi, root_tenant, root_principal, new_identity
    )
    new_identity_obj = _load_identity(postgres_spi, new_identity)
    resolver = ManagementAuthorizationResolver(postgres_spi)
    target = _seed_tenant(db)[0]

    def resolve(identity_obj, canonical_identity: str):
        return resolver.resolve(
            session=SessionContext(tenant.id, principal_obj.id, identity_obj.id),
            target_tenant_id=make_id_like(target),
            manager_tenant=tenant,
            manager_principal=principal_obj,
            manager_identity=identity_obj,
            principal_tenant_memberships=ptms,
            identity_tenant_memberships=tuple(
                spi_itm for spi_itm in _load_itms(postgres_spi, identity_obj.id)
            ),
            target_tenant=_load_tenant(postgres_spi, target),
            canonical_root_tenant_id=make_id_like(root_tenant),
            canonical_root_identity_id=make_id_like(canonical_identity),
        )

    recovered = resolve(new_identity_obj, new_identity)
    assert recovered.is_elevated is True
    # The previous root Identity must no longer carry ROOT authority.
    stale = resolve(new_identity_obj, old_identity)
    assert stale.is_elevated is False


def _load_identity(spi: PostgresMtmfSpi, identity_id: str):
    with spi.create_unit_of_work() as uow:
        return spi.create_identity_repository(uow).get(make_id_like(identity_id))


def _load_itms(spi: PostgresMtmfSpi, identity_id):
    with spi.create_unit_of_work() as uow:
        return spi.create_identity_tenant_membership_repository(uow).find_by_identity(identity_id)
