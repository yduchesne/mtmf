"""Deterministic concurrency matrix for root/stewardship invariants (0008).

Every scenario uses two or more independent PostgreSQL connections, a
:class:`threading.Barrier` immediately before the contested statement, and
bounded ``statement_timeout``/``lock_timeout``. Each scenario runs the
prescribed **10 cycles**; a hang, deadlock, or split state fails the test.

A single-connection sequential run is not accepted as concurrency evidence.
Worker callables are built with :func:`functools.partial` so each cycle binds
its own state without late loop-variable capture.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from functools import partial

import helpers
import psycopg
import pytest

from mtmf_core import (
    DomainId,
    Identity,
    IdentityOrigin,
    IdentityRoleAssignment,
    IdentityTenantMembership,
    Principal,
    PrincipalTenantMembership,
    RoleUrn,
    SecurityScope,
    Tenant,
    TenantLifecycle,
)
from mtmf_core.persistence.spi import MtmfSpi

_TENANT_ADMIN_URN = RoleUrn("urn:mtmf:iam:roles:system:tenant-administrator")
_CYCLES = 10


def _run_race(
    dsn: str, specs: list[tuple[str, Callable[[psycopg.Connection], object]]]
) -> dict[str, str]:
    """Run ``specs`` on independent connections behind one barrier.

    Returns a mapping of worker name to ``"ok"`` or the observed SQLSTATE.
    Raises if any worker is still alive after the bounded join (a hang or
    deadlock must fail the test, not silently pass).
    """
    barrier = threading.Barrier(len(specs))
    outcomes: dict[str, str] = {}

    def make(name: str, fn: Callable[[psycopg.Connection], object]) -> Callable[[], None]:
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
            except Exception as exc:  # pragma: no cover - diagnostic only
                outcomes[name] = f"ERR:{type(exc).__name__}"

        return run

    threads = [threading.Thread(target=make(name, fn)) for name, fn in specs]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    if any(thread.is_alive() for thread in threads):
        raise AssertionError("concurrency scenario hung beyond the bounded timeout")
    return outcomes


def _execute(connection: psycopg.Connection, sql: str, params: tuple[object, ...] = ()) -> None:
    connection.execute(sql, params)


def _designate(
    connection: psycopg.Connection,
    tenant: Tenant,
    principal: Principal,
    identity: Identity,
    expected: int | None,
    operation: str = "RECOVERY",
) -> None:
    connection.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, %s, %s, 'test', 'operator')",
        (tenant.id.value, principal.id.value, identity.id.value, expected, operation),
    )


def _create_tenant(spi: MtmfSpi) -> Tenant:
    owner_principal = Principal(DomainId.generate(), "Owner")
    owner_identity = Identity(
        DomainId.generate(), owner_principal.id, "Owner I", IdentityOrigin.LOCAL
    )
    tenant = Tenant(
        DomainId.generate(),
        "T",
        SecurityScope.TENANT,
        owner_identity.id,
        lifecycle=TenantLifecycle.PROVISIONING,
    )
    with spi.create_unit_of_work() as uow:
        spi.create_principal_repository(uow).add(owner_principal)
        spi.create_identity_repository(uow).add(owner_identity)
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()
    return tenant


def _add_eligible_steward(spi: MtmfSpi, tenant: Tenant) -> tuple[Principal, Identity]:
    principal = Principal(DomainId.generate(), "Steward")
    identity = Identity(DomainId.generate(), principal.id, "Steward I", IdentityOrigin.LOCAL)
    with spi.create_unit_of_work() as uow:
        spi.create_principal_repository(uow).add(principal)
        spi.create_identity_repository(uow).add(identity)
        spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(principal.id, tenant.id)
        )
        spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(identity.id, tenant.id)
        )
        spi.create_identity_role_assignment_repository(uow).add(
            IdentityRoleAssignment(DomainId.generate(), tenant.id, identity.id, _TENANT_ADMIN_URN)
        )
        uow.commit()
    return principal, identity


def _active_tenant_with_steward(
    spi: MtmfSpi, db: psycopg.Connection
) -> tuple[Tenant, Principal, Identity]:
    tenant = _create_tenant(spi)
    principal, identity = _add_eligible_steward(spi, tenant)
    _designate(db, tenant, principal, identity, None)
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    return tenant, principal, identity


def _designation_row(db: psycopg.Connection, tenant: Tenant) -> tuple[str, str, int]:
    row = db.execute(
        "SELECT steward_principal_id::text, designated_identity_id::text, version "
        "FROM mtmf.stewardship_designation WHERE tenant_id = %s",
        (tenant.id.value,),
    ).fetchone()
    assert row is not None, "an ACTIVE/designated Tenant must retain its designation"
    return str(row[0]), str(row[1]), int(row[2])


# --- SC01: concurrent bootstrap ------------------------------------------------


def test_sc01_concurrent_bootstrap_serializes(
    db: psycopg.Connection, dsn: str, migrator_config
) -> None:
    for cycle in range(_CYCLES):
        helpers.reset_and_migrate(db, migrator_config)
        ids = (str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4()))
        worker = partial(
            _execute,
            sql="SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
            params=ids,
        )
        outcomes = _run_race(dsn, [("a", worker), ("b", worker)])
        assert outcomes == {"a": "ok", "b": "ok"}, (cycle, outcomes)
        assert db.execute("SELECT count(*) FROM mtmf.root_registry").fetchone()[0] == 1
        assert db.execute("SELECT count(*) FROM mtmf.stewardship_audit").fetchone()[0] == 1


# --- SC02: transfer vs transfer ------------------------------------------------


def test_sc02_concurrent_transfer_has_one_winner(
    postgres_spi: MtmfSpi, db: psycopg.Connection, dsn: str
) -> None:
    tenant, current_principal, current_identity = _active_tenant_with_steward(postgres_spi, db)
    version = _designation_row(db, tenant)[2]
    for cycle in range(_CYCLES):
        challenger_principal, challenger_identity = _add_eligible_steward(postgres_spi, tenant)
        outcomes = _run_race(
            dsn,
            [
                (
                    "challenger",
                    partial(
                        _designate,
                        tenant=tenant,
                        principal=challenger_principal,
                        identity=challenger_identity,
                        expected=version,
                        operation="TRANSFER",
                    ),
                ),
                (
                    "incumbent",
                    partial(
                        _designate,
                        tenant=tenant,
                        principal=current_principal,
                        identity=current_identity,
                        expected=version,
                        operation="TRANSFER",
                    ),
                ),
            ],
        )
        assert sorted(outcomes.values()) == ["MT012", "ok"], (cycle, outcomes)
        if outcomes["challenger"] == "ok":
            current_principal, current_identity = challenger_principal, challenger_identity
        version = _designation_row(db, tenant)[2]
    assert version == 1 + _CYCLES
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE operation = 'TRANSFER'"
        ).fetchone()[0]
        == _CYCLES
    )
    assert (
        db.execute(
            "SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant.id.value,)
        ).fetchone()[0]
        == 1
    )


# --- SC03/SC04: transfer vs incumbent deactivation -----------------------------


@pytest.mark.parametrize("target", ["principal", "identity"])
def test_sc03_transfer_races_incumbent_deactivation(
    postgres_spi: MtmfSpi, db: psycopg.Connection, dsn: str, target: str
) -> None:
    for cycle in range(_CYCLES):
        tenant, incumbent_principal, incumbent_identity = _active_tenant_with_steward(
            postgres_spi, db
        )
        successor_principal, successor_identity = _add_eligible_steward(postgres_spi, tenant)
        if target == "principal":
            sql = "UPDATE mtmf.principal SET deletion_status = 1 WHERE id = %s"
            target_id = incumbent_principal.id.value
        else:
            sql = "UPDATE mtmf.identity SET deletion_status = 1 WHERE id = %s"
            target_id = incumbent_identity.id.value
        outcomes = _run_race(
            dsn,
            [
                (
                    "transfer",
                    partial(
                        _designate,
                        tenant=tenant,
                        principal=successor_principal,
                        identity=successor_identity,
                        expected=1,
                        operation="TRANSFER",
                    ),
                ),
                ("deactivate", partial(_execute, sql=sql, params=(target_id,))),
            ],
        )
        assert outcomes["transfer"] == "ok", (cycle, target, outcomes)
        assert outcomes["deactivate"] in {"ok", "MT032"}, (cycle, target, outcomes)
        principal_id, identity_id, _version = _designation_row(db, tenant)
        assert principal_id == str(successor_principal.id.value)
        assert identity_id == str(successor_identity.id.value)
        assert (
            db.execute(
                "SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant.id.value,)
            ).fetchone()[0]
            == 1
        )


# --- SC05: transfer vs final Tenant Administrator revocation -------------------


def test_sc05_transfer_races_steward_assignment_revocation(
    postgres_spi: MtmfSpi, db: psycopg.Connection, dsn: str
) -> None:
    for cycle in range(_CYCLES):
        tenant, _incumbent_principal, incumbent_identity = _active_tenant_with_steward(
            postgres_spi, db
        )
        successor_principal, successor_identity = _add_eligible_steward(postgres_spi, tenant)
        assignment_id = db.execute(
            "SELECT id FROM mtmf.identity_role_assignment "
            "WHERE tenant_id = %s AND identity_id = %s AND organization_id IS NULL",
            (tenant.id.value, incumbent_identity.id.value),
        ).fetchone()[0]
        outcomes = _run_race(
            dsn,
            [
                (
                    "transfer",
                    partial(
                        _designate,
                        tenant=tenant,
                        principal=successor_principal,
                        identity=successor_identity,
                        expected=1,
                        operation="TRANSFER",
                    ),
                ),
                (
                    "revoke",
                    partial(
                        _execute,
                        sql="SELECT mtmf.identity_role_assignment_remove(%s)",
                        params=(assignment_id,),
                    ),
                ),
            ],
        )
        assert outcomes["transfer"] == "ok", (cycle, outcomes)
        assert outcomes["revoke"] in {"ok", "MT032"}, (cycle, outcomes)
        principal_id, _identity_id, _version = _designation_row(db, tenant)
        assert principal_id == str(successor_principal.id.value)


# --- SC06: activation vs incomplete stewardship setup --------------------------


def test_sc06_activation_races_incomplete_setup(
    postgres_spi: MtmfSpi, db: psycopg.Connection, dsn: str
) -> None:
    for cycle in range(_CYCLES):
        tenant = _create_tenant(postgres_spi)
        principal, identity = _add_eligible_steward(postgres_spi, tenant)
        outcomes = _run_race(
            dsn,
            [
                (
                    "activate",
                    partial(
                        _execute,
                        sql="SELECT mtmf.activate_tenant(%s)",
                        params=(tenant.id.value,),
                    ),
                ),
                (
                    "designate",
                    partial(
                        _designate,
                        tenant=tenant,
                        principal=principal,
                        identity=identity,
                        expected=None,
                    ),
                ),
            ],
        )
        assert outcomes["designate"] == "ok", (cycle, outcomes)
        assert outcomes["activate"] in {"ok", "MT014"}, (cycle, outcomes)
        lifecycle = db.execute(
            "SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant.id.value,)
        ).fetchone()[0]
        # A committed ACTIVE Tenants always has a designation; a PROVISIONING
        # one never authorizes.
        assert _designation_row(db, tenant) is not None
        assert lifecycle == (1 if outcomes["activate"] == "ok" else 0), (cycle, outcomes)


# --- SC07: root recovery vs replacement-candidate deactivation -----------------


def test_sc07_root_recovery_races_candidate_deactivation(
    db: psycopg.Connection, dsn: str, migrator_config
) -> None:
    for cycle in range(_CYCLES):
        helpers.reset_and_migrate(db, migrator_config)
        root_tenant, root_principal, root_identity = (
            str(uuid.uuid4()),
            str(uuid.uuid4()),
            str(uuid.uuid4()),
        )
        db.execute(
            "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
            (root_tenant, root_principal, root_identity),
        )
        candidate = str(uuid.uuid4())
        db.execute(
            "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
            "VALUES (%s, %s, 'New Root I', 1, 2)",
            (candidate, root_principal),
        )
        db.execute(
            "INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id) VALUES (%s, %s)",
            (candidate, root_tenant),
        )
        db.commit()

        outcomes = _run_race(
            dsn,
            [
                (
                    "recover",
                    partial(
                        _execute,
                        sql="SELECT mtmf.recover_root_identity(%s, 'rotate', 'operator')",
                        params=(candidate,),
                    ),
                ),
                (
                    "deactivate",
                    partial(
                        _execute,
                        sql="UPDATE mtmf.identity SET deletion_status = 1 WHERE id = %s",
                        params=(candidate,),
                    ),
                ),
            ],
        )
        assert outcomes in (
            {"recover": "ok", "deactivate": "MT030"},
            {"recover": "MT026", "deactivate": "ok"},
        ), (cycle, outcomes)
        designated = db.execute("SELECT root_identity_id::text FROM mtmf.root_registry").fetchone()[
            0
        ]
        assert designated in {root_identity, candidate}
        assert db.execute(
            "SELECT origin, deletion_status FROM mtmf.identity WHERE id = %s", (designated,)
        ).fetchone() == (1, 2)


# --- SC08: concurrent built-in seed install ------------------------------------


def test_sc08_concurrent_seed_install_is_idempotent(
    db: psycopg.Connection, dsn: str, migrator_config
) -> None:
    worker = partial(_execute, sql="SELECT mtmf.install_builtin_policy()")
    for cycle in range(_CYCLES):
        helpers.reset_and_migrate(db, migrator_config)
        outcomes = _run_race(dsn, [("a", worker), ("b", worker)])
        assert all(value == "ok" for value in outcomes.values()), (cycle, outcomes)
        assert db.execute("SELECT count(*) FROM mtmf.builtin_role").fetchone()[0] == 11
        assert db.execute("SELECT count(*) FROM mtmf.permission_set").fetchone()[0] == 11
        assert db.execute("SELECT count(*) FROM mtmf.permission").fetchone()[0] == 11


# --- SC09: transfer vs successor deactivation ----------------------------------


@pytest.mark.parametrize("target", ["principal", "identity"])
def test_sc09_transfer_races_successor_deactivation(
    postgres_spi: MtmfSpi, db: psycopg.Connection, dsn: str, target: str
) -> None:
    for cycle in range(_CYCLES):
        tenant, incumbent_principal, incumbent_identity = _active_tenant_with_steward(
            postgres_spi, db
        )
        successor_principal, successor_identity = _add_eligible_steward(postgres_spi, tenant)
        if target == "principal":
            sql = "UPDATE mtmf.principal SET deletion_status = 1 WHERE id = %s"
            target_id = successor_principal.id.value
        else:
            sql = "UPDATE mtmf.identity SET deletion_status = 1 WHERE id = %s"
            target_id = successor_identity.id.value
        outcomes = _run_race(
            dsn,
            [
                (
                    "transfer",
                    partial(
                        _designate,
                        tenant=tenant,
                        principal=successor_principal,
                        identity=successor_identity,
                        expected=1,
                        operation="TRANSFER",
                    ),
                ),
                ("deactivate", partial(_execute, sql=sql, params=(target_id,))),
            ],
        )
        assert outcomes in (
            {"transfer": "ok", "deactivate": "MT032"},
            {"transfer": "MT013", "deactivate": "ok"},
        ), (cycle, target, outcomes)
        principal_id, identity_id, _version = _designation_row(db, tenant)
        # Whichever steward is designated must be active and eligible.
        designated_principal, designated_identity = (
            (successor_principal, successor_identity)
            if principal_id == str(successor_principal.id.value)
            else (incumbent_principal, incumbent_identity)
        )
        assert identity_id == str(designated_identity.id.value)
        assert (
            db.execute(
                "SELECT deletion_status FROM mtmf.principal WHERE id = %s",
                (designated_principal.id.value,),
            ).fetchone()[0]
            == 2
        )
        assert (
            db.execute(
                "SELECT deletion_status FROM mtmf.identity WHERE id = %s",
                (designated_identity.id.value,),
            ).fetchone()[0]
            == 2
        )
        assert (
            db.execute(
                "SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant.id.value,)
            ).fetchone()[0]
            == 1
        )


# --- SC10: activation vs designated-identity deactivation ----------------------


def test_sc10_activation_races_designated_deactivation(
    postgres_spi: MtmfSpi, db: psycopg.Connection, dsn: str
) -> None:
    for cycle in range(_CYCLES):
        tenant = _create_tenant(postgres_spi)
        principal, identity = _add_eligible_steward(postgres_spi, tenant)
        _designate(db, tenant, principal, identity, None)
        outcomes = _run_race(
            dsn,
            [
                (
                    "activate",
                    partial(
                        _execute,
                        sql="SELECT mtmf.activate_tenant(%s)",
                        params=(tenant.id.value,),
                    ),
                ),
                (
                    "deactivate",
                    partial(
                        _execute,
                        sql="UPDATE mtmf.identity SET deletion_status = 1 WHERE id = %s",
                        params=(identity.id.value,),
                    ),
                ),
            ],
        )
        assert outcomes in (
            {"activate": "ok", "deactivate": "MT032"},
            {"activate": "MT013", "deactivate": "ok"},
        ), (cycle, outcomes)
        lifecycle = db.execute(
            "SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant.id.value,)
        ).fetchone()[0]
        if outcomes["activate"] == "ok":
            assert lifecycle == 1
            assert (
                db.execute(
                    "SELECT deletion_status FROM mtmf.identity WHERE id = %s", (identity.id.value,)
                ).fetchone()[0]
                == 2
            )
        else:
            # Activation failed closed; the Tenant stays non-authorizing.
            assert lifecycle == 0
