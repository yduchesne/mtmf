"""UnitOfWork lifecycle contract tests (plan matrix U01-U16).

These tests exercise only the provider-neutral UnitOfWork contract:
enter/commit/rollback/context-manager semantics, completion, and the
absence of driver handles. They are provider-agnostic on purpose.
"""

from __future__ import annotations

import pytest
from helpers import make_tenant

from mtmf_core.persistence import (
    MtmfSpi,
    UnitOfWork,
    UnitOfWorkStateError,
)


def test_u01_enter_establishes_active_unit_of_work(spi: MtmfSpi) -> None:
    uow = spi.create_unit_of_work()
    with uow:
        tenants = spi.create_tenant_repository(uow)
        tenant = make_tenant()
        # Repository operations succeed only while the UoW is active.
        tenants.add(tenant)
        assert tenants.get(tenant.id) == tenant
    # The normal (uncommitted) exit rolled the change back.
    with spi.create_unit_of_work() as fresh:
        assert spi.create_tenant_repository(fresh).get(tenant.id) is None


def test_u02_explicit_commit_is_durable(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()
    with spi.create_unit_of_work() as fresh:
        loaded = spi.create_tenant_repository(fresh).get(tenant.id)
        assert loaded == tenant
        assert loaded is not tenant


def test_u03_explicit_rollback_discards(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as uow:
        repo = spi.create_tenant_repository(uow)
        repo.add(tenant)
        assert repo.get(tenant.id) == tenant
        uow.rollback()
    with spi.create_unit_of_work() as fresh:
        assert spi.create_tenant_repository(fresh).get(tenant.id) is None


def test_u04_normal_exit_without_commit_rolls_back(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
    with spi.create_unit_of_work() as fresh:
        assert spi.create_tenant_repository(fresh).get(tenant.id) is None


def test_u05_exceptional_exit_rolls_back_and_propagates(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    sentinel = RuntimeError("boom")
    with pytest.raises(RuntimeError) as captured, spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        raise sentinel
    assert captured.value is sentinel
    with spi.create_unit_of_work() as fresh:
        assert spi.create_tenant_repository(fresh).get(tenant.id) is None


def test_u06_second_commit_fails(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        uow.commit()
        with pytest.raises(UnitOfWorkStateError):
            uow.commit()


def test_u07_rollback_after_commit_fails(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        uow.commit()
        with pytest.raises(UnitOfWorkStateError):
            uow.rollback()


def test_u08_commit_after_rollback_fails(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        uow.rollback()
        with pytest.raises(UnitOfWorkStateError):
            uow.commit()


def test_u09_repository_use_after_commit_fails(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        tenants = spi.create_tenant_repository(uow)
        tenants.add(make_tenant())
        uow.commit()
        with pytest.raises(UnitOfWorkStateError):
            tenants.add(make_tenant())
        with pytest.raises(UnitOfWorkStateError):
            tenants.get(make_tenant().id)
        with pytest.raises(UnitOfWorkStateError):
            tenants.save(make_tenant())


def test_u10_repository_use_after_rollback_fails(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        tenants = spi.create_tenant_repository(uow)
        uow.rollback()
        with pytest.raises(UnitOfWorkStateError):
            tenants.add(make_tenant())
        with pytest.raises(UnitOfWorkStateError):
            tenants.get(make_tenant().id)


def test_u11_repository_use_after_context_close_fails(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        tenants = spi.create_tenant_repository(uow)
    with pytest.raises(UnitOfWorkStateError):
        tenants.add(make_tenant())
    with pytest.raises(UnitOfWorkStateError):
        tenants.get(make_tenant().id)

    with pytest.raises(RuntimeError), spi.create_unit_of_work() as uow:
        closed_by_exception = spi.create_tenant_repository(uow)
        raise RuntimeError("boom")
    with pytest.raises(UnitOfWorkStateError):
        closed_by_exception.add(make_tenant())


def test_u12_two_active_unit_of_works_do_not_share_uncommitted_state(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as first, spi.create_unit_of_work() as second:
        staged = make_tenant()
        spi.create_tenant_repository(first).add(staged)
        assert spi.create_tenant_repository(second).get(staged.id) is None


def test_u13_new_unit_of_work_after_commit_sees_committed_data(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as first:
        spi.create_tenant_repository(first).add(tenant)
        first.commit()
    with spi.create_unit_of_work() as second:
        assert spi.create_tenant_repository(second).get(tenant.id) == tenant


def test_u14_new_unit_of_work_after_rollback_sees_nothing(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as first:
        spi.create_tenant_repository(first).add(tenant)
        first.rollback()
    with spi.create_unit_of_work() as second:
        assert spi.create_tenant_repository(second).get(tenant.id) is None


def test_u15_exit_never_suppresses_the_original_exception(spi: MtmfSpi) -> None:
    sentinel = ValueError("must propagate")
    with pytest.raises(ValueError) as captured, spi.create_unit_of_work():
        raise sentinel
    assert captured.value is sentinel


def test_u16_unit_of_work_contract_exposes_no_driver_handle(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        for name in (
            "connection",
            "cursor",
            "session",
            "engine",
            "pool",
            "transaction",
            "transaction_handle",
            "connection_handle",
            "executor",
        ):
            assert not hasattr(uow, name), f"UnitOfWork must not expose {name!r}"
    for name in (
        "connection",
        "cursor",
        "session",
        "engine",
        "pool",
        "transaction",
        "transaction_handle",
    ):
        assert not hasattr(UnitOfWork, name), f"UnitOfWork contract must not declare {name!r}"


def test_unit_of_work_contract_has_no_nested_transaction_surface(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        for name in ("savepoint", "begin_nested", "join", "nest", "distributed"):
            assert not hasattr(uow, name), f"UnitOfWork must not expose {name!r}"


def test_commit_before_enter_is_a_state_error(spi: MtmfSpi) -> None:
    uow = spi.create_unit_of_work()
    with pytest.raises(UnitOfWorkStateError):
        uow.commit()
    with pytest.raises(UnitOfWorkStateError):
        uow.rollback()


def test_repository_use_before_enter_is_a_state_error(spi: MtmfSpi) -> None:
    uow = spi.create_unit_of_work()
    tenants = spi.create_tenant_repository(uow)
    with pytest.raises(UnitOfWorkStateError):
        tenants.add(make_tenant())
    with pytest.raises(UnitOfWorkStateError):
        tenants.get(make_tenant().id)


def test_reentering_a_completed_unit_of_work_fails(spi: MtmfSpi) -> None:
    uow = spi.create_unit_of_work()
    with uow:
        uow.commit()
    with pytest.raises(UnitOfWorkStateError), uow:
        pass
