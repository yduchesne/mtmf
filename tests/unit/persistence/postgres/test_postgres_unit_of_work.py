"""Unit tests for the PostgreSQL UnitOfWork lifecycle (no database).

A fake psycopg connection exercises the state machine, the mandatory
authenticated-runtime identity check, commit/rollback/dispose ordering,
and the deterministic failed-transaction state. No real driver is used.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from mtmf_core import DomainId
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    PersistenceConnectionError,
    PersistenceTransactionError,
    UnitOfWorkStateError,
)
from mtmf_core.persistence.postgres import unit_of_work as uow_module
from mtmf_core.persistence.postgres.config import PostgresConfig, PostgresRole
from mtmf_core.persistence.postgres.spi import PostgresMtmfSpi
from mtmf_core.persistence.postgres.unit_of_work import PostgresUnitOfWork


class _FakePgError(psycopg.Error):
    def __init__(self, sqlstate: str) -> None:
        super().__init__("driver detail")
        self.sqlstate = sqlstate


class _FakeCursor:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row

    def fetchall(self) -> list[tuple[Any, ...]]:
        return [] if self._row is None else [self._row]


class _FakeConnection:
    def __init__(
        self,
        *,
        session_user: str = "mtmf_runtime",
        current_user: str = "mtmf_runtime",
        execute_error: psycopg.Error | None = None,
    ) -> None:
        self.session_user = session_user
        self.current_user = current_user
        self.execute_error = execute_error
        self.closed = False
        self.commit_count = 0
        self.rollback_count = 0
        self.close_count = 0
        self.executed: list[str] = []

    def execute(self, query: str, params: object = None) -> _FakeCursor:
        self.executed.append(query)
        if query.startswith("SELECT session_user"):
            return _FakeCursor((self.session_user, self.current_user))
        if self.execute_error is not None:
            raise self.execute_error
        return _FakeCursor((True,))

    def commit(self) -> None:
        self.commit_count += 1

    def rollback(self) -> None:
        self.rollback_count += 1

    def close(self) -> None:
        self.closed = True
        self.close_count += 1


def _runtime_config() -> PostgresConfig:
    return PostgresConfig(
        host="db.example",
        port=25432,
        database="mtmf",
        user="mtmf_runtime",
        password="pw",
        role=PostgresRole.RUNTIME,
    )


def _install_connection(monkeypatch: pytest.MonkeyPatch, connection: _FakeConnection) -> None:
    monkeypatch.setattr(uow_module.psycopg, "connect", lambda *a, **k: connection)


def test_enter_validates_runtime_identity_and_commit_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection()
    _install_connection(monkeypatch, connection)
    spi = PostgresMtmfSpi(_runtime_config())
    uow = spi.create_unit_of_work()
    with uow:
        uow.commit()
    assert connection.commit_count == 1
    assert connection.close_count == 1
    assert connection.rollback_count == 0


def test_mislabelled_login_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection(session_user="mtmf", current_user="mtmf")
    _install_connection(monkeypatch, connection)
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    with pytest.raises(PersistenceConnectionError):
        uow.__enter__()
    assert connection.close_count == 1


def test_connect_failure_is_translated(monkeypatch: pytest.MonkeyPatch) -> None:
    def failing_connect(*args: object, **kwargs: object) -> None:
        raise psycopg.OperationalError("could not connect")

    monkeypatch.setattr(uow_module.psycopg, "connect", failing_connect)
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    with pytest.raises(PersistenceConnectionError):
        uow.__enter__()


def test_commit_before_enter_is_a_state_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_connection(monkeypatch, _FakeConnection())
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    with pytest.raises(UnitOfWorkStateError):
        uow.commit()
    with pytest.raises(UnitOfWorkStateError):
        uow.rollback()


def test_second_commit_and_rollback_after_commit_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection()
    _install_connection(monkeypatch, connection)
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    with uow:
        uow.commit()
        with pytest.raises(UnitOfWorkStateError):
            uow.commit()
        with pytest.raises(UnitOfWorkStateError):
            uow.rollback()


def test_normal_exit_without_commit_rolls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection()
    _install_connection(monkeypatch, connection)
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    with uow:
        pass
    assert connection.rollback_count == 1
    assert connection.commit_count == 0


def test_exceptional_exit_rolls_back_and_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection()
    _install_connection(monkeypatch, connection)
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    sentinel = RuntimeError("boom")
    with pytest.raises(RuntimeError) as captured, uow:
        raise sentinel
    assert captured.value is sentinel
    assert connection.rollback_count == 1


def test_failed_statement_enters_failed_state(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection(execute_error=_FakePgError("23505"))
    _install_connection(monkeypatch, connection)
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    with pytest.raises(DuplicatePersistenceIdentityError), uow:
        uow._execute("SELECT mtmf.tenant_add(%s)", ("x",))
    # The UnitOfWork was left failed; commit is refused, rollback allowed.
    assert connection.close_count == 1


def test_failed_state_rejects_commit_and_further_operations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection(execute_error=_FakePgError("23505"))
    _install_connection(monkeypatch, connection)
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    uow.__enter__()
    with pytest.raises(DuplicatePersistenceIdentityError):
        uow._execute("SELECT mtmf.tenant_add(%s)", ("x",))
    with pytest.raises(PersistenceTransactionError):
        uow._execute("SELECT mtmf.tenant_get(%s)", ("x",))
    with pytest.raises(PersistenceTransactionError):
        uow.commit()
    uow.rollback()


def test_repository_use_after_completion_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _FakeConnection()
    _install_connection(monkeypatch, connection)
    spi = PostgresMtmfSpi(_runtime_config())
    uow = spi.create_unit_of_work()
    repository = spi.create_tenant_repository(uow)
    with uow:
        uow.commit()
    with pytest.raises(UnitOfWorkStateError):
        repository.get(DomainId.generate())


def test_repository_use_before_enter_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_connection(monkeypatch, _FakeConnection())
    spi = PostgresMtmfSpi(_runtime_config())
    uow = spi.create_unit_of_work()
    repository = spi.create_tenant_repository(uow)
    with pytest.raises(UnitOfWorkStateError):
        repository.get(DomainId.generate())


def test_reentering_completed_unit_of_work_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_connection(monkeypatch, _FakeConnection())
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    with uow:
        uow.commit()
    with pytest.raises(UnitOfWorkStateError), uow:
        pass


def test_unit_of_work_exposes_no_driver_handle(monkeypatch: pytest.MonkeyPatch) -> None:
    _install_connection(monkeypatch, _FakeConnection())
    uow = PostgresMtmfSpi(_runtime_config()).create_unit_of_work()
    with uow:
        for name in ("connection", "cursor", "session", "engine", "pool", "transaction"):
            assert not hasattr(uow, name)
        assert isinstance(uow, PostgresUnitOfWork)
