"""Concrete PostgreSQL UnitOfWork.

One :class:`PostgresUnitOfWork` owns exactly one psycopg connection and
one real PostgreSQL transaction. Every repository created from the
UnitOfWork shares that connection, so all staged writes commit or roll
back together.

Lifecycle semantics mirror the provider-neutral contract exactly:

- ``__enter__`` opens the connection using the runtime-only DSN and
  verifies the authenticated identity is the restricted login *before*
  any repository statement runs; a mislabelled or elevated login fails
  closed;
- :meth:`commit` commits once and completes the UnitOfWork;
- a normal exit without an explicit commit rolls back;
- an exceptional exit rolls back and never suppresses the original
  exception;
- :meth:`rollback` discards all staged changes and completes;
- after completion the UnitOfWork and every repository created from it
  fail deterministically.

In addition, a failed statement aborts the PostgreSQL transaction. The
UnitOfWork then enters a ``FAILED`` state that rejects further
repository calls and refuses to commit; only rollback-and-close is
possible. No savepoints and no automatic retries are introduced.
"""

from __future__ import annotations

from contextlib import suppress
from enum import Enum
from types import TracebackType
from typing import TYPE_CHECKING, Self

import psycopg

from mtmf_core.persistence.errors import (
    PersistenceTransactionError,
    UnitOfWorkStateError,
)
from mtmf_core.persistence.postgres.config import PostgresConfig
from mtmf_core.persistence.postgres.error_translation import (
    translate_connection_error,
    translate_operation_error,
)
from mtmf_core.persistence.postgres.roles import RUNTIME_ROLE

if TYPE_CHECKING:
    from mtmf_core.persistence.postgres.spi import PostgresMtmfSpi


class _UnitOfWorkState(Enum):
    """Internal lifecycle state of a PostgreSQL UnitOfWork."""

    PENDING = "pending"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"


class PostgresUnitOfWork:
    """One real PostgreSQL transaction bound to a runtime-only configuration."""

    def __init__(self, config: PostgresConfig, spi: PostgresMtmfSpi) -> None:
        self._config = config
        self._spi = spi
        self._state = _UnitOfWorkState.PENDING
        self._connection: psycopg.Connection | None = None

    # -- lifecycle -----------------------------------------------------------

    def __enter__(self) -> Self:
        """Open the single transaction and verify the runtime identity."""
        if self._state is not _UnitOfWorkState.PENDING:
            raise UnitOfWorkStateError(
                "UnitOfWork cannot be entered: it is not in its initial state "
                f"(current state is {self._state.value})"
            )
        try:
            connection = psycopg.connect(self._config.psycopg_dsn, autocommit=False)
        except psycopg.Error as exc:
            raise translate_connection_error(exc) from exc
        try:
            row = connection.execute("SELECT session_user, current_user").fetchone()
        except psycopg.Error as exc:
            connection.close()
            raise translate_connection_error(exc) from exc
        session_user = None if row is None else row[0]
        current_user = None if row is None else row[1]
        if session_user != RUNTIME_ROLE or current_user != RUNTIME_ROLE:
            connection.close()
            raise translate_connection_error(psycopg.OperationalError("runtime identity mismatch"))
        self._connection = connection
        self._state = _UnitOfWorkState.ACTIVE
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Roll back any open transaction, close, and never suppress an exception."""
        if self._state in (_UnitOfWorkState.ACTIVE, _UnitOfWorkState.FAILED):
            self._safe_rollback()
            self._state = _UnitOfWorkState.COMPLETED
        self._close()
        return None

    def commit(self) -> None:
        """Make all staged changes durable exactly once and complete the UnitOfWork."""
        if self._state is _UnitOfWorkState.FAILED:
            raise PersistenceTransactionError(
                "the UnitOfWork transaction is aborted and cannot be committed; "
                "roll it back and retry the business operation on a new UnitOfWork"
            )
        if self._state is not _UnitOfWorkState.ACTIVE:
            raise UnitOfWorkStateError(
                "commit requires an active UnitOfWork; current UnitOfWork state is "
                f"{self._state.value}"
            )
        connection = self._require_connection()
        try:
            connection.commit()
        except psycopg.Error as exc:
            self._state = _UnitOfWorkState.FAILED
            raise translate_operation_error(exc) from exc
        self._state = _UnitOfWorkState.COMPLETED

    def rollback(self) -> None:
        """Discard every staged change and complete the UnitOfWork."""
        if self._state not in (_UnitOfWorkState.ACTIVE, _UnitOfWorkState.FAILED):
            raise UnitOfWorkStateError(
                f"rollback requires an active UnitOfWork; current UnitOfWork state is "
                f"{self._state.value}"
            )
        self._safe_rollback()
        self._state = _UnitOfWorkState.COMPLETED

    # -- private operation surface (never a public contract) -----------------

    def _require_active(self, operation: str) -> None:
        """Fail unless this UnitOfWork currently hosts a usable transaction."""
        if self._state is _UnitOfWorkState.FAILED:
            raise PersistenceTransactionError(
                f"{operation} cannot run: the UnitOfWork transaction is aborted; "
                "roll it back and retry the business operation on a new UnitOfWork"
            )
        if self._state is not _UnitOfWorkState.ACTIVE:
            raise UnitOfWorkStateError(
                f"{operation} requires an active UnitOfWork; "
                f"current UnitOfWork state is {self._state.value}"
            )

    def _execute(self, query: str, params: tuple[object, ...]) -> psycopg.Cursor:
        """Run one reviewed stored-function call within this transaction."""
        self._require_active("repository operation")
        try:
            return self._require_connection().execute(query, params)
        except psycopg.Error as exc:
            self._state = _UnitOfWorkState.FAILED
            raise translate_operation_error(exc) from exc

    # -- helpers -------------------------------------------------------------

    def _require_connection(self) -> psycopg.Connection:
        if self._connection is None:
            raise UnitOfWorkStateError("the UnitOfWork has no open transaction")
        return self._connection

    def _safe_rollback(self) -> None:
        connection = self._connection
        if connection is None or connection.closed:
            return
        # Best-effort cleanup: the connection is closed regardless, and no
        # partial commit can occur after a rollback attempt.
        with suppress(psycopg.Error):
            connection.rollback()

    def _close(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None and not connection.closed:
            connection.close()
