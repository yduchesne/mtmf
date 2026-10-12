"""Real-PostgreSQL verification of runtime session timeouts (PR 17 Amendment #2).

Proves that the restricted runtime identity receives configurable
``statement_timeout``/``lock_timeout`` on every connection, that a blocked
statement is terminated and the transaction rolled back, and that the
connection remains usable afterwards. No privilege is expanded and no
global database setting is changed.
"""

from __future__ import annotations

from dataclasses import replace

import psycopg
import pytest

from mtmf_core.persistence.postgres import PostgresConfig
from mtmf_core.persistence.postgres.config import (
    DEFAULT_RUNTIME_LOCK_TIMEOUT_MS,
    DEFAULT_RUNTIME_STATEMENT_TIMEOUT_MS,
)
from mtmf_core.persistence.postgres.roles import RUNTIME_ROLE


def test_a2_13_default_runtime_config_applies_conservative_timeouts(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    assert runtime_config.statement_timeout_ms == DEFAULT_RUNTIME_STATEMENT_TIMEOUT_MS
    assert runtime_config.lock_timeout_ms == DEFAULT_RUNTIME_LOCK_TIMEOUT_MS
    assert runtime_config.statement_timeout_ms is not None
    assert runtime_config.lock_timeout_ms is not None
    assert runtime_config.lock_timeout_ms < runtime_config.statement_timeout_ms


def test_a2_13_short_timeouts_apply_to_the_session(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    short = replace(runtime_config, statement_timeout_ms=300, lock_timeout_ms=200)
    with psycopg.connect(short.psycopg_dsn) as connection:
        session_user = connection.execute("SELECT session_user").fetchone()[0]
        assert session_user == RUNTIME_ROLE
        assert connection.execute("SHOW statement_timeout").fetchone()[0] == "300ms"
        assert connection.execute("SHOW lock_timeout").fetchone()[0] == "200ms"


def test_a2_14_blocked_statement_is_cancelled_and_rolled_back(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    short = replace(runtime_config, statement_timeout_ms=300, lock_timeout_ms=200)
    connection = psycopg.connect(short.psycopg_dsn)
    try:
        with pytest.raises(psycopg.errors.QueryCanceled):
            connection.execute("SELECT pg_sleep(2)")
        connection.rollback()
        # The session is still usable and the timeout still applies.
        assert connection.execute("SELECT 1").fetchone()[0] == 1
        assert connection.execute("SHOW statement_timeout").fetchone()[0] == "300ms"
    finally:
        connection.close()


def test_a2_14_blocked_lock_is_cancelled(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    short = replace(runtime_config, statement_timeout_ms=2000, lock_timeout_ms=200)
    holder = psycopg.connect(runtime_config.psycopg_dsn, autocommit=True)
    waiter = psycopg.connect(short.psycopg_dsn)
    try:
        holder.execute("SELECT pg_advisory_lock(987654321)")
        with pytest.raises(psycopg.errors.LockNotAvailable):
            waiter.execute("SELECT pg_advisory_lock(987654321)")
        waiter.rollback()
        assert waiter.execute("SELECT 1").fetchone()[0] == 1
    finally:
        waiter.close()
        holder.rollback()
        holder.close()


def test_a2_14_timeout_does_not_leave_a_broken_transaction(
    runtime_config: PostgresConfig, db: psycopg.Connection
) -> None:
    short = replace(runtime_config, statement_timeout_ms=200, lock_timeout_ms=150)
    with psycopg.connect(short.psycopg_dsn) as connection:
        with pytest.raises(psycopg.errors.QueryCanceled):
            connection.execute("SELECT pg_sleep(1)")
        connection.rollback()
        # A fresh transaction on the same connection is healthy.
        assert connection.execute("SELECT current_user").fetchone()[0] == RUNTIME_ROLE
