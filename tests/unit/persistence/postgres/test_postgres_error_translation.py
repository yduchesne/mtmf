"""Unit tests for PostgreSQL error translation (no database).

A driver failure must map deterministically to a provider-neutral error
without leaking SQLSTATE text, SQL, DSNs, or credentials. The fake
exceptions carry only the ``sqlstate`` attribute the translator reads.
"""

from __future__ import annotations

from typing import cast

import psycopg
import pytest

from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    PersistenceConcurrencyError,
    PersistenceConnectionError,
    PersistenceConstraintError,
    PersistenceIntegrityError,
    PersistenceReferenceError,
    PersistenceTransactionError,
    PersistenceValueError,
)
from mtmf_core.persistence.postgres import error_translation
from mtmf_core.persistence.postgres.error_translation import (
    is_constraint_error,
    translate_connection_error,
    translate_operation_error,
)


class _DriverError(Exception):
    def __init__(self, sqlstate: str | None) -> None:
        super().__init__("driver detail that must not leak")
        self.sqlstate = sqlstate


def _as_error(sqlstate: str | None) -> psycopg.Error:
    return cast(psycopg.Error, _DriverError(sqlstate))


@pytest.mark.parametrize(
    ("sqlstate", "expected"),
    [
        ("23505", DuplicatePersistenceIdentityError),
        ("23503", PersistenceReferenceError),
        ("23514", PersistenceIntegrityError),
        ("22P02", PersistenceValueError),
        (error_translation.CUSTOM_AGGREGATE_INTEGRITY, PersistenceIntegrityError),
        (error_translation.CUSTOM_MISSING_PREREQUISITE, PersistenceReferenceError),
        (error_translation.CUSTOM_INVALID_PAYLOAD, PersistenceIntegrityError),
    ],
)
def test_known_sqlstates_map_to_their_errors(sqlstate: str, expected: type[Exception]) -> None:
    translated = translate_operation_error(_as_error(sqlstate))
    assert isinstance(translated, expected)
    assert "driver detail" not in str(translated)


def test_structural_sqlstates_are_constraint_errors() -> None:
    for sqlstate in (
        "23503",
        "23514",
        "22P02",
        error_translation.CUSTOM_AGGREGATE_INTEGRITY,
        error_translation.CUSTOM_MISSING_PREREQUISITE,
        error_translation.CUSTOM_INVALID_PAYLOAD,
    ):
        translated = translate_operation_error(_as_error(sqlstate))
        assert isinstance(translated, PersistenceConstraintError)


@pytest.mark.parametrize("sqlstate", ["40001", "40P01"])
def test_concurrency_sqlstates_map_to_retryable_errors(sqlstate: str) -> None:
    translated = translate_operation_error(_as_error(sqlstate))
    assert isinstance(translated, PersistenceConcurrencyError)
    assert isinstance(translated, PersistenceTransactionError)


@pytest.mark.parametrize("sqlstate", ["42601", "XX000", None, "P0001"])
def test_unknown_sqlstates_map_to_transaction_errors(sqlstate: str | None) -> None:
    translated = translate_operation_error(_as_error(sqlstate))
    assert isinstance(translated, PersistenceTransactionError)
    assert not isinstance(translated, PersistenceConcurrencyError)


def test_connection_error_is_secret_free() -> None:
    translated = translate_connection_error(_as_error(None))
    assert isinstance(translated, PersistenceConnectionError)
    assert "driver detail" not in str(translated)


def test_constraint_classification_helper() -> None:
    assert is_constraint_error(PersistenceReferenceError("x"))
    assert is_constraint_error(PersistenceIntegrityError("x"))
    assert not is_constraint_error(PersistenceTransactionError("x"))
    assert not is_constraint_error(PersistenceConnectionError("x"))
    assert not is_constraint_error(DuplicatePersistenceIdentityError("x"))
