"""PostgreSQL error translation for the MTMF persistence provider.

Repository operations run inside a reviewed ``SECURITY DEFINER`` stored
function; a failure surfaces as a psycopg exception carrying a SQLSTATE.
Callers of the persistence SPI never see psycopg errors, SQLSTATEs,
constraint names, SQL text, or credentials: this module maps a driver
failure to one deterministic provider-neutral error.

Classification is deliberately coarse and reviewable:

- duplicate immutable identity (``23505``);
- missing prerequisite reference (``23503`` and the reviewed custom
  ``MT002``/``MT003`` codes);
- check/definition integrity violation (``23514`` and ``MT001``);
- invalid value representation (``22P02``);
- retryable concurrency failure (``40001`` serialization, ``40P01``
  deadlock);
- any other statement failure aborts the transaction and is a
  :class:`PersistenceTransactionError`.

A failed statement aborts its PostgreSQL transaction. The owning
UnitOfWork therefore also enters a deterministic failed state (see
:class:`~mtmf_core.persistence.postgres.unit_of_work.PostgresUnitOfWork`);
translation is not a signal that the transaction remains usable.
"""

from __future__ import annotations

import psycopg

from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    PersistenceConcurrencyError,
    PersistenceConnectionError,
    PersistenceConstraintError,
    PersistenceError,
    PersistenceIntegrityError,
    PersistenceReferenceError,
    PersistenceTransactionError,
    PersistenceValueError,
)

#: Reviewed custom SQLSTATEs raised by the stored functions. They are
#: intentionally not PostgreSQL standard codes; the strings are internal
#: to the provider and never exposed to callers as text.
CUSTOM_AGGREGATE_INTEGRITY = "MT001"
CUSTOM_MISSING_PREREQUISITE = "MT002"
CUSTOM_INVALID_PAYLOAD = "MT003"
CUSTOM_ASSIGNMENT_CONTEXT = "MT004"

_UNIQUE_VIOLATION = "23505"
_FOREIGN_KEY_VIOLATION = "23503"
_CHECK_VIOLATION = "23514"
_INVALID_TEXT_REPRESENTATION = "22P02"
_SERIALIZATION_FAILURE = "40001"
_DEADLOCK_DETECTED = "40P01"

_REFERENCE_CODES = frozenset({_FOREIGN_KEY_VIOLATION, CUSTOM_MISSING_PREREQUISITE})
_INTEGRITY_CODES = frozenset(
    {
        _CHECK_VIOLATION,
        CUSTOM_AGGREGATE_INTEGRITY,
        CUSTOM_INVALID_PAYLOAD,
        CUSTOM_ASSIGNMENT_CONTEXT,
    }
)


def _sqlstate(exc: psycopg.Error) -> str | None:
    """Return the driver-reported SQLSTATE, when present, as plain text."""
    candidate = getattr(exc, "sqlstate", None)
    if candidate is None:
        return None
    return str(candidate)


def translate_operation_error(exc: psycopg.Error) -> PersistenceError:
    """Map a failed repository statement to a provider-neutral error.

    Never includes SQL text, DSNs, or credentials in the returned error.
    """
    code = _sqlstate(exc)
    if code == _UNIQUE_VIOLATION:
        return DuplicatePersistenceIdentityError(
            "the requested persistence identity already exists"
        )
    if code in _REFERENCE_CODES:
        return PersistenceReferenceError(
            "a required referenced persistence identity or prerequisite relationship is absent"
        )
    if code in _INTEGRITY_CODES:
        return PersistenceIntegrityError(
            "the requested persistence state violates a structural integrity invariant"
        )
    if code == _INVALID_TEXT_REPRESENTATION:
        return PersistenceValueError("a supplied persistence value has an invalid representation")
    if code in (_SERIALIZATION_FAILURE, _DEADLOCK_DETECTED):
        return PersistenceConcurrencyError(
            "the transaction failed for a retryable concurrency reason"
        )
    return PersistenceTransactionError(
        "the persistence statement failed and aborted the transaction"
    )


def translate_connection_error(exc: psycopg.Error) -> PersistenceError:
    """Map a connection-establishment failure to a provider-neutral error."""
    return PersistenceConnectionError(
        "the persistence transaction could not be established as the approved identity"
    )


def is_constraint_error(exc: PersistenceError) -> bool:
    """Whether a translated error is a deterministic constraint failure."""
    return isinstance(exc, PersistenceConstraintError)
