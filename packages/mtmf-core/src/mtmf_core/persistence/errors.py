"""Provider-neutral persistence errors.

This is the internal error hierarchy needed for deterministic
persistence-contract semantics. The base errors model contract
semantics (duplicate/unknown identity, lifecycle, ownership). PR 7B adds
narrow provider-neutral subclasses for failures a concrete provider can
encounter but must translate into the same vocabulary rather than leak
SQLSTATE codes, driver exception classes, DSNs, or SQL text to callers.

No provider-neutral error models a raw SQLSTATE, constraint name, or
driver type: a concrete provider is responsible for that translation.
"""

from __future__ import annotations


class PersistenceError(Exception):
    """Base class for deterministic persistence contract failures."""


class UnitOfWorkError(PersistenceError):
    """Superclass for UnitOfWork lifecycle and ownership violations."""


class UnitOfWorkStateError(UnitOfWorkError):
    """A UnitOfWork or repository operation ran in an invalid lifecycle state.

    Examples: a second commit, commit-after-rollback, lifecycle calls on
    a UnitOfWork that was never entered, or repository use after the
    owning UnitOfWork completed.
    """


class ForeignUnitOfWorkError(UnitOfWorkError):
    """A repository factory received a UnitOfWork owned by another provider.

    Repository factories reject UnitOfWork objects created by any other
    persistence provider instance; a repository is never bound to a
    foreign transaction.
    """


class DuplicatePersistenceIdentityError(PersistenceError):
    """An immutable persistence identity already exists.

    Adding an identity that already exists (committed, or staged inside
    the current UnitOfWork) is rejected and never silently overwrites.

    Mutable names are presentation metadata, not persistence identity.
    """


class UnknownPersistenceIdentityError(PersistenceError):
    """A save operation targets an identity that does not exist.

    Saving never silently creates an identity: the entity must already
    be known (committed, or added inside the current UnitOfWork).
    """


class PersistenceConfigurationError(PersistenceError):
    """A persistence provider was constructed with an unsupported configuration.

    A production provider rejects a configuration that does not describe
    its required least-privilege identity (for example an administrator
    or migration credential offered to the application runtime) before
    any connection is opened.
    """


class PersistenceConnectionError(PersistenceError):
    """A provider transaction could not be established as the approved identity.

    The connection could not be opened, or it authenticated as an
    identity other than the one the provider configuration declared; the
    provider fails closed rather than operating with unexpected
    database capability.
    """


class PersistenceTransactionError(PersistenceError):
    """A UnitOfWork transaction is aborted or otherwise no longer usable.

    A failed statement aborts its PostgreSQL transaction. The owning
    UnitOfWork enters a deterministic failed state, rejects further
    repository operation, and can only be rolled back and closed; it can
    never commit partial or invalid state.
    """


class PersistenceConcurrencyError(PersistenceTransactionError):
    """A transaction failed for a retryable concurrency reason.

    Serialization failures and deadlocks are classified separately from
    contract violations; the caller may retry the whole business
    operation on a new UnitOfWork. The provider never retries silently
    and never installs hidden savepoints.
    """


class PersistenceConstraintError(PersistenceError):
    """A database integrity constraint rejected a persistence operation.

    Superclass for deterministic structural failures (missing
    prerequisite references, check/definition violations, invalid value
    representations). It is never used to represent a connection,
    serialization, or contract-identity failure.
    """


class PersistenceReferenceError(PersistenceConstraintError):
    """A referenced prerequisite identity or relationship does not exist.

    Examples: an Identity referencing an absent Principal, or a typed
    membership whose prerequisite membership is missing. The operation
    is rejected and never turned into a no-op.
    """


class PersistenceIntegrityError(PersistenceConstraintError):
    """A structural or definition-integrity invariant was violated.

    Examples: a non-object JSON extension value, an aggregate child that
    points at a different owner, or an immutable structural column
    update attempt.
    """


class PersistenceValueError(PersistenceConstraintError):
    """A persisted or supplied value had an invalid representation.

    Named distinctly from the builtin :class:`ValueError`; it denotes a
    database-level value/representation failure, not a Python argument
    error.
    """


class PersistenceDataError(PersistenceError):
    """Stored data could not be mapped to a valid domain object.

    The provider fails closed on corrupt, truncated, or shape-invalid
    rows instead of coercing them or returning a partially initialized
    aggregate.
    """
