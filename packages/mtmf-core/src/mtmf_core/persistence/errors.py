"""Provider-neutral persistence errors.

This is the minimal internal error hierarchy needed for deterministic
persistence-contract semantics. It deliberately does not model SQLSTATE
codes, constraint classes, deadlocks, connection failures, or driver
errors: those are PostgreSQL-provider internals owned by later PRs.
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
