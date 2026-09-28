"""UnitOfWork contract.

A UnitOfWork represents one provider transaction without leaking any
connection, cursor, session, engine, or driver object into public
abstractions. Every repository participating in one business operation
is created from and shares the same UnitOfWork.

Lifecycle contract:

- :meth:`__enter__` establishes exactly one provider transaction;
- :meth:`commit` makes staged changes durable and completes the UnitOfWork;
- a normal :meth:`__exit__` without an explicit commit rolls back;
- an exceptional :meth:`__exit__` rolls back and never suppresses the
  original exception;
- :meth:`rollback` discards all staged changes and completes the UnitOfWork;
- after completion, the UnitOfWork and every repository created from it
  deterministically fail further use.

There are no nested UnitOfWorks, savepoints, transaction joining, or
distributed transactions.
"""

from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self, runtime_checkable


@runtime_checkable
class UnitOfWork(Protocol):
    """Provider-neutral transaction boundary.

    Implementations own the transaction handle; this contract never
    exposes it. ``bool`` return from :meth:`__exit__` is permitted but
    must never be ``True``: exceptions always propagate.
    """

    def __enter__(self) -> Self:
        """Establish the provider transaction and return this UnitOfWork."""
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Close the transaction according to the lifecycle contract.

        Returns ``None`` so the original exception, when present, always
        propagates.
        """
        ...

    def commit(self) -> None:
        """Make all staged changes from this UnitOfWork durable.

        :raises UnitOfWorkStateError: if the UnitOfWork is not active.
        """
        ...

    def rollback(self) -> None:
        """Discard all staged changes from this UnitOfWork.

        :raises UnitOfWorkStateError: if the UnitOfWork is not active.
        """
        ...
