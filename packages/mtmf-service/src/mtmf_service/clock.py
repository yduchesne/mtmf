"""Injectable UTC clock seam for deterministic snapshot timestamps.

Snapshot ``issued_at``/``expires_at`` are server-issued UTC values taken
from a single clock reading per successful batch. Injecting the clock
keeps the TTL contract testable under a frozen or monotonic source; it is
never caller-controlled.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

__all__ = ["Clock", "FrozenClock", "SystemClock"]


@runtime_checkable
class Clock(Protocol):
    """A source of the current timezone-aware UTC instant."""

    def now(self) -> datetime:
        """Return the current instant as an aware UTC datetime."""
        ...


class SystemClock:
    """Production clock backed by the system wall clock."""

    __slots__ = ()

    def now(self) -> datetime:
        """Return ``datetime.now(UTC)``."""
        return datetime.now(UTC)


class FrozenClock:
    """Deterministic clock for tests; returns the exact injected instant."""

    __slots__ = ("_instant",)

    def __init__(self, instant: datetime) -> None:
        if instant.tzinfo is None or instant.utcoffset() is None:
            raise ValueError("a frozen clock instant must be timezone-aware")
        self._instant = instant.astimezone(UTC)

    def now(self) -> datetime:
        """Return the frozen instant."""
        return self._instant

    def advance(self, **delta: float) -> FrozenClock:
        """Return a new frozen clock advanced by ``timedelta(**delta)``."""
        from datetime import timedelta

        return FrozenClock(self._instant + timedelta(**delta))
