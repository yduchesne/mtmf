"""Provider-neutral persistence telemetry seam.

``mtmf-core`` must not depend on a telemetry SDK, exporter, ORM or HTTP
framework. This module defines the minimal structural contract the
PostgreSQL UnitOfWork uses to report bounded operation observations, plus a
no-op implementation. The service layer supplies an adapter that maps these
values into its metrics recorder.

The seam deliberately exposes only a closed ``operation``/``outcome``
vocabulary and a duration. No query text, parameter value, table name,
column name, actor identifier or connection detail crosses it.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

__all__ = ["NoopPersistenceTelemetry", "PersistenceTelemetry"]


@runtime_checkable
class PersistenceTelemetry(Protocol):
    """A bounded observation sink for persistence operations."""

    def record_operation(self, *, operation: str, outcome: str, duration_ms: float) -> None:
        """Record one persistence observation.

        Implementations must never raise into the caller; the provider
        additionally wraps every call defensively. ``operation`` is one of
        ``read``/``write``/``transaction`` and ``outcome`` one of
        ``success``/``failure``/``rollback``; an unknown value is ignored
        rather than guessed.
        """
        ...


class NoopPersistenceTelemetry:
    """A persistence telemetry sink that discards every observation."""

    __slots__ = ()

    def record_operation(self, *, operation: str, outcome: str, duration_ms: float) -> None:
        """Discard the observation."""
        del operation, outcome, duration_ms
