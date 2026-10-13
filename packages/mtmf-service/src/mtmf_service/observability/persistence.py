"""Adapter mapping core persistence observations into service metrics.

The core UnitOfWork exposes a provider-neutral ``PersistenceTelemetry``
protocol with primitive ``operation``/``outcome`` strings. This adapter
validates them against the closed service enums; an unrecognized value is
dropped rather than recorded as a high-cardinality or guessed label.
"""

from __future__ import annotations

from mtmf_core.persistence.instrumentation import PersistenceTelemetry
from mtmf_service.observability.metrics import (
    PersistenceOperation,
    PersistenceOutcome,
)
from mtmf_service.observability.runtime import Telemetry

__all__ = ["MetricsPersistenceTelemetry"]


class MetricsPersistenceTelemetry:
    """A ``PersistenceTelemetry`` that forwards to the service metrics recorder."""

    __slots__ = ("_telemetry",)

    def __init__(self, telemetry: Telemetry) -> None:
        self._telemetry = telemetry

    def record_operation(self, *, operation: str, outcome: str, duration_ms: float) -> None:
        """Record one bounded persistence observation.

        Unknown operation/outcome values are ignored; the target recorder
        performs its own duration and label validation.
        """
        try:
            resolved_operation = PersistenceOperation(operation)
            resolved_outcome = PersistenceOutcome(outcome)
        except ValueError:
            return
        self._telemetry.record_persistence_metric(
            operation=resolved_operation,
            outcome=resolved_outcome,
            duration_ms=duration_ms,
        )


#: Static conformance assertion: the adapter satisfies the core protocol.
_PROTOCOL_CONFORMANCE: type[PersistenceTelemetry] = MetricsPersistenceTelemetry
