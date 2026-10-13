"""Low-cardinality metric instruments for the MTMF service.

Every dimension is a closed enum. Arbitrary routes, methods, outcomes,
identifiers, SQL text or exception text cannot become a metric attribute:
:class:`OtelMetricsRecorder` validates each value and raises
:class:`InvalidTelemetryAttributeError`, which the telemetry boundary converts
into a bounded export-failure observation instead of a datapoint. This is
the structural guarantee behind the "no high-cardinality labels" rule.
"""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

from opentelemetry.metrics import Meter

from mtmf_service.observability.events import AuditReason

__all__ = [
    "AuthorizationEffectLabel",
    "BatchOutcomeLabel",
    "DependencyFailureCategory",
    "DependencyLabel",
    "HttpMethod",
    "HttpRoute",
    "HttpStatusClass",
    "InMemoryMetricsRecorder",
    "InvalidTelemetryAttributeError",
    "MetricsRecorder",
    "NoopMetricsRecorder",
    "OtelMetricsRecorder",
    "PersistenceOperation",
    "PersistenceOutcome",
    "TelemetrySignal",
]

#: Histogram bucket boundaries in milliseconds spanning sub-millisecond to
#: multi-second workloads. Recorded so deployments can review them.
DURATION_BUCKETS_MS: Final[tuple[float, ...]] = (
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    25.0,
    50.0,
    100.0,
    250.0,
    500.0,
    1000.0,
    2500.0,
    5000.0,
    10000.0,
)

#: Batch-size histogram boundaries in Action occurrences.
BATCH_SIZE_BUCKETS: Final[tuple[float, ...]] = (
    1.0,
    2.0,
    5.0,
    10.0,
    25.0,
    50.0,
    100.0,
)


class InvalidTelemetryAttributeError(ValueError):
    """A metric attribute was not a member of its closed, bounded enum."""


class HttpRoute(StrEnum):
    """The closed set of instrumented HTTP route templates."""

    EVALUATE = "/v1/authorization/evaluate"
    LIVE = "/health/live"
    READY = "/health/ready"
    UNKNOWN = "unknown"


class HttpMethod(StrEnum):
    """The closed set of instrumented HTTP methods."""

    GET = "GET"
    POST = "POST"
    UNKNOWN = "UNKNOWN"


class HttpStatusClass(StrEnum):
    """The closed set of HTTP status classes."""

    SUCCESS = "2xx"
    REDIRECT = "3xx"
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"
    UNKNOWN = "unknown"


class BatchOutcomeLabel(StrEnum):
    """The closed set of batch outcome labels."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    MIXED = "MIXED"


class AuthorizationEffectLabel(StrEnum):
    """The closed set of per-Action effect labels."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class PersistenceOperation(StrEnum):
    """The closed set of persistence operation labels."""

    READ = "read"
    WRITE = "write"
    TRANSACTION = "transaction"


class PersistenceOutcome(StrEnum):
    """The closed set of persistence outcome labels."""

    SUCCESS = "success"
    FAILURE = "failure"
    ROLLBACK = "rollback"


class DependencyLabel(StrEnum):
    """The closed set of external dependency labels."""

    POSTGRES = "postgres"
    ISSUER = "issuer"
    COLLECTOR = "collector"


class DependencyFailureCategory(StrEnum):
    """The closed set of dependency failure categories."""

    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    PROTOCOL = "protocol"
    OTHER = "other"


class TelemetrySignal(StrEnum):
    """The closed set of telemetry signals."""

    LOGS = "logs"
    TRACES = "traces"
    METRICS = "metrics"


def _require_enum(value: object, enum_type: type[StrEnum], field_name: str) -> str:
    if not isinstance(value, enum_type):
        raise InvalidTelemetryAttributeError(
            f"{field_name} must be a {enum_type.__name__}, got {type(value).__name__}"
        )
    return value.value


def _require_finite(value: float, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise InvalidTelemetryAttributeError(f"{field_name} must be finite")
    if value < 0:
        raise InvalidTelemetryAttributeError(f"{field_name} must be nonnegative")
    return float(value)


@runtime_checkable
class MetricsRecorder(Protocol):
    """A bounded, low-cardinality metric recorder."""

    def record_http_request(
        self,
        *,
        route: HttpRoute,
        method: HttpMethod,
        status_class: HttpStatusClass,
        duration_ms: float,
    ) -> None: ...

    def record_batch(
        self,
        *,
        outcome: BatchOutcomeLabel,
        duration_ms: float,
        action_count: int,
        allow_count: int,
        deny_count: int,
    ) -> None: ...

    def record_rejection(self, *, category: AuditReason) -> None: ...

    def record_persistence(
        self,
        *,
        operation: PersistenceOperation,
        outcome: PersistenceOutcome,
        duration_ms: float,
    ) -> None: ...

    def record_dependency_failure(
        self,
        *,
        dependency: DependencyLabel,
        category: DependencyFailureCategory,
    ) -> None: ...

    def record_export_failure(self, *, signal: TelemetrySignal) -> None: ...

    def record_dropped_events(self, *, signal: TelemetrySignal) -> None: ...


class NoopMetricsRecorder:
    """A recorder that discards every observation (disabled telemetry)."""

    __slots__ = ()

    def record_http_request(
        self,
        *,
        route: HttpRoute,
        method: HttpMethod,
        status_class: HttpStatusClass,
        duration_ms: float,
    ) -> None:
        del route, method, status_class, duration_ms

    def record_batch(
        self,
        *,
        outcome: BatchOutcomeLabel,
        duration_ms: float,
        action_count: int,
        allow_count: int,
        deny_count: int,
    ) -> None:
        del outcome, duration_ms, action_count, allow_count, deny_count

    def record_rejection(self, *, category: AuditReason) -> None:
        del category

    def record_persistence(
        self,
        *,
        operation: PersistenceOperation,
        outcome: PersistenceOutcome,
        duration_ms: float,
    ) -> None:
        del operation, outcome, duration_ms

    def record_dependency_failure(
        self,
        *,
        dependency: DependencyLabel,
        category: DependencyFailureCategory,
    ) -> None:
        del dependency, category

    def record_export_failure(self, *, signal: TelemetrySignal) -> None:
        del signal

    def record_dropped_events(self, *, signal: TelemetrySignal) -> None:
        del signal


class InMemoryMetricsRecorder:
    """A deterministic, validating recorder for tests and diagnostics."""

    __slots__ = ("_counters", "_histograms")

    def __init__(self) -> None:
        self._counters: list[tuple[str, dict[str, str], int]] = []
        self._histograms: list[tuple[str, dict[str, str], float]] = []

    @property
    def counters(self) -> tuple[tuple[str, dict[str, str], int], ...]:
        """A snapshot of recorded counter increments."""
        return tuple((name, dict(attrs), value) for name, attrs, value in self._counters)

    @property
    def histograms(self) -> tuple[tuple[str, dict[str, str], float], ...]:
        """A snapshot of recorded histogram observations."""
        return tuple((name, dict(attrs), value) for name, attrs, value in self._histograms)

    def _counter(self, name: str, attributes: dict[str, str], value: int = 1) -> None:
        self._counters.append((name, attributes, value))

    def _histogram(self, name: str, attributes: dict[str, str], value: float) -> None:
        self._histograms.append((name, attributes, value))

    def record_http_request(
        self,
        *,
        route: HttpRoute,
        method: HttpMethod,
        status_class: HttpStatusClass,
        duration_ms: float,
    ) -> None:
        attributes = {
            "route": _require_enum(route, HttpRoute, "route"),
            "method": _require_enum(method, HttpMethod, "method"),
            "status_class": _require_enum(status_class, HttpStatusClass, "status_class"),
        }
        self._counter("mtmf.http.requests", attributes)
        self._histogram(
            "mtmf.http.duration", attributes, _require_finite(duration_ms, "duration_ms")
        )

    def record_batch(
        self,
        *,
        outcome: BatchOutcomeLabel,
        duration_ms: float,
        action_count: int,
        allow_count: int,
        deny_count: int,
    ) -> None:
        label = _require_enum(outcome, BatchOutcomeLabel, "outcome")
        for value, field_name in (
            (action_count, "action_count"),
            (allow_count, "allow_count"),
            (deny_count, "deny_count"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidTelemetryAttributeError(f"{field_name} must be a nonnegative integer")
        if allow_count + deny_count != action_count:
            raise InvalidTelemetryAttributeError("allow_count + deny_count must equal action_count")
        label_attributes = {"outcome": label}
        self._counter("mtmf.authorization.batches", label_attributes)
        self._histogram(
            "mtmf.authorization.batch.duration",
            label_attributes,
            _require_finite(duration_ms, "duration_ms"),
        )
        self._histogram("mtmf.authorization.batch.size", {}, float(_require_size(action_count)))
        self._counter(
            "mtmf.authorization.actions",
            {"effect": AuthorizationEffectLabel.ALLOW.value},
            allow_count,
        )
        self._counter(
            "mtmf.authorization.actions",
            {"effect": AuthorizationEffectLabel.DENY.value},
            deny_count,
        )

    def record_rejection(self, *, category: AuditReason) -> None:
        self._counter(
            "mtmf.security.rejections",
            {"category": _require_enum(category, AuditReason, "category")},
        )

    def record_persistence(
        self,
        *,
        operation: PersistenceOperation,
        outcome: PersistenceOutcome,
        duration_ms: float,
    ) -> None:
        attributes = {
            "operation": _require_enum(operation, PersistenceOperation, "operation"),
            "outcome": _require_enum(outcome, PersistenceOutcome, "outcome"),
        }
        self._counter("mtmf.persistence.operations", attributes)
        self._histogram(
            "mtmf.persistence.duration", attributes, _require_finite(duration_ms, "duration_ms")
        )

    def record_dependency_failure(
        self,
        *,
        dependency: DependencyLabel,
        category: DependencyFailureCategory,
    ) -> None:
        self._counter(
            "mtmf.dependencies.failures",
            {
                "dependency": _require_enum(dependency, DependencyLabel, "dependency"),
                "category": _require_enum(category, DependencyFailureCategory, "category"),
            },
        )

    def record_export_failure(self, *, signal: TelemetrySignal) -> None:
        self._counter(
            "mtmf.telemetry.export.failures",
            {"signal": _require_enum(signal, TelemetrySignal, "signal")},
        )

    def record_dropped_events(self, *, signal: TelemetrySignal) -> None:
        self._counter(
            "mtmf.telemetry.dropped.events",
            {"signal": _require_enum(signal, TelemetrySignal, "signal")},
        )


def _require_size(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidTelemetryAttributeError("batch size must be a nonnegative integer")
    return value


class OtelMetricsRecorder:
    """An :class:`MetricsRecorder` backed by an OTel meter.

    The recorder validates every dimension before recording; an invalid
    attribute raises rather than creating a high-cardinality datapoint.
    """

    __slots__ = (
        "_actions",
        "_batch_duration",
        "_batch_size",
        "_batches",
        "_dependencies",
        "_dropped",
        "_export_failures",
        "_http_duration",
        "_http_requests",
        "_persistence_duration",
        "_persistence_operations",
        "_rejections",
    )

    def __init__(self, meter: Meter) -> None:
        self._http_requests = meter.create_counter(
            "mtmf.http.requests", unit="{request}", description="Completed HTTP requests"
        )
        self._http_duration = meter.create_histogram(
            "mtmf.http.duration",
            unit="ms",
            description="HTTP request duration",
            explicit_bucket_boundaries_advisory=DURATION_BUCKETS_MS,
        )
        self._batches = meter.create_counter(
            "mtmf.authorization.batches", unit="{batch}", description="Validated batch decisions"
        )
        self._actions = meter.create_counter(
            "mtmf.authorization.actions", unit="{action}", description="Per-Action decisions"
        )
        self._batch_duration = meter.create_histogram(
            "mtmf.authorization.batch.duration",
            unit="ms",
            description="Batch evaluation duration",
            explicit_bucket_boundaries_advisory=DURATION_BUCKETS_MS,
        )
        self._batch_size = meter.create_histogram(
            "mtmf.authorization.batch.size",
            unit="{action}",
            description="Accepted batch size",
            explicit_bucket_boundaries_advisory=BATCH_SIZE_BUCKETS,
        )
        self._rejections = meter.create_counter(
            "mtmf.security.rejections", unit="{request}", description="Rejected requests"
        )
        self._persistence_operations = meter.create_counter(
            "mtmf.persistence.operations", unit="{operation}", description="Persistence operations"
        )
        self._persistence_duration = meter.create_histogram(
            "mtmf.persistence.duration",
            unit="ms",
            description="Persistence operation duration",
            explicit_bucket_boundaries_advisory=DURATION_BUCKETS_MS,
        )
        self._dependencies = meter.create_counter(
            "mtmf.dependencies.failures", unit="{failure}", description="Dependency failures"
        )
        self._export_failures = meter.create_counter(
            "mtmf.telemetry.export.failures",
            unit="{failure}",
            description="Telemetry export failures",
        )
        self._dropped = meter.create_counter(
            "mtmf.telemetry.dropped.events", unit="{event}", description="Dropped telemetry events"
        )

    def record_http_request(
        self,
        *,
        route: HttpRoute,
        method: HttpMethod,
        status_class: HttpStatusClass,
        duration_ms: float,
    ) -> None:
        attributes = {
            "route": _require_enum(route, HttpRoute, "route"),
            "method": _require_enum(method, HttpMethod, "method"),
            "status_class": _require_enum(status_class, HttpStatusClass, "status_class"),
        }
        self._http_requests.add(1, attributes)
        self._http_duration.record(_require_finite(duration_ms, "duration_ms"), attributes)

    def record_batch(
        self,
        *,
        outcome: BatchOutcomeLabel,
        duration_ms: float,
        action_count: int,
        allow_count: int,
        deny_count: int,
    ) -> None:
        label = _require_enum(outcome, BatchOutcomeLabel, "outcome")
        for value, field_name in (
            (action_count, "action_count"),
            (allow_count, "allow_count"),
            (deny_count, "deny_count"),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise InvalidTelemetryAttributeError(f"{field_name} must be a nonnegative integer")
        if allow_count + deny_count != action_count:
            raise InvalidTelemetryAttributeError("allow_count + deny_count must equal action_count")
        attributes = {"outcome": label}
        self._batches.add(1, attributes)
        self._batch_duration.record(_require_finite(duration_ms, "duration_ms"), attributes)
        self._batch_size.record(_require_size(action_count), {})
        self._actions.add(allow_count, {"effect": AuthorizationEffectLabel.ALLOW.value})
        self._actions.add(deny_count, {"effect": AuthorizationEffectLabel.DENY.value})

    def record_rejection(self, *, category: AuditReason) -> None:
        self._rejections.add(1, {"category": _require_enum(category, AuditReason, "category")})

    def record_persistence(
        self,
        *,
        operation: PersistenceOperation,
        outcome: PersistenceOutcome,
        duration_ms: float,
    ) -> None:
        attributes = {
            "operation": _require_enum(operation, PersistenceOperation, "operation"),
            "outcome": _require_enum(outcome, PersistenceOutcome, "outcome"),
        }
        self._persistence_operations.add(1, attributes)
        self._persistence_duration.record(_require_finite(duration_ms, "duration_ms"), attributes)

    def record_dependency_failure(
        self,
        *,
        dependency: DependencyLabel,
        category: DependencyFailureCategory,
    ) -> None:
        self._dependencies.add(
            1,
            {
                "dependency": _require_enum(dependency, DependencyLabel, "dependency"),
                "category": _require_enum(category, DependencyFailureCategory, "category"),
            },
        )

    def record_export_failure(self, *, signal: TelemetrySignal) -> None:
        self._export_failures.add(1, {"signal": _require_enum(signal, TelemetrySignal, "signal")})

    def record_dropped_events(self, *, signal: TelemetrySignal) -> None:
        self._dropped.add(1, {"signal": _require_enum(signal, TelemetrySignal, "signal")})
