"""Service observability: structured audit events, metrics and spans.

The package is deliberately separated from the authorization domain. It
never imports a policy, evaluator or token object, and it owns no
authorization semantics. The public entry point is :func:`build_telemetry`,
which returns either a fully disabled no-op runtime or an instance-scoped
OTel runtime with bounded, asynchronous export.
"""

from __future__ import annotations

from mtmf_service.observability.classification import (
    AuditClassification,
    classify_failure,
)
from mtmf_service.observability.events import (
    AuditEvent,
    AuditEventName,
    AuditEventSerializationError,
    AuditEventSink,
    AuditOutcome,
    AuditReason,
    InMemoryAuditEventSink,
    NoopAuditEventSink,
    OtelAuditEventSink,
)
from mtmf_service.observability.metrics import (
    BatchOutcomeLabel,
    DependencyFailureCategory,
    DependencyLabel,
    HttpMethod,
    HttpRoute,
    HttpStatusClass,
    InMemoryMetricsRecorder,
    InvalidTelemetryAttributeError,
    MetricsRecorder,
    NoopMetricsRecorder,
    OtelMetricsRecorder,
    PersistenceOperation,
    PersistenceOutcome,
    TelemetrySignal,
)
from mtmf_service.observability.persistence import MetricsPersistenceTelemetry
from mtmf_service.observability.runtime import Telemetry, build_telemetry

__all__ = [
    "AuditClassification",
    "AuditEvent",
    "AuditEventName",
    "AuditEventSerializationError",
    "AuditEventSink",
    "AuditOutcome",
    "AuditReason",
    "BatchOutcomeLabel",
    "DependencyFailureCategory",
    "DependencyLabel",
    "HttpMethod",
    "HttpRoute",
    "HttpStatusClass",
    "InMemoryAuditEventSink",
    "InMemoryMetricsRecorder",
    "InvalidTelemetryAttributeError",
    "MetricsPersistenceTelemetry",
    "MetricsRecorder",
    "NoopAuditEventSink",
    "NoopMetricsRecorder",
    "OtelAuditEventSink",
    "OtelMetricsRecorder",
    "PersistenceOperation",
    "PersistenceOutcome",
    "Telemetry",
    "TelemetrySignal",
    "build_telemetry",
    "classify_failure",
]
