"""Core persistence telemetry seam and the service metrics adapter."""

from __future__ import annotations

from mtmf_core.persistence.instrumentation import NoopPersistenceTelemetry
from mtmf_core.persistence.postgres.unit_of_work import _classify_operation
from mtmf_service.observability import (
    InMemoryMetricsRecorder,
    MetricsPersistenceTelemetry,
    Telemetry,
)


def test_classify_operation_distinguishes_read_and_write() -> None:
    assert _classify_operation("SELECT mtmf.tenant_get(%s)") == "read"
    assert _classify_operation("SELECT * FROM mtmf.role_get(%s)") == "read"
    assert _classify_operation("SELECT mtmf.identity_role_assignment_add(%s, %s)") == "write"
    assert _classify_operation("SELECT mtmf.role_save(%s)") == "write"
    assert _classify_operation("SELECT mtmf.service_credential_application_revoke(%s)") == "write"
    assert _classify_operation("SELECT mtmf.recover_root_identity(%s)") == "write"


def test_noop_persistence_telemetry_discards() -> None:
    NoopPersistenceTelemetry().record_operation(
        operation="write", outcome="success", duration_ms=1.0
    )


def test_metrics_adapter_records_bounded_values() -> None:
    metrics = InMemoryMetricsRecorder()
    telemetry = Telemetry(enabled=True, sink=_Sink(), metrics=metrics)
    adapter = MetricsPersistenceTelemetry(telemetry)
    adapter.record_operation(operation="write", outcome="success", duration_ms=2.0)
    names = [name for name, _attrs, _value in metrics.counters]
    assert names == ["mtmf.persistence.operations"]
    assert metrics.counters[0][1] == {"operation": "write", "outcome": "success"}


def test_metrics_adapter_ignores_unknown_values() -> None:
    metrics = InMemoryMetricsRecorder()
    telemetry = Telemetry(enabled=True, sink=_Sink(), metrics=metrics)
    adapter = MetricsPersistenceTelemetry(telemetry)
    adapter.record_operation(operation="tenant-secret", outcome="success", duration_ms=1.0)
    adapter.record_operation(operation="read", outcome="banana", duration_ms=1.0)
    assert metrics.counters == ()


class _Sink:
    def emit(self, event: object) -> None:
        del event
