"""Low-cardinality metric validation and the fail-safe telemetry façade (O-U10, O-U13, O-U14)."""

from __future__ import annotations

import threading

import pytest

from mtmf_service.observability import (
    AuditEventName,
    AuditOutcome,
    AuditReason,
    InMemoryMetricsRecorder,
    InvalidTelemetryAttributeError,
    NoopAuditEventSink,
    NoopMetricsRecorder,
    Telemetry,
)
from mtmf_service.observability.metrics import (
    BatchOutcomeLabel,
    DependencyFailureCategory,
    DependencyLabel,
    HttpMethod,
    HttpRoute,
    HttpStatusClass,
    PersistenceOperation,
    PersistenceOutcome,
)


def test_in_memory_recorder_accepts_bounded_labels() -> None:
    recorder = InMemoryMetricsRecorder()
    recorder.record_http_request(
        route=HttpRoute.EVALUATE,
        method=HttpMethod.POST,
        status_class=HttpStatusClass.SUCCESS,
        duration_ms=3.0,
    )
    recorder.record_batch(
        outcome=BatchOutcomeLabel.MIXED,
        duration_ms=5.0,
        action_count=2,
        allow_count=1,
        deny_count=1,
    )
    recorder.record_rejection(category=AuditReason.RATE_LIMITED)
    recorder.record_persistence(
        operation=PersistenceOperation.TRANSACTION,
        outcome=PersistenceOutcome.SUCCESS,
        duration_ms=1.0,
    )
    recorder.record_dependency_failure(
        dependency=DependencyLabel.POSTGRES,
        category=DependencyFailureCategory.UNAVAILABLE,
    )
    names = [name for name, _attributes, _value in recorder.counters]
    assert "mtmf.http.requests" in names
    assert "mtmf.authorization.batches" in names
    assert "mtmf.security.rejections" in names


def test_o_u10_high_cardinality_attribute_rejected() -> None:
    recorder = InMemoryMetricsRecorder()
    with pytest.raises(InvalidTelemetryAttributeError):
        recorder.record_http_request(
            route="urn:mtmf:tenant:secret",  # type: ignore[arg-type]
            method=HttpMethod.POST,
            status_class=HttpStatusClass.SUCCESS,
            duration_ms=1.0,
        )
    with pytest.raises(InvalidTelemetryAttributeError):
        recorder.record_rejection(category="tenant-123")  # type: ignore[arg-type]
    assert recorder.counters == ()


def test_o_u10_invalid_duration_and_counts_rejected() -> None:
    recorder = InMemoryMetricsRecorder()
    with pytest.raises(InvalidTelemetryAttributeError):
        recorder.record_http_request(
            route=HttpRoute.EVALUATE,
            method=HttpMethod.POST,
            status_class=HttpStatusClass.SUCCESS,
            duration_ms=float("inf"),
        )
    with pytest.raises(InvalidTelemetryAttributeError):
        recorder.record_batch(
            outcome=BatchOutcomeLabel.ALLOW,
            duration_ms=1.0,
            action_count=2,
            allow_count=1,
            deny_count=0,
        )


class _RaisingMetrics:
    """A recorder that fails every call, to prove boundary containment."""

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        def _raise(*args: object, **kwargs: object) -> None:
            raise RuntimeError("metrics backend exploded")

        return _raise


def test_o_u13_metrics_failure_is_contained() -> None:
    telemetry = Telemetry(
        enabled=True,
        sink=_RecordingSink(),
        metrics=_RaisingMetrics(),  # type: ignore[arg-type]
    )
    telemetry.record_batch_metrics(
        outcome=BatchOutcomeLabel.ALLOW,
        duration_ms=1.0,
        action_count=1,
        allow_count=1,
        deny_count=0,
    )
    assert telemetry.failure_count >= 1
    telemetry.record_http_request(
        route=HttpRoute.EVALUATE,
        method=HttpMethod.POST,
        status_class=HttpStatusClass.SUCCESS,
        duration_ms=1.0,
    )
    assert telemetry.failure_count >= 2


class _RecordingSink:
    def __init__(self) -> None:
        self.events: list[object] = []

    def emit(self, event: object) -> None:
        self.events.append(event)


class _RaisingSink:
    def emit(self, event: object) -> None:
        raise RuntimeError("sink exploded")


def test_o_u13_sink_failure_is_contained() -> None:
    telemetry = Telemetry(enabled=True, sink=_RaisingSink(), metrics=NoopMetricsRecorder())
    telemetry.record_batch_event(
        correlation_id="abc123",
        outcome=AuditOutcome.ALLOW,
        duration_ms=1.0,
        action_count=1,
        allow_count=1,
        deny_count=0,
    )
    assert telemetry.failure_count >= 1


def test_o_u03_batch_event_is_single_terminal_event() -> None:
    sink = _RecordingSink()
    telemetry = Telemetry(enabled=True, sink=sink, metrics=NoopMetricsRecorder())
    telemetry.record_batch_event(
        correlation_id="abc123",
        outcome=AuditOutcome.MIXED,
        duration_ms=2.0,
        action_count=2,
        allow_count=1,
        deny_count=1,
    )
    assert len(sink.events) == 1


def test_o_u14_shutdown_hook_failure_is_contained() -> None:
    def _boom() -> None:
        raise RuntimeError("shutdown exploded")

    telemetry = Telemetry(
        enabled=True,
        sink=NoopAuditEventSink(),
        metrics=NoopMetricsRecorder(),
        shutdown_hook=_boom,
    )
    telemetry.shutdown()
    assert telemetry.failure_count >= 1


def test_o_u15_repeated_construction_has_no_global_side_effects() -> None:
    from opentelemetry import trace

    before = trace.get_tracer_provider()
    first = Telemetry.disabled()
    second = Telemetry.disabled()
    assert first.enabled is False
    assert second.enabled is False
    assert trace.get_tracer_provider() is before


def test_disabled_telemetry_is_a_noop() -> None:
    telemetry = Telemetry.disabled()
    assert telemetry.enabled is False
    assert telemetry.current_trace_ids() == (None, None)
    telemetry.record_rejection_event(
        name=AuditEventName.AUTHENTICATION_REJECTED,
        reason_code=AuditReason.INVALID_REQUEST,
        correlation_id="abc123",
    )
    telemetry.shutdown()


def test_threaded_telemetry_emission_is_bounded() -> None:
    sink = _RecordingSink()
    telemetry = Telemetry(enabled=True, sink=sink, metrics=NoopMetricsRecorder())
    errors: list[BaseException] = []

    def _worker() -> None:
        try:
            for _ in range(50):
                telemetry.record_rejection_event(
                    name=AuditEventName.REQUEST_REJECTED,
                    reason_code=AuditReason.INVALID_REQUEST,
                    correlation_id="abc123",
                )
        except BaseException as exc:  # pragma: no cover - defensive
            errors.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(sink.events) == 200
