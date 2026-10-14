"""Audit event schema, redaction and strict serialization (O-U01, O-U03, O-U08, O-U09)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from mtmf_service.observability import (
    AuditEvent,
    AuditEventName,
    AuditEventSerializationError,
    AuditOutcome,
    InMemoryAuditEventSink,
    NoopAuditEventSink,
    OtelAuditEventSink,
)

_CORRELATION = "0123456789abcdef0123456789abcdef"
_TRACE = "0123456789abcdef0123456789abcdef"
_SPAN = "0123456789abcdef"


def _batch(**overrides: Any) -> AuditEvent:
    values: dict[str, Any] = {
        "name": AuditEventName.AUTHORIZATION_BATCH,
        "outcome": AuditOutcome.ALLOW,
        "timestamp": datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC),
        "request_correlation_id": _CORRELATION,
        "service_name": "mtmf-service",
        "service_version": "0.1.0",
        "environment": "development",
        "duration_ms": 1.5,
        "action_count": 2,
        "allow_count": 2,
        "deny_count": 0,
    }
    values.update(overrides)
    return AuditEvent(**values)


def test_o_u01_all_allow_batch_event_serializes() -> None:
    event = _batch()
    attributes = event.to_attributes()
    assert attributes["event.name"] == "mtmf.authorization.batch"
    assert attributes["event.schema_version"] == 1
    assert attributes["outcome"] == "ALLOW"
    assert attributes["allow_count"] == 2
    assert set(attributes) <= {
        "event.name",
        "event.schema_version",
        "timestamp",
        "request_correlation_id",
        "outcome",
        "reason_code",
        "duration_ms",
        "action_count",
        "allow_count",
        "deny_count",
        "trace_id",
        "span_id",
        "service.name",
        "service.version",
        "deployment.environment",
    }


@pytest.mark.parametrize(
    ("outcome", "allow_count", "deny_count"),
    [
        (AuditOutcome.DENY, 0, 2),
        (AuditOutcome.MIXED, 1, 1),
    ],
)
def test_o_u02_deny_and_mixed_outcomes(
    outcome: AuditOutcome, allow_count: int, deny_count: int
) -> None:
    event = _batch(outcome=outcome, allow_count=allow_count, deny_count=deny_count)
    assert event.to_attributes()["outcome"] == outcome.value


def test_o_u02_inconsistent_counts_fail_closed() -> None:
    with pytest.raises(AuditEventSerializationError):
        _batch(outcome=AuditOutcome.MIXED, allow_count=2, deny_count=0)
    with pytest.raises(AuditEventSerializationError):
        _batch(allow_count=1, deny_count=0, action_count=5)


def test_o_u03_duplicate_actions_counted_per_occurrence() -> None:
    event = _batch(action_count=3, allow_count=3, deny_count=0)
    assert event.to_attributes()["action_count"] == 3


def test_o_u08_from_mapping_rejects_forbidden_keys() -> None:
    with pytest.raises(AuditEventSerializationError):
        AuditEvent.from_mapping(
            {
                "event.name": "mtmf.authorization.batch",
                "outcome": "ALLOW",
                "timestamp": "2026-10-13T12:00:00+00:00",
                "request_correlation_id": _CORRELATION,
                "service.name": "mtmf-service",
                "service.version": "0.1.0",
                "deployment.environment": "development",
                "action_count": 1,
                "allow_count": 1,
                "deny_count": 0,
                "token": "secret",
            }
        )


def test_o_u08_from_mapping_rejects_unknown_keys() -> None:
    with pytest.raises(AuditEventSerializationError):
        AuditEvent.from_mapping(
            {
                "event.name": "mtmf.authorization.batch",
                "outcome": "ALLOW",
                "timestamp": "2026-10-13T12:00:00+00:00",
                "request_correlation_id": _CORRELATION,
                "service.name": "mtmf-service",
                "service.version": "0.1.0",
                "deployment.environment": "development",
                "action_count": 1,
                "allow_count": 1,
                "deny_count": 0,
                "resource": "urn:secret",
            }
        )


def test_o_u08_from_mapping_roundtrip_preserves_allowlist() -> None:
    event = _batch(trace_id=_TRACE, span_id=_SPAN)
    rebuilt = AuditEvent.from_mapping(event.to_attributes())
    assert rebuilt == event


def test_o_u09_malformed_fields_fail_closed() -> None:
    with pytest.raises(AuditEventSerializationError):
        _batch(request_correlation_id="bad id!")
    with pytest.raises(AuditEventSerializationError):
        _batch(duration_ms=float("nan"))
    with pytest.raises(AuditEventSerializationError):
        _batch(duration_ms=-1.0)
    with pytest.raises(AuditEventSerializationError):
        _batch(trace_id="nothex")
    with pytest.raises(AuditEventSerializationError):
        _batch(timestamp=datetime(2026, 10, 13, 12, 0, 0))
    with pytest.raises(AuditEventSerializationError):
        _batch(service_name="has space")


def test_o_u09_non_batch_event_shape() -> None:
    with pytest.raises(AuditEventSerializationError):
        AuditEvent(
            name=AuditEventName.AUTHENTICATION_REJECTED,
            outcome=AuditOutcome.REJECTED,
            timestamp=datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC),
            request_correlation_id=_CORRELATION,
            service_name="mtmf-service",
            service_version="0.1.0",
            environment="development",
            action_count=1,
        )
    with pytest.raises(AuditEventSerializationError):
        AuditEvent(
            name=AuditEventName.AUTHENTICATION_REJECTED,
            outcome=AuditOutcome.REJECTED,
            timestamp=datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC),
            request_correlation_id=_CORRELATION,
            service_name="mtmf-service",
            service_version="0.1.0",
            environment="development",
        )


def test_in_memory_and_noop_sinks() -> None:
    sink = InMemoryAuditEventSink()
    event = _batch()
    sink.emit(event)
    assert sink.events == (event,)
    sink.clear()
    assert sink.events == ()
    NoopAuditEventSink().emit(event)


def test_otel_sink_emits_one_record() -> None:
    class _Logger:
        def __init__(self) -> None:
            self.records: list[object] = []

        def emit(self, record: object) -> None:
            self.records.append(record)

    from opentelemetry.sdk.resources import Resource

    logger = _Logger()
    resource = Resource.create({"service.name": "mtmf-service"})
    OtelAuditEventSink(logger, resource).emit(_batch(trace_id=_TRACE, span_id=_SPAN))
    assert len(logger.records) == 1
    record = logger.records[0]
    assert record.body == "mtmf.authorization.batch"
    assert record.attributes["outcome"] == "ALLOW"
    # The provider resource must travel with the record so Loki sees the
    # real service.name rather than ``unknown_service``.
    assert record.resource.attributes["service.name"] == "mtmf-service"
