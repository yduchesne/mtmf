"""Telemetry runtime construction, disabled mode and strict configuration (O-U12, O-U15)."""

from __future__ import annotations

import pytest

from mtmf_service.observability import build_telemetry
from mtmf_service.observability.runtime import Telemetry
from mtmf_service.settings import ServiceConfigurationError, ServiceSettings


def test_disabled_by_default_builds_no_exporter() -> None:
    telemetry = build_telemetry(ServiceSettings())
    assert telemetry.enabled is False
    assert telemetry.current_trace_ids() == (None, None)
    telemetry.shutdown()


def test_enabled_requires_endpoint() -> None:
    with pytest.raises(ServiceConfigurationError):
        ServiceSettings(otel_enabled=True)


def test_endpoint_without_enabled_is_rejected() -> None:
    with pytest.raises(ServiceConfigurationError):
        ServiceSettings(otel_exporter_otlp_endpoint="http://127.0.0.1:24317")


@pytest.mark.parametrize(
    "overrides",
    [
        {"otel_queue_size": 0},
        {"otel_queue_size": 70000},
        {"otel_batch_size": 0},
        {"otel_batch_size": 4096, "otel_queue_size": 2048},
        {"otel_schedule_delay_ms": 10},
        {"otel_export_timeout_ms": 10},
        {"otel_metric_export_interval_ms": 10},
        {"otel_shutdown_timeout_seconds": 0.1},
    ],
)
def test_unbounded_otel_settings_are_rejected(overrides: dict[str, int | float]) -> None:
    with pytest.raises(ServiceConfigurationError):
        ServiceSettings(
            otel_enabled=True, otel_exporter_otlp_endpoint="http://127.0.0.1:24317", **overrides
        )


def test_enabled_builds_instance_scoped_runtime_and_shuts_down() -> None:
    from opentelemetry import trace

    before = trace.get_tracer_provider()
    telemetry = build_telemetry(
        ServiceSettings(
            otel_enabled=True,
            otel_exporter_otlp_endpoint="http://127.0.0.1:24317",
        )
    )
    assert telemetry.enabled is True
    # A fresh, valid span must be available without touching the global provider.
    with telemetry.span(_span_name()):
        trace_id, span_id = telemetry.current_trace_ids()
    assert trace_id is not None and span_id is not None
    assert trace.get_tracer_provider() is before
    telemetry.shutdown()


def _span_name():  # type: ignore[no-untyped-def]
    from mtmf_service.observability.spans import SpanName

    return SpanName.HTTP_EVALUATE


def test_from_env_reads_otel_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MTMF_OTEL_ENABLED", "true")
    monkeypatch.setenv("MTMF_OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:24317")
    monkeypatch.setenv("MTMF_OTEL_SERVICE_NAME", "mtmf-service")
    monkeypatch.setenv("MTMF_OTEL_ENVIRONMENT", "test")
    settings = ServiceSettings.from_env()
    assert settings.otel_enabled is True
    assert settings.otel_exporter_otlp_endpoint == "http://127.0.0.1:24317"
    assert settings.otel_environment == "test"


def test_disabled_runtime_records_events_without_trace_context() -> None:
    telemetry = Telemetry.disabled()
    with telemetry.span(_span_name()):
        assert telemetry.current_trace_ids() == (None, None)
