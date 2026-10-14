"""Telemetry runtime: provider construction, bounded export and shutdown.

The runtime owns *instance-scoped* OTel ``TracerProvider``/
``MeterProvider``/``LoggerProvider`` objects. It never installs or replaces
a process-global provider, so constructing the application factory more
than once (as tests do) cannot duplicate handlers or spans. When telemetry
is disabled every adapter is a no-op and no exporter or background thread
is created.

All public emission methods are exception-contained: a telemetry fault
increments a bounded internal failure counter and never propagates into
the authorization path.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from opentelemetry.trace import SpanKind

from mtmf_service.observability.events import (
    AuditEvent,
    AuditEventName,
    AuditEventSink,
    AuditOutcome,
    AuditReason,
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
    MetricsRecorder,
    NoopMetricsRecorder,
    OtelMetricsRecorder,
    PersistenceOperation,
    PersistenceOutcome,
    TelemetrySignal,
)
from mtmf_service.observability.spans import (
    SanitizedSpanAttributes,
    SpanName,
    span_context,
)

if TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from opentelemetry.trace import Span, Tracer

    from mtmf_service.settings import ServiceSettings

__all__ = ["Telemetry", "build_telemetry"]

#: Bounded gRPC reconnect backoff for the OTLP exporters. The gRPC default
#: maximum backoff is minutes, which makes recovery after a Collector restart
#: non-deterministic. Bounding it keeps recovery time bounded and observable
#: while leaving the asynchronous, best-effort delivery contract unchanged.
_GRPC_CHANNEL_OPTIONS: tuple[tuple[str, str], ...] = (
    ("grpc.initial_reconnect_backoff_ms", "500"),
    ("grpc.max_reconnect_backoff_ms", "5000"),
)


class Telemetry:
    """An instance-scoped, fail-safe telemetry façade.

    Construction is intentionally low-level so unit tests can supply
    in-memory sinks/recorders without any exporter or network traffic.
    """

    __slots__ = (
        "_enabled",
        "_environment",
        "_failure_count",
        "_metrics",
        "_service_name",
        "_service_version",
        "_shutdown_done",
        "_shutdown_hook",
        "_sink",
        "_tracer",
    )

    def __init__(
        self,
        *,
        enabled: bool,
        sink: AuditEventSink,
        metrics: MetricsRecorder,
        tracer: Tracer | None = None,
        service_name: str = "mtmf-service",
        service_version: str = "0.1.0",
        environment: str = "development",
        shutdown_hook: Callable[[], None] | None = None,
    ) -> None:
        self._enabled = enabled
        self._sink = sink
        self._metrics = metrics
        self._tracer = tracer
        self._service_name = service_name
        self._service_version = service_version
        self._environment = environment
        self._shutdown_hook = shutdown_hook
        self._failure_count = 0
        self._shutdown_done = False

    @classmethod
    def disabled(
        cls, *, service_name: str = "mtmf-service", service_version: str = "0.1.0"
    ) -> Telemetry:
        """Return a fully disabled telemetry façade with no side effects."""
        return cls(
            enabled=False,
            sink=NoopAuditEventSink(),
            metrics=NoopMetricsRecorder(),
            tracer=None,
            service_name=service_name,
            service_version=service_version,
        )

    @property
    def enabled(self) -> bool:
        """Whether OTel export is active."""
        return self._enabled

    @property
    def failure_count(self) -> int:
        """A bounded count of contained telemetry faults (diagnostics only)."""
        return self._failure_count

    # -- correlation -------------------------------------------------------

    @staticmethod
    def new_correlation_id() -> str:
        """Return a fresh server-owned opaque correlation id."""
        return uuid.uuid4().hex

    def current_trace_ids(self) -> tuple[str | None, str | None]:
        """Return the valid current OTel ``(trace_id, span_id)`` hex pair.

        Returns ``(None, None)`` when there is no active, valid span. This
        never fabricates a W3C identifier.
        """
        if self._tracer is None:
            return (None, None)
        try:
            from opentelemetry.trace import get_current_span

            context = get_current_span().get_span_context()
        except Exception:
            self._note_failure()
            return (None, None)
        if not context.is_valid:
            return (None, None)
        return (format(context.trace_id, "032x"), format(context.span_id, "016x"))

    # -- spans -------------------------------------------------------------

    def span(
        self,
        name: SpanName,
        *,
        kind: SpanKind = SpanKind.INTERNAL,
        attributes: SanitizedSpanAttributes | None = None,
    ) -> AbstractContextManager[Span]:
        """Return a context manager for the bounded span ``name``."""
        return span_context(self._tracer, name, kind=kind, attributes=attributes)

    # -- events ------------------------------------------------------------

    def record_batch_event(
        self,
        *,
        correlation_id: str,
        outcome: AuditOutcome,
        duration_ms: float,
        action_count: int,
        allow_count: int,
        deny_count: int,
    ) -> None:
        """Emit exactly one terminal batch-decision audit event."""
        self._guard(
            lambda: self._emit_batch(
                correlation_id=correlation_id,
                outcome=outcome,
                duration_ms=duration_ms,
                action_count=action_count,
                allow_count=allow_count,
                deny_count=deny_count,
            )
        )

    def record_rejection_event(
        self,
        *,
        name: AuditEventName,
        reason_code: AuditReason,
        correlation_id: str,
        duration_ms: float | None = None,
    ) -> None:
        """Emit exactly one terminal rejection audit event."""
        self._guard(
            lambda: self._emit_terminal(
                name=name,
                outcome=AuditOutcome.REJECTED,
                reason_code=reason_code,
                correlation_id=correlation_id,
                duration_ms=duration_ms,
            )
        )

    def record_error_event(
        self,
        *,
        reason_code: AuditReason,
        correlation_id: str,
        duration_ms: float | None = None,
    ) -> None:
        """Emit exactly one terminal whole-request error audit event."""
        self._guard(
            lambda: self._emit_terminal(
                name=AuditEventName.AUTHORIZATION_ERROR,
                outcome=AuditOutcome.ERROR,
                reason_code=reason_code,
                correlation_id=correlation_id,
                duration_ms=duration_ms,
            )
        )

    def record_management_event(
        self,
        *,
        outcome: AuditOutcome,
        correlation_id: str,
        duration_ms: float,
    ) -> None:
        """Emit exactly one terminal management-mutation audit event."""
        self._guard(
            lambda: self._emit_management(
                outcome=outcome,
                correlation_id=correlation_id,
                duration_ms=duration_ms,
            )
        )

    def _emit_batch(
        self,
        *,
        correlation_id: str,
        outcome: AuditOutcome,
        duration_ms: float,
        action_count: int,
        allow_count: int,
        deny_count: int,
    ) -> None:
        trace_id, span_id = self.current_trace_ids()
        event = AuditEvent(
            name=AuditEventName.AUTHORIZATION_BATCH,
            outcome=outcome,
            timestamp=datetime.now(UTC),
            request_correlation_id=correlation_id,
            service_name=self._service_name,
            service_version=self._service_version,
            environment=self._environment,
            duration_ms=duration_ms,
            action_count=action_count,
            allow_count=allow_count,
            deny_count=deny_count,
            trace_id=trace_id,
            span_id=span_id,
        )
        self._sink.emit(event)

    def _emit_terminal(
        self,
        *,
        name: AuditEventName,
        outcome: AuditOutcome,
        reason_code: AuditReason,
        correlation_id: str,
        duration_ms: float | None,
    ) -> None:
        trace_id, span_id = self.current_trace_ids()
        event = AuditEvent(
            name=name,
            outcome=outcome,
            timestamp=datetime.now(UTC),
            request_correlation_id=correlation_id,
            service_name=self._service_name,
            service_version=self._service_version,
            environment=self._environment,
            reason_code=reason_code,
            duration_ms=duration_ms,
            trace_id=trace_id,
            span_id=span_id,
        )
        self._sink.emit(event)

    def _emit_management(
        self,
        *,
        outcome: AuditOutcome,
        correlation_id: str,
        duration_ms: float,
    ) -> None:
        trace_id, span_id = self.current_trace_ids()
        event = AuditEvent(
            name=AuditEventName.MANAGEMENT_MUTATION,
            outcome=outcome,
            timestamp=datetime.now(UTC),
            request_correlation_id=correlation_id,
            service_name=self._service_name,
            service_version=self._service_version,
            environment=self._environment,
            duration_ms=duration_ms,
            trace_id=trace_id,
            span_id=span_id,
        )
        self._sink.emit(event)

    # -- metrics -----------------------------------------------------------

    def record_http_request(
        self,
        *,
        route: HttpRoute,
        method: HttpMethod,
        status_class: HttpStatusClass,
        duration_ms: float,
    ) -> None:
        """Record one completed HTTP request."""
        self._guard(
            lambda: self._metrics.record_http_request(
                route=route,
                method=method,
                status_class=status_class,
                duration_ms=duration_ms,
            )
        )

    def record_batch_metrics(
        self,
        *,
        outcome: BatchOutcomeLabel,
        duration_ms: float,
        action_count: int,
        allow_count: int,
        deny_count: int,
    ) -> None:
        """Record the validated batch counters and distributions."""
        self._guard(
            lambda: self._metrics.record_batch(
                outcome=outcome,
                duration_ms=duration_ms,
                action_count=action_count,
                allow_count=allow_count,
                deny_count=deny_count,
            )
        )

    def record_rejection_metric(self, *, category: AuditReason) -> None:
        """Record one rejected request metric."""
        self._guard(lambda: self._metrics.record_rejection(category=category))

    def record_persistence_metric(
        self,
        *,
        operation: PersistenceOperation,
        outcome: PersistenceOutcome,
        duration_ms: float,
    ) -> None:
        """Record one persistence operation observation."""
        self._guard(
            lambda: self._metrics.record_persistence(
                operation=operation, outcome=outcome, duration_ms=duration_ms
            )
        )

    def record_dependency_failure(
        self,
        *,
        dependency: DependencyLabel,
        category: DependencyFailureCategory,
    ) -> None:
        """Record one classified dependency failure."""
        self._guard(
            lambda: self._metrics.record_dependency_failure(
                dependency=dependency, category=category
            )
        )

    # -- lifecycle ---------------------------------------------------------

    def shutdown(self) -> None:
        """Flush and shut down exporters within the configured deadline.

        Idempotent: an ASGI shutdown hook and an explicit owner shutdown can
        both request termination without double-shutting the SDK providers.
        """
        if self._shutdown_done:
            return
        self._shutdown_done = True
        if self._shutdown_hook is not None:
            self._guard(self._shutdown_hook)

    # -- internal ----------------------------------------------------------

    def _guard(self, call: Callable[[], None]) -> None:
        """Run ``call`` and contain any telemetry fault."""
        try:
            call()
        except Exception:
            self._note_failure()

    def _note_failure(self) -> None:
        self._failure_count += 1
        try:
            self._metrics.record_export_failure(signal=TelemetrySignal.LOGS)
        except Exception:
            # Never recurse or raise from failure accounting.
            return


def build_telemetry(settings: ServiceSettings) -> Telemetry:
    """Build the telemetry runtime for ``settings``.

    Disabled settings return a no-op façade with no exporter, thread or
    network activity. Enabled settings construct instance-scoped providers
    with bounded queues, batch sizes and export timeouts.

    :raises ServiceConfigurationError: when OTel is enabled without a
        valid endpoint (validated earlier by :class:`ServiceSettings`).
    """
    from mtmf_service.settings import ServiceSettings as _ServiceSettings

    if not isinstance(settings, _ServiceSettings):  # pragma: no cover - defensive
        raise TypeError("build_telemetry requires ServiceSettings")
    if not settings.otel_enabled:
        return Telemetry.disabled(
            service_name=settings.otel_service_name,
        )

    from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    endpoint = settings.otel_exporter_otlp_endpoint or ""
    insecure = endpoint.startswith("http://")
    resource = Resource.create(
        {
            "service.name": settings.otel_service_name,
            "service.version": "0.1.0",
            "deployment.environment": settings.otel_environment,
        }
    )

    tracer_provider = TracerProvider(resource=resource, shutdown_on_exit=False)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(
            OTLPSpanExporter(
                endpoint=endpoint, insecure=insecure, channel_options=_GRPC_CHANNEL_OPTIONS
            ),
            max_queue_size=settings.otel_queue_size,
            schedule_delay_millis=settings.otel_schedule_delay_ms,
            max_export_batch_size=settings.otel_batch_size,
            export_timeout_millis=settings.otel_export_timeout_ms,
        )
    )
    meter_provider = MeterProvider(
        resource=resource,
        shutdown_on_exit=False,
        metric_readers=[
            PeriodicExportingMetricReader(
                OTLPMetricExporter(
                    endpoint=endpoint, insecure=insecure, channel_options=_GRPC_CHANNEL_OPTIONS
                ),
                export_interval_millis=settings.otel_metric_export_interval_ms,
                export_timeout_millis=settings.otel_export_timeout_ms,
            )
        ],
    )
    logger_provider = LoggerProvider(resource=resource, shutdown_on_exit=False)
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(
            OTLPLogExporter(
                endpoint=endpoint, insecure=insecure, channel_options=_GRPC_CHANNEL_OPTIONS
            ),
            max_queue_size=settings.otel_queue_size,
            schedule_delay_millis=settings.otel_schedule_delay_ms,
            max_export_batch_size=settings.otel_batch_size,
            export_timeout_millis=settings.otel_export_timeout_ms,
        )
    )

    tracer = tracer_provider.get_tracer("mtmf-service")
    meter = meter_provider.get_meter("mtmf-service")
    logger = logger_provider.get_logger("mtmf-service")

    def _shutdown() -> None:
        _shutdown_with_deadline(
            (tracer_provider, meter_provider, logger_provider),
            deadline_seconds=settings.otel_shutdown_timeout_seconds,
        )

    return Telemetry(
        enabled=True,
        sink=OtelAuditEventSink(logger, resource),
        metrics=OtelMetricsRecorder(meter),
        tracer=tracer,
        service_name=settings.otel_service_name,
        service_version="0.1.0",
        environment=settings.otel_environment,
        shutdown_hook=_shutdown,
    )


def _shutdown_with_deadline(
    providers: tuple[object, ...],
    *,
    deadline_seconds: float,
) -> None:
    """Shut down ``providers`` within ``deadline_seconds``.

    Exporters are flushed on a background thread; if the deadline expires
    the process is not blocked further. In-flight events that cannot be
    flushed are dropped by design and must be accounted for by the
    Collector's self-observability, not fabricated as delivered.
    """
    done = threading.Event()

    def _run() -> None:
        for provider in providers:
            shutdown = getattr(provider, "shutdown", None)
            if callable(shutdown):
                try:
                    shutdown()
                except Exception:
                    continue
        done.set()

    thread = threading.Thread(target=_run, name="mtmf-otel-shutdown", daemon=True)
    thread.start()
    done.wait(timeout=max(0.1, deadline_seconds))
