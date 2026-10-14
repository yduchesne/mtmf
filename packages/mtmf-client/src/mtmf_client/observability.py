"""Optional, independently configured client-side telemetry.

``mtmf-client`` imports and operates with **no** OpenTelemetry package
installed. Instrumentation is injected by the consumer through the
:class:`ClientInstrumentation` protocol; the default is a no-op. The
bundled :class:`OtelClientInstrumentation` adapter accepts an already-built
OTel tracer/meter supplied by the consuming process, so this package never
installs a global provider, never creates an exporter and never opens a
network connection on its own. No token, token-endpoint payload, request
DTO body or response body is ever recorded.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager, nullcontext
from enum import StrEnum
from typing import Protocol, runtime_checkable

__all__ = [
    "ClientInstrumentation",
    "ClientStatusClass",
    "NoopClientInstrumentation",
    "OtelClientInstrumentation",
    "SnapshotRejectionReason",
    "TokenFailureCategory",
]


class ClientStatusClass(StrEnum):
    """The closed set of client-observed HTTP status classes."""

    SUCCESS = "2xx"
    REDIRECT = "3xx"
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"
    UNKNOWN = "unknown"


class TokenFailureCategory(StrEnum):
    """The closed set of token-acquisition failure categories."""

    TRANSPORT = "transport"
    PROTOCOL = "protocol"
    REJECTED = "rejected"
    UNAVAILABLE = "unavailable"


class SnapshotRejectionReason(StrEnum):
    """The closed set of local snapshot rejection reasons.

    These are *client-side* PEP checks only and are never a server PDP
    decision; the metric name keeps that distinction explicit.
    """

    NOT_OWNED = "not_owned"
    CONTEXT_MISMATCH = "context_mismatch"
    EXPIRED = "expired"
    NO_MATCH = "no_match"
    DENIED = "denied"


@runtime_checkable
class ClientInstrumentation(Protocol):
    """A consumer-supplied, fail-open-free client telemetry seam.

    Implementations must never raise into the client path; the client
    wraps every call defensively. A telemetry fault must never change a
    fail-closed client result.
    """

    def span_evaluate(self) -> AbstractContextManager[object]:
        """Return a context manager for one ``evaluate`` call."""
        ...

    def span_token_acquire(self) -> AbstractContextManager[object]:
        """Return a context manager for one service-token acquisition."""
        ...

    def record_http_response(self, *, status_class: ClientStatusClass) -> None:
        """Record one outbound HTTP response status class."""
        ...

    def record_token_failure(self, *, category: TokenFailureCategory) -> None:
        """Record one classified token-acquisition failure."""
        ...

    def record_snapshot_rejection(self, *, reason: SnapshotRejectionReason) -> None:
        """Record one local snapshot rejection."""
        ...


class NoopClientInstrumentation:
    """The default client instrumentation: no export, no side effects."""

    __slots__ = ()

    def span_evaluate(self) -> AbstractContextManager[object]:
        """Return a no-op context manager."""
        return nullcontext()

    def span_token_acquire(self) -> AbstractContextManager[object]:
        """Return a no-op context manager."""
        return nullcontext()

    def record_http_response(self, *, status_class: ClientStatusClass) -> None:
        """Discard the observation."""
        del status_class

    def record_token_failure(self, *, category: TokenFailureCategory) -> None:
        """Discard the observation."""
        del category

    def record_snapshot_rejection(self, *, reason: SnapshotRejectionReason) -> None:
        """Discard the observation."""
        del reason


@runtime_checkable
class _SpanStarter(Protocol):
    def start_as_current_span(self, name: str) -> AbstractContextManager[object]: ...


@runtime_checkable
class _CounterInstrument(Protocol):
    def add(self, amount: int, attributes: Mapping[str, str]) -> None: ...


@runtime_checkable
class _MeterFactory(Protocol):
    def create_counter(
        self, name: str, unit: str = "", description: str = ""
    ) -> _CounterInstrument: ...


class OtelClientInstrumentation:
    """A client instrumentation adapter over consumer-owned OTel objects.

    :param tracer: An OTel ``Tracer`` owned by the consuming process.
    :param meter: An OTel ``Meter`` owned by the consuming process.
    """

    __slots__ = ("_http", "_meter", "_snapshots", "_tokens", "_tracer")

    def __init__(self, *, tracer: _SpanStarter, meter: _MeterFactory) -> None:
        self._tracer = tracer
        self._http = meter.create_counter(
            "mtmf.client.http.responses",
            unit="{response}",
            description="Outbound client HTTP responses",
        )
        self._tokens = meter.create_counter(
            "mtmf.client.tokens",
            unit="{acquisition}",
            description="Service-token acquisitions",
        )
        self._snapshots = meter.create_counter(
            "mtmf.client.snapshot.rejections",
            unit="{check}",
            description="Local snapshot PEP rejections (not server decisions)",
        )

    def span_evaluate(self) -> AbstractContextManager[object]:
        """Start a bounded ``mtmf.client.evaluate`` span."""
        return self._tracer.start_as_current_span("mtmf.client.evaluate")

    def span_token_acquire(self) -> AbstractContextManager[object]:
        """Start a bounded ``mtmf.client.token_acquire`` span."""
        return self._tracer.start_as_current_span("mtmf.client.token_acquire")

    def record_http_response(self, *, status_class: ClientStatusClass) -> None:
        """Record the outbound HTTP response status class."""
        self._http.add(1, {"status_class": status_class.value})

    def record_token_failure(self, *, category: TokenFailureCategory) -> None:
        """Record a token-acquisition failure category."""
        self._tokens.add(1, {"outcome": "failure", "category": category.value})

    def record_snapshot_rejection(self, *, reason: SnapshotRejectionReason) -> None:
        """Record a local snapshot rejection reason."""
        self._snapshots.add(1, {"reason": reason.value})
