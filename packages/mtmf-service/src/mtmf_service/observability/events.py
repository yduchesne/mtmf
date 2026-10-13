"""Structured, privacy-preserving audit event taxonomy and serialization.

This module owns the internal audit-event contract for ``mtmf-service``.
Events are *not* ``mtmf-api`` DTOs and are never exposed over HTTP. They
are built by **allowlist construction**: only the fields declared here can
ever be emitted, and construction from an untrusted mapping rejects unknown
keys instead of copying them through. No token, policy body, request/response
body, resource identifier, PII or raw exception text can be represented.

The schema version is ``1``. An incompatible change increments it; a
reader must not guess across versions.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

if TYPE_CHECKING:
    from opentelemetry.sdk._logs import Logger

__all__ = [
    "ATTRIBUTE_ALLOWLIST",
    "SCHEMA_VERSION",
    "AuditEvent",
    "AuditEventName",
    "AuditEventSerializationError",
    "AuditEventSink",
    "AuditOutcome",
    "AuditReason",
    "InMemoryAuditEventSink",
    "NoopAuditEventSink",
    "OtelAuditEventSink",
]

#: The only schema version this service emits.
SCHEMA_VERSION: Final = 1

_MAX_IDENTIFIER_LENGTH: Final = 256
_MAX_LABEL_LENGTH: Final = 128
_CORRELATION_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9_.:\-]{1,256}$")
_TRACE_ID_PATTERN: Final = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_PATTERN: Final = re.compile(r"^[0-9a-f]{16}$")
_SAFE_LABEL_PATTERN: Final = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


class AuditEventName(StrEnum):
    """The closed set of allowlisted audit event names."""

    AUTHORIZATION_BATCH = "mtmf.authorization.batch"
    AUTHENTICATION_REJECTED = "mtmf.security.authentication_rejected"
    CONTEXT_REJECTED = "mtmf.security.context_rejected"
    SUBSCRIPTION_REJECTED = "mtmf.security.subscription_rejected"
    REQUEST_REJECTED = "mtmf.security.request_rejected"
    AUTHORIZATION_ERROR = "mtmf.authorization.error"


class AuditOutcome(StrEnum):
    """The closed set of audit outcomes."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    MIXED = "MIXED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"


class AuditReason(StrEnum):
    """The closed, non-sensitive reason taxonomy.

    Codes are derived from typed internal classification only; they are
    never derived by inspecting exception text.
    """

    INVALID_REQUEST = "INVALID_REQUEST"
    RATE_LIMITED = "RATE_LIMITED"
    ADMISSION_REJECTED = "ADMISSION_REJECTED"
    SERVICE_AUTHENTICATION_FAILED = "SERVICE_AUTHENTICATION_FAILED"
    USER_AUTHENTICATION_FAILED = "USER_AUTHENTICATION_FAILED"
    ACTOR_CONTEXT_INVALID = "ACTOR_CONTEXT_INVALID"
    SUBSCRIPTION_INELIGIBLE = "SUBSCRIPTION_INELIGIBLE"
    DATABASE_UNAVAILABLE = "DATABASE_UNAVAILABLE"
    ISSUER_UNAVAILABLE = "ISSUER_UNAVAILABLE"
    EVALUATION_ERROR = "EVALUATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


#: The mapping keys a serialized event may ever contain.
ATTRIBUTE_ALLOWLIST: Final[frozenset[str]] = frozenset(
    {
        "event.name",
        "event.schema_version",
        "timestamp",
        "request_correlation_id",
        "trace_id",
        "span_id",
        "outcome",
        "reason_code",
        "duration_ms",
        "action_count",
        "allow_count",
        "deny_count",
        "service.name",
        "service.version",
        "deployment.environment",
    }
)

#: Keys that must never be accepted even if a future allowlist is widened.
_FORBIDDEN_KEYS: Final[frozenset[str]] = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "x-mtmf-user-authorization",
        "client_secret",
        "secret",
        "password",
        "assertion",
        "jwt",
        "claims",
        "policy",
        "body",
        "request_body",
        "response_body",
        "resource",
        "resources",
        "sql",
        "query",
        "email",
        "subject",
        "tenant_id",
        "identity_id",
        "principal_id",
        "application_id",
        "request_id",
        "exception",
        "stack_trace",
    }
)


class AuditEventSerializationError(ValueError):
    """An audit event could not be safely constructed or serialized."""


def _require_bounded_label(value: str, *, field_name: str) -> None:
    if not isinstance(value, str) or not _SAFE_LABEL_PATTERN.match(value):
        raise AuditEventSerializationError(f"{field_name} must be a bounded safe label")


def _require_correlation_id(value: str) -> None:
    if not isinstance(value, str) or not _CORRELATION_ID_PATTERN.match(value):
        raise AuditEventSerializationError("request_correlation_id is malformed")


def _require_optional_hex(value: str | None, pattern: re.Pattern[str], field_name: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not pattern.match(value):
        raise AuditEventSerializationError(f"{field_name} must be valid OTel context or absent")


def _require_count(value: int | None, field_name: str) -> int:
    if value is None or isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuditEventSerializationError(f"{field_name} must be a nonnegative integer")
    return value


def _coerce_int(value: object, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise AuditEventSerializationError(f"{field_name} must be an integer")
    try:
        return int(value)
    except ValueError as exc:
        raise AuditEventSerializationError(f"{field_name} must be an integer") from exc


def _coerce_float(value: object, field_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise AuditEventSerializationError(f"{field_name} must be a number")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise AuditEventSerializationError(f"{field_name} must be a number") from exc


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One immutable, allowlisted audit event payload.

    :raises AuditEventSerializationError: when any field is inconsistent,
        unsafe, or out of bounds. Construction failure is a telemetry fault
        and never changes an authorization response.
    """

    name: AuditEventName
    outcome: AuditOutcome
    timestamp: datetime
    request_correlation_id: str
    service_name: str
    service_version: str
    environment: str
    reason_code: AuditReason | None = None
    duration_ms: float | None = None
    action_count: int | None = None
    allow_count: int | None = None
    deny_count: int | None = None
    trace_id: str | None = None
    span_id: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise AuditEventSerializationError(
                f"unsupported audit event schema version {self.schema_version!r}"
            )
        if not isinstance(self.name, AuditEventName):
            raise AuditEventSerializationError("event name must be an AuditEventName")
        if not isinstance(self.outcome, AuditOutcome):
            raise AuditEventSerializationError("outcome must be an AuditOutcome")
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise AuditEventSerializationError("timestamp must be timezone-aware")
        offset = self.timestamp.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise AuditEventSerializationError("timestamp must be UTC")
        _require_correlation_id(self.request_correlation_id)
        for label, field_name in (
            (self.service_name, "service_name"),
            (self.service_version, "service_version"),
            (self.environment, "environment"),
        ):
            _require_bounded_label(label, field_name=field_name)
        _require_optional_hex(self.trace_id, _TRACE_ID_PATTERN, "trace_id")
        _require_optional_hex(self.span_id, _SPAN_ID_PATTERN, "span_id")
        if self.duration_ms is not None and (
            isinstance(self.duration_ms, bool)
            or not isinstance(self.duration_ms, (int, float))
            or not math.isfinite(self.duration_ms)
            or self.duration_ms < 0
        ):
            raise AuditEventSerializationError("duration_ms must be finite and nonnegative")
        self._validate_shape()

    def _validate_shape(self) -> None:
        """Enforce that counts and outcome agree with the event name."""
        is_batch = self.name is AuditEventName.AUTHORIZATION_BATCH
        if is_batch:
            if self.outcome not in (AuditOutcome.ALLOW, AuditOutcome.DENY, AuditOutcome.MIXED):
                raise AuditEventSerializationError("a batch event outcome must be ALLOW/DENY/MIXED")
            action_count = _require_count(self.action_count, "action_count")
            allow_count = _require_count(self.allow_count, "allow_count")
            deny_count = _require_count(self.deny_count, "deny_count")
            if allow_count + deny_count != action_count:
                raise AuditEventSerializationError(
                    "allow_count + deny_count must equal action_count"
                )
            if self.outcome is AuditOutcome.ALLOW and deny_count != 0:
                raise AuditEventSerializationError("an ALLOW outcome cannot contain a denial")
            if self.outcome is AuditOutcome.DENY and allow_count != 0:
                raise AuditEventSerializationError("a DENY outcome cannot contain an allowance")
            if self.outcome is AuditOutcome.MIXED and (allow_count == 0 or deny_count == 0):
                raise AuditEventSerializationError("a MIXED outcome must contain both effects")
        else:
            if any(
                count is not None
                for count in (self.action_count, self.allow_count, self.deny_count)
            ):
                raise AuditEventSerializationError("only batch events may carry counts")
            if self.outcome is AuditOutcome.ERROR:
                if self.name is not AuditEventName.AUTHORIZATION_ERROR:
                    raise AuditEventSerializationError("only the error event may be an ERROR")
            elif self.outcome is AuditOutcome.REJECTED:
                if self.name is AuditEventName.AUTHORIZATION_ERROR:
                    raise AuditEventSerializationError("the error event must use ERROR")
            else:
                raise AuditEventSerializationError(
                    "a non-batch event outcome must be REJECTED or ERROR"
                )
            if self.reason_code is None:
                raise AuditEventSerializationError("a non-batch event requires a reason_code")
        if self.reason_code is not None and not isinstance(self.reason_code, AuditReason):
            raise AuditEventSerializationError("reason_code must be an AuditReason")

    def to_attributes(self) -> dict[str, str | int | float | bool]:
        """Serialize to the exact allowlisted attribute mapping.

        Optional fields are omitted when absent; unknown fields are
        structurally impossible because this method enumerates the schema.
        """
        attributes: dict[str, str | int | float | bool] = {
            "event.name": self.name.value,
            "event.schema_version": self.schema_version,
            "timestamp": self.timestamp.isoformat(),
            "request_correlation_id": self.request_correlation_id,
            "outcome": self.outcome.value,
            "service.name": self.service_name,
            "service.version": self.service_version,
            "deployment.environment": self.environment,
        }
        if self.reason_code is not None:
            attributes["reason_code"] = self.reason_code.value
        if self.duration_ms is not None:
            attributes["duration_ms"] = float(self.duration_ms)
        if self.action_count is not None:
            attributes["action_count"] = self.action_count
        if self.allow_count is not None:
            attributes["allow_count"] = self.allow_count
        if self.deny_count is not None:
            attributes["deny_count"] = self.deny_count
        if self.trace_id is not None:
            attributes["trace_id"] = self.trace_id
        if self.span_id is not None:
            attributes["span_id"] = self.span_id
        return attributes

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> AuditEvent:
        """Construct an event from a strict allowlisted mapping.

        Unknown keys and known-sensitive keys are rejected rather than
        copied. This is the only supported deserialization path and is
        used by tests to prove the serializer cannot smuggle secrets.

        :raises AuditEventSerializationError: on an unknown/forbidden key
            or an unrepresentable value.
        """
        for key in data:
            if key in _FORBIDDEN_KEYS:
                raise AuditEventSerializationError(f"forbidden audit attribute {key!r}")
            if key not in ATTRIBUTE_ALLOWLIST:
                raise AuditEventSerializationError(f"unknown audit attribute {key!r}")

        def _enum(name: str, enum_type: type[StrEnum]) -> object:
            raw = data.get(name)
            if raw is None:
                return None
            try:
                return enum_type(str(raw))
            except ValueError as exc:
                raise AuditEventSerializationError(f"invalid {name} value") from exc

        name = _enum("event.name", AuditEventName)
        outcome = _enum("outcome", AuditOutcome)
        if not isinstance(name, AuditEventName) or not isinstance(outcome, AuditOutcome):
            raise AuditEventSerializationError("event.name and outcome are required")
        timestamp_raw = data.get("timestamp")
        if isinstance(timestamp_raw, str):
            try:
                timestamp = datetime.fromisoformat(timestamp_raw)
            except ValueError as exc:
                raise AuditEventSerializationError("timestamp is malformed") from exc
        elif isinstance(timestamp_raw, datetime):
            timestamp = timestamp_raw
        else:
            raise AuditEventSerializationError("timestamp is required")
        reason = _enum("reason_code", AuditReason)
        duration = data.get("duration_ms")
        counts: list[int | None] = []
        for key in ("action_count", "allow_count", "deny_count"):
            raw = data.get(key)
            counts.append(None if raw is None else _coerce_int(raw, key))
        schema_raw = data.get("event.schema_version")
        schema_version = (
            SCHEMA_VERSION
            if schema_raw is None
            else _coerce_int(schema_raw, "event.schema_version")
        )
        return cls(
            name=name,
            outcome=outcome,
            timestamp=timestamp,
            request_correlation_id=str(data.get("request_correlation_id", "")),
            service_name=str(data.get("service.name", "")),
            service_version=str(data.get("service.version", "")),
            environment=str(data.get("deployment.environment", "")),
            reason_code=reason if isinstance(reason, AuditReason) else None,
            duration_ms=None if duration is None else _coerce_float(duration, "duration_ms"),
            action_count=counts[0],
            allow_count=counts[1],
            deny_count=counts[2],
            trace_id=None if data.get("trace_id") is None else str(data.get("trace_id")),
            span_id=None if data.get("span_id") is None else str(data.get("span_id")),
            schema_version=schema_version,
        )


@runtime_checkable
class AuditEventSink(Protocol):
    """A fire-and-forget destination for structured audit events.

    Implementations must never raise into the authorization path: the
    telemetry boundary owns exception containment and failure accounting.
    """

    def emit(self, event: AuditEvent) -> None:
        """Emit ``event`` without blocking the caller indefinitely."""
        ...


class NoopAuditEventSink:
    """A sink that discards every event (disabled telemetry)."""

    __slots__ = ()

    def emit(self, event: AuditEvent) -> None:
        """Discard ``event``."""
        del event


class InMemoryAuditEventSink:
    """A deterministic in-memory sink for tests and diagnostics."""

    __slots__ = ("_events",)

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        """A snapshot tuple of the events emitted so far."""
        return tuple(self._events)

    def emit(self, event: AuditEvent) -> None:
        """Append ``event`` to the retained list."""
        self._events.append(event)

    def clear(self) -> None:
        """Discard every retained event."""
        self._events.clear()


class OtelAuditEventSink:
    """An :class:`AuditEventSink` backed by an OTel SDK logger.

    The logger's processor owns batching, queue bounds and export; this
    adapter only converts an already-validated event into one OTel log
    record. It never attaches a request body, token or policy payload.
    """

    __slots__ = ("_logger",)

    def __init__(self, logger: Logger) -> None:
        self._logger = logger

    def emit(self, event: AuditEvent) -> None:
        """Convert ``event`` to one OTel log record and hand it to the SDK."""
        from opentelemetry._logs import SeverityNumber
        from opentelemetry.context import Context
        from opentelemetry.sdk._logs import LogRecord
        from opentelemetry.trace import (
            NonRecordingSpan,
            SpanContext,
            TraceFlags,
            set_span_in_context,
        )

        timestamp_ns = int(event.timestamp.timestamp() * 1_000_000_000)
        context: Context | None = None
        if event.trace_id is not None and event.span_id is not None:
            span_context = SpanContext(
                trace_id=int(event.trace_id, 16),
                span_id=int(event.span_id, 16),
                is_remote=False,
                trace_flags=TraceFlags(TraceFlags.SAMPLED),
            )
            context = set_span_in_context(NonRecordingSpan(span_context))
        record = LogRecord(
            timestamp=timestamp_ns,
            observed_timestamp=timestamp_ns,
            context=context,
            severity_text="INFO",
            severity_number=SeverityNumber.INFO,
            body=event.name.value,
            attributes=event.to_attributes(),
            event_name=event.name.value,
        )
        self._logger.emit(record)
