"""Correlated trace-span helpers for the MTMF service.

Spans are created at existing orchestration seams only. Attributes are
supplied as bounded literal values; no request body, header, query string,
SQL text, token, claim, policy payload or business identifier is ever
added. Instrumentation code never hands a request object to this module.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import AbstractContextManager, nullcontext
from enum import StrEnum
from typing import Final

from opentelemetry.trace import INVALID_SPAN, Span, SpanKind, Tracer

__all__ = [
    "SPAN_NAMES",
    "SanitizedSpanAttributes",
    "SpanName",
    "span_context",
]

#: The closed set of span names emitted by the service.
SPAN_NAMES: Final[frozenset[str]] = frozenset(
    {
        "mtmf.http.evaluate",
        "mtmf.http.management_membership_add",
        "mtmf.actor.verify",
        "mtmf.subscription.check",
        "mtmf.roles.resolve",
        "mtmf.authorization.batch",
        "mtmf.persistence.uow",
        "mtmf.issuer.verify",
    }
)


class SpanName(StrEnum):
    """The closed set of instrumented span names."""

    HTTP_EVALUATE = "mtmf.http.evaluate"
    HTTP_MANAGEMENT_MEMBERSHIP_ADD = "mtmf.http.management_membership_add"
    ACTOR_VERIFY = "mtmf.actor.verify"
    SUBSCRIPTION_CHECK = "mtmf.subscription.check"
    ROLES_RESOLVE = "mtmf.roles.resolve"
    AUTHORIZATION_BATCH = "mtmf.authorization.batch"
    PERSISTENCE_UOW = "mtmf.persistence.uow"
    ISSUER_VERIFY = "mtmf.issuer.verify"


#: Marker alias documenting that span attributes are bounded, sanitized
#: scalar values, never request/response objects.
SanitizedSpanAttributes = Mapping[str, str | int | bool]


def span_context(
    tracer: Tracer | None,
    name: SpanName,
    *,
    kind: SpanKind = SpanKind.INTERNAL,
    attributes: SanitizedSpanAttributes | None = None,
) -> AbstractContextManager[Span]:
    """Return a span context manager for ``name``.

    When tracing is disabled (``tracer`` is ``None``) a no-op context that
    yields the OTel invalid span is returned, so callers never need a
    branch. ``name`` must be a member of the closed :class:`SpanName` set.
    """
    if tracer is None:
        return nullcontext(INVALID_SPAN)
    return tracer.start_as_current_span(
        name.value,
        kind=kind,
        attributes=dict(attributes or {}),
        # Operational failures still set the span status to ERROR, but the
        # raw exception event (which could quote a provider message or SQL
        # fragment) is never attached to the trace.
        record_exception=False,
        set_status_on_exception=True,
    )
