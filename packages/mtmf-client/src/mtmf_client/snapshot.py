"""Immutable, context-bound, monotonic authorization snapshots and PEP helpers.

A snapshot is a detached record of *exactly* the ordered request that a
consumer submitted and the decisions the authoritative remote PDP returned
for it, bound to the trusted local actor/session and Application context
that produced it. It is **not** a bearer capability: it is only usable
through :func:`is_allowed` / :func:`require` with the identical trusted
context, Tenant, optional Organization, and exact Action resource
occurrence that were evaluated.

The helpers perform no network I/O and no policy evaluation. Missing,
ambiguous, expired, mismatched, tampered or unknown occurrences deny.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from mtmf_api.authorization import (
    ActionDecision,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    ResourceTarget,
)
from mtmf_client.errors import ActorContextError, AuthorizationDenied

__all__ = [
    "AuthorizationSnapshot",
    "TrustedActorContext",
    "is_allowed",
    "require",
]


@dataclass(frozen=True, slots=True)
class TrustedActorContext:
    """The consumer's authenticated local actor/session binding.

    This value must be constructed at the consuming application's
    authenticated server-side boundary from its own trusted session store;
    it is **not** cryptographic proof and ``mtmf-client`` cannot verify
    that the caller is truthful. A UUID, JWT payload, query parameter or
    body field is never sufficient on its own. The raw user access token is
    passed separately and is never a persisted key.
    """

    actor_key: str
    session_key: str
    tenant_id: UUID
    application_id: UUID
    principal_id: UUID | None = None
    identity_id: UUID | None = None
    organization_id: UUID | None = None

    def __post_init__(self) -> None:
        for name in ("actor_key", "session_key"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ActorContextError(f"{name} must be a non-empty string")
        for name in ("tenant_id", "application_id"):
            value = getattr(self, name)
            if not isinstance(value, UUID) or value.int == 0:
                raise ActorContextError(f"{name} must be a non-nil UUID")
        for name in ("principal_id", "identity_id", "organization_id"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, UUID) or value.int == 0):
                raise ActorContextError(f"{name} must be a non-nil UUID or None")


class _Provenance:
    """Opaque per-client-instance marker proving a snapshot was issued locally."""

    __slots__ = ("instance",)

    def __init__(self) -> None:
        self.instance = object()


class AuthorizationSnapshot:
    """Immutable, locally issued, context-bound authorization result.

    Construction is only supported through the validated client path
    (:func:`_issue_snapshot`). Python object construction is not a security
    boundary, so the helpers additionally require the private provenance
    marker; a hand-built or reconstructed object is never treated as a
    trusted grant.
    """

    __slots__ = (
        "_context",
        "_deadline_monotonic",
        "_decisions",
        "_expires_at",
        "_issued_at",
        "_issued_monotonic",
        "_monotonic_clock",
        "_provenance",
        "_request",
    )

    def __init__(
        self,
        *,
        request: AuthorizationBatchRequest,
        response: AuthorizationBatchResponse,
        context: TrustedActorContext,
        issued_monotonic: float,
        deadline_monotonic: float,
        monotonic_clock: Callable[[], float],
        provenance: _Provenance,
    ) -> None:
        if not isinstance(request, AuthorizationBatchRequest):
            raise ValueError("snapshot requires an AuthorizationBatchRequest")
        if not isinstance(context, TrustedActorContext):
            raise ValueError("snapshot requires a TrustedActorContext")
        if len(response.decisions) != len(request.actions):
            raise ValueError("snapshot decisions must align with the request")
        if type(provenance) is not _Provenance:
            raise ValueError("snapshot requires a valid local provenance marker")
        self._request = request
        self._decisions = response.decisions
        self._context = context
        self._issued_at = response.issued_at
        self._expires_at = response.expires_at
        self._issued_monotonic = issued_monotonic
        self._deadline_monotonic = deadline_monotonic
        self._monotonic_clock = monotonic_clock
        self._provenance = provenance

    def __repr__(self) -> str:
        organization = (
            str(self._request.organization_id) if self._request.organization_id else "None"
        )
        return (
            "AuthorizationSnapshot("
            f"tenant_id={self._request.tenant_id}, "
            f"organization_id={organization}, "
            f"decision_count={len(self._decisions)}, "
            f"expires_at={self._expires_at.isoformat()})"
        )

    @property
    def tenant_id(self) -> UUID:
        """The bound ordinary Tenant UUID."""
        return self._request.tenant_id

    @property
    def organization_id(self) -> UUID | None:
        """The bound optional Organization UUID."""
        return self._request.organization_id

    @property
    def application_id(self) -> UUID:
        """The local Application binding that produced the snapshot."""
        return self._context.application_id

    @property
    def issued_at(self) -> datetime:
        """The server-issued UTC ``issued_at``."""
        return self._issued_at

    @property
    def expires_at(self) -> datetime:
        """The server-issued UTC ``expires_at`` (bounded to the client cap)."""
        return self._expires_at

    @property
    def decision_count(self) -> int:
        """The number of ordered decisions bound to the snapshot."""
        return len(self._decisions)


def _issue_snapshot(
    *,
    request: AuthorizationBatchRequest,
    response: AuthorizationBatchResponse,
    context: TrustedActorContext,
    issued_monotonic: float,
    deadline_monotonic: float,
    monotonic_clock: Callable[[], float],
    provenance: _Provenance,
) -> AuthorizationSnapshot:
    """Issue a snapshot from already-validated internal state (client only)."""
    return AuthorizationSnapshot(
        request=request,
        response=response,
        context=context,
        issued_monotonic=issued_monotonic,
        deadline_monotonic=deadline_monotonic,
        monotonic_clock=monotonic_clock,
        provenance=provenance,
    )


def _owned_by(snapshot: object, provenance: _Provenance) -> bool:
    """Return whether ``snapshot`` was issued by the given client provenance."""
    if not isinstance(snapshot, AuthorizationSnapshot):
        return False
    return snapshot._provenance is provenance


def _context_matches(snapshot: AuthorizationSnapshot, context: TrustedActorContext) -> bool:
    """Return whether ``context`` is the exact bound trusted context."""
    if not isinstance(context, TrustedActorContext):
        return False
    return context == snapshot._context


def _snapshot_is_live(snapshot: AuthorizationSnapshot) -> bool:
    """Return whether the snapshot is locally valid and unexpired right now."""
    if type(snapshot) is not AuthorizationSnapshot:
        return False
    if type(snapshot._provenance) is not _Provenance:
        return False
    now = float(snapshot._monotonic_clock())
    if now < snapshot._issued_monotonic:
        # Monotonic rollback / anomaly: fail closed.
        return False
    return now < snapshot._deadline_monotonic


def _find_decision(
    snapshot: AuthorizationSnapshot,
    *,
    action: object,
    resource: object,
    request_id: str | None,
) -> ActionDecision | None:
    """Return the single matching ordered decision, or ``None`` on ambiguity.

    The Action and ResourceTarget are mandatory: a lookup must identify the
    exact object or capability being checked. ``request_id`` is only a
    correlation discriminator and never supplies the authorization target.
    """
    if not isinstance(action, str) or not isinstance(resource, ResourceTarget):
        return None
    actions = snapshot._request.actions
    if request_id is not None:
        if not isinstance(request_id, str) or not request_id:
            return None
        matches = [
            index
            for index, item in enumerate(actions)
            if item.request_id == request_id and item.action == action and item.resource == resource
        ]
        if len(matches) != 1:
            return None
        return snapshot._decisions[matches[0]]
    matches = [
        index
        for index, item in enumerate(actions)
        if item.action == action and item.resource == resource
    ]
    if len(matches) != 1:
        return None
    return snapshot._decisions[matches[0]]


def is_allowed(
    snapshot: AuthorizationSnapshot | None,
    *,
    context: TrustedActorContext,
    action: str,
    resource: ResourceTarget,
    request_id: str | None = None,
) -> bool:
    """Return whether an exact bound occurrence is an unexpired ``ALLOW``.

    ``action`` and ``resource`` are **mandatory**: every local authorization
    decision must identify the exact Action and ``ResourceTarget`` for the
    object or capability being checked. Supplying a capability check requires
    an explicit ``ResourceTarget(kind=ResourceKind.CAPABILITY)``; a missing
    resource is never treated as a wildcard. ``request_id`` is only a
    correlation discriminator: when given, the occurrence must match it *and*
    the exact Action/ResourceTarget; when omitted, the Action/ResourceTarget
    pair must be unique in the evaluated batch.

    Never performs network I/O and never evaluates policy. Returns ``False``
    for a missing/mismatched context, an expired or tampered snapshot, an
    absent or ambiguous occurrence, and any non-``ALLOW`` decision.
    """
    if not isinstance(snapshot, AuthorizationSnapshot):
        return False
    if not _context_matches(snapshot, context):
        return False
    if not _snapshot_is_live(snapshot):
        return False
    decision = _find_decision(
        snapshot,
        action=action,
        resource=resource,
        request_id=request_id,
    )
    if decision is None:
        return False
    return (
        decision.effect is AuthorizationEffect.ALLOW and decision.reason is DecisionReason.PERMITTED
    )


def require(
    snapshot: AuthorizationSnapshot | None,
    *,
    context: TrustedActorContext,
    action: str,
    resource: ResourceTarget,
    request_id: str | None = None,
) -> None:
    """Raise :class:`AuthorizationDenied` unless :func:`is_allowed` is true.

    ``action`` and ``resource`` are mandatory (see :func:`is_allowed`). The
    consumer must derive them from the *actual object being accessed*, not
    copy a previously authorized target by correlation id. An explicit
    matching tuple proves only that this previously evaluated
    Action/ResourceTarget was ``ALLOW``; it does not prove that the
    consumer's own row/Tenant predicate succeeded, which remains a separate
    mandatory enforcement step.
    """
    if not is_allowed(
        snapshot,
        context=context,
        action=action,
        resource=resource,
        request_id=request_id,
    ):
        raise AuthorizationDenied("the requested Action occurrence is not allowed")
