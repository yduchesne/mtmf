"""Detached request/response DTOs for the MTMF v1 batch authorization contract.

These are immutable, transport-independent snapshots. They import no
MTMF implementation package and expose no live domain object: a request
is a parsed, strictly validated value, and a response is an ordered set
of detached decisions with no policy internals.

The Action on the wire is the *exact* canonical MTMF Action URN
(``urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>``), not a
Permission, not a wildcard, and never an implicit "all actions". This
keeps the public contract lossless with respect to the core Action
grammar while keeping the DTO package free of a core import.

Nothing here evaluates authorization, resolves policy, or performs I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from uuid import UUID

from mtmf_api.errors import ApiContractValidationError

#: The literal wire schema version. Version selection is by URL (``/v1``);
#: callers cannot negotiate a different version in the body.
SCHEMA_VERSION = "1"

#: Batch bounds. Duplicates are preserved; a request never expands to all
#: actions and never contains a wildcard.
MIN_BATCH_ACTIONS = 1
MAX_BATCH_ACTIONS = 100

#: Per-field bounds. The Action is the full exact URN, so its bound is
#: intentionally large enough for the canonical ``urn:mtmf:iam:actions``
#: prefix plus a resource/operation pair.
MAX_ACTION_LENGTH = 256
MAX_REQUEST_ID_LENGTH = 64
MAX_RESOURCE_TYPE_LENGTH = 128
MAX_RESOURCE_ID_LENGTH = 256

#: Normative snapshot lifetime limits (approved PR 12 decision T3). The
#: DTO only represents timestamps; PR 17/18 own sensitivity classification
#: and the effective TTL selection.
SNAPSHOT_MAX_TTL = timedelta(seconds=300)
SNAPSHOT_DEFAULT_TTL = timedelta(seconds=60)
SNAPSHOT_SENSITIVE_MAX_TTL = timedelta(seconds=15)

_ACTION_PREFIX = "urn:mtmf:iam:actions:system:"
_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9._:-]+")


class AuthorizationEffect(Enum):
    """The public decision effect. Exactly ``ALLOW`` and ``DENY`` exist."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class DecisionReason(Enum):
    """The public, non-sensitive disclosure taxonomy for a decision.

    ``PERMITTED`` accompanies ``ALLOW`` only. The remaining values
    accompany ``DENY`` only. No value exposes matched Roles, policy ids,
    grants, or native-engine detail. ``INELIGIBLE_CONTEXT`` is
    deliberately absent: application/subscription ineligibility is an
    envelope-level error, not a per-item policy outcome.
    """

    PERMITTED = "PERMITTED"
    NO_PERMISSION = "NO_PERMISSION"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    UNKNOWN_ACTION = "UNKNOWN_ACTION"
    INVALID_SCOPE = "INVALID_SCOPE"
    UNSUPPORTED_RESOURCE = "UNSUPPORTED_RESOURCE"


#: The DENY-only subset of :class:`DecisionReason`.
_DENY_REASONS = frozenset(
    {
        DecisionReason.NO_PERMISSION,
        DecisionReason.EXPLICIT_DENY,
        DecisionReason.UNKNOWN_ACTION,
        DecisionReason.INVALID_SCOPE,
        DecisionReason.UNSUPPORTED_RESOURCE,
    }
)


class ResourceKind(Enum):
    """The discriminated resource binding kind.

    ``CAPABILITY`` binds no instance; ``APPLICATION_OWNED`` carries the
    consuming application's scope metadata (the PEP enforces isolation);
    ``MTMF_OWNED`` requires PR 17 to validate target class and qualifiers
    against authoritative MTMF policy before any ALLOW.
    """

    CAPABILITY = "capability"
    APPLICATION_OWNED = "application_owned"
    MTMF_OWNED = "mtmf_owned"


def _validate_text(
    value: object,
    *,
    field: str,
    max_length: int,
    ascii_only: bool = False,
) -> str:
    """Validate a bounded, control-character-free text field."""
    if not isinstance(value, str):
        raise ApiContractValidationError(f"{field} must be a string")
    if not value:
        raise ApiContractValidationError(f"{field} must not be empty")
    if len(value) > max_length:
        raise ApiContractValidationError(f"{field} exceeds the maximum length")
    if ascii_only and not value.isascii():
        raise ApiContractValidationError(f"{field} must be ASCII")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ApiContractValidationError(f"{field} must not contain control characters")
    return value


def _validate_request_id(value: object) -> str:
    """Validate a per-occurrence correlation id (1-64 ASCII, fixed charset)."""
    text = _validate_text(
        value,
        field="request_id",
        max_length=MAX_REQUEST_ID_LENGTH,
        ascii_only=True,
    )
    if _REQUEST_ID_PATTERN.fullmatch(text) is None:
        raise ApiContractValidationError("request_id contains disallowed characters")
    return text


def _validate_uuid(value: object, field: str) -> UUID:
    """Validate a non-nil UUID value."""
    if not isinstance(value, UUID):
        raise ApiContractValidationError(f"{field} must be a UUID")
    if value.int == 0:
        raise ApiContractValidationError(f"{field} must not be the nil UUID")
    return value


def validate_action_urn(value: object) -> str:
    """Validate an exact canonical MTMF Action URN.

    The grammar mirrors the authoritative core Action grammar
    (``urn:mtmf:iam:actions:system:<resource>:<verb>-<qualifier>``),
    without importing core. Wildcards, the unsupported tenant namespace,
    whitespace, and malformed operations are rejected. A syntactically
    valid but unregistered Action is *not* a DTO error; it becomes a
    per-item ``DENY/UNKNOWN_ACTION`` downstream.
    """
    text = _validate_text(
        value,
        field="action",
        max_length=MAX_ACTION_LENGTH,
        ascii_only=True,
    )
    if not text.startswith(_ACTION_PREFIX):
        raise ApiContractValidationError("action must be an exact MTMF system Action URN")
    if any(character.isspace() for character in text):
        raise ApiContractValidationError("action must not contain whitespace")
    if "*" in text:
        raise ApiContractValidationError("action must not contain a wildcard")
    remainder = text[len(_ACTION_PREFIX) :]
    parts = remainder.split(":")
    if len(parts) != 2:
        raise ApiContractValidationError(
            "action must be '<resource>:<verb>-<qualifier>' after the Action prefix"
        )
    resource, operation = parts
    if not resource or not operation:
        raise ApiContractValidationError("action components must not be empty")
    verb, separator, qualifier = operation.partition("-")
    if not separator or not verb or not qualifier:
        raise ApiContractValidationError("action operation must be '<verb>-<qualifier>'")
    return text


@dataclass(frozen=True, slots=True)
class ResourceTarget:
    """A detached, tagged resource binding.

    ``capability`` carries no instance. ``application_owned`` and
    ``mtmf_owned`` require an explicit type and id. Type/id are scope
    binding metadata, never proof of ownership or authorization.
    """

    kind: ResourceKind
    resource_type: str | None = None
    resource_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ResourceKind):
            raise ApiContractValidationError("resource kind must be a ResourceKind")
        if self.kind is ResourceKind.CAPABILITY:
            if self.resource_type is not None or self.resource_id is not None:
                raise ApiContractValidationError(
                    "a capability resource must not carry a type or id"
                )
            return
        _validate_text(
            self.resource_type,
            field="resource type",
            max_length=MAX_RESOURCE_TYPE_LENGTH,
            ascii_only=True,
        )
        _validate_text(
            self.resource_id,
            field="resource id",
            max_length=MAX_RESOURCE_ID_LENGTH,
        )


@dataclass(frozen=True, slots=True)
class ActionRequest:
    """One requested exact Action occurrence in a batch.

    ``request_id`` is correlation only, never a security identity.
    Duplicates are preserved and each occurrence is decisioned.
    """

    request_id: str
    action: str
    resource: ResourceTarget

    def __post_init__(self) -> None:
        _validate_request_id(self.request_id)
        validate_action_urn(self.action)
        if not isinstance(self.resource, ResourceTarget):
            raise ApiContractValidationError("resource must be a ResourceTarget")


@dataclass(frozen=True, slots=True)
class AuthorizationBatchRequest:
    """A detached batch request under one Tenant/organization context.

    ``tenant_id`` is a *requested selector*: PR 17 validates it against
    the verified actor. It is never proof of membership. ``actions`` is
    a nonempty ordered tuple preserving duplicates.
    """

    tenant_id: UUID
    organization_id: UUID | None
    actions: tuple[ActionRequest, ...]

    def __post_init__(self) -> None:
        _validate_uuid(self.tenant_id, "tenant_id")
        if self.organization_id is not None:
            _validate_uuid(self.organization_id, "organization_id")
        if not isinstance(self.actions, tuple):
            raise ApiContractValidationError("actions must be a tuple")
        if not MIN_BATCH_ACTIONS <= len(self.actions) <= MAX_BATCH_ACTIONS:
            raise ApiContractValidationError(
                f"actions must contain between {MIN_BATCH_ACTIONS} and {MAX_BATCH_ACTIONS} entries"
            )
        for action in self.actions:
            if not isinstance(action, ActionRequest):
                raise ApiContractValidationError("actions entries must be ActionRequest values")
        request_ids = [action.request_id for action in self.actions]
        if len(set(request_ids)) != len(request_ids):
            raise ApiContractValidationError("request_id values must be unique within a batch")


@dataclass(frozen=True, slots=True)
class ActionDecision:
    """One detached decision correlated to a request occurrence by id."""

    request_id: str
    effect: AuthorizationEffect
    reason: DecisionReason

    def __post_init__(self) -> None:
        _validate_request_id(self.request_id)
        if not isinstance(self.effect, AuthorizationEffect):
            raise ApiContractValidationError("effect must be an AuthorizationEffect")
        if not isinstance(self.reason, DecisionReason):
            raise ApiContractValidationError("reason must be a DecisionReason")
        if self.effect is AuthorizationEffect.ALLOW:
            if self.reason is not DecisionReason.PERMITTED:
                raise ApiContractValidationError("an ALLOW must use the PERMITTED reason")
        elif self.reason not in _DENY_REASONS:
            raise ApiContractValidationError("a DENY must not use the PERMITTED reason")


def _validate_utc(value: object, field: str) -> datetime:
    """Validate an aware UTC timestamp."""
    if not isinstance(value, datetime):
        raise ApiContractValidationError(f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ApiContractValidationError(f"{field} must be UTC")
    return value


@dataclass(frozen=True, slots=True)
class AuthorizationBatchResponse:
    """A detached, ordered batch response with bounded snapshot metadata.

    ``issued_at``/``expires_at`` are UTC and satisfy
    ``0 < expires_at - issued_at <= 300s``. The window cannot grant
    authority: PR 18 validates snapshots, PR 17 classifies sensitive
    Actions and applies the effective TTL. No Application/Principal/
    Identity UUID is exposed here.
    """

    tenant_id: UUID
    organization_id: UUID | None
    issued_at: datetime
    expires_at: datetime
    decisions: tuple[ActionDecision, ...]
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ApiContractValidationError("unsupported schema_version")
        _validate_uuid(self.tenant_id, "tenant_id")
        if self.organization_id is not None:
            _validate_uuid(self.organization_id, "organization_id")
        _validate_utc(self.issued_at, "issued_at")
        _validate_utc(self.expires_at, "expires_at")
        if self.issued_at >= self.expires_at:
            raise ApiContractValidationError("issued_at must precede expires_at")
        if self.expires_at - self.issued_at > SNAPSHOT_MAX_TTL:
            raise ApiContractValidationError("snapshot lifetime exceeds the 300s maximum")
        if not isinstance(self.decisions, tuple):
            raise ApiContractValidationError("decisions must be a tuple")
        if not self.decisions:
            raise ApiContractValidationError("decisions must not be empty")
        for decision in self.decisions:
            if not isinstance(decision, ActionDecision):
                raise ApiContractValidationError("decisions entries must be ActionDecision values")


def ensure_utc(value: datetime) -> datetime:
    """Return ``value`` normalized to UTC after validating it is aware UTC."""
    return _validate_utc(value, "timestamp").astimezone(UTC)
