"""Application registry and Tenant subscription domain model (PR 13).

PR 13 introduces three distinct, independently meaningful concepts:

- :class:`Application` — a globally registered software Application. It
  is deliberately **not** a Principal, Identity, Tenant, Organization,
  IAM Group, Role, Permission, or OAuth credential. Its internal UUID
  identity is stable and its application key is unique and normalized.
- :class:`ApplicationTenantRegistration` — the explicit fact that an
  Application is permitted to operate for one Tenant (decision S1/S6).
- :class:`TenantApplicationSubscription` — the time-bounded commercial
  fact that a Tenant subscribes to an Application (decisions S2/S3/S7).

A registration and a subscription are separate security facts. Neither
implies the other, and neither is authorization: an eligible
subscription never grants a Role, Permission, action, or acting-user
authority. A positive eligibility outcome requires an ``ACTIVE``
Application, an ``ACTIVE`` tenant, an ``ACTIVE`` registration, and an
eligible in-window ``ACTIVE`` subscription (decision S6).

These entities are structural persistence facts. Their identity,
association, and provenance fields are immutable; only the documented
lifecycle (and a subscription's optional end instant) may change, and
only through the validated transitions in this module. Possessing a
repository or constructing an entity confers no authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar

from mtmf_core.domain.errors import (
    ApplicationRegistryInvariantError,
    DomainInvariantError,
)
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, new_extension
from mtmf_core.domain.lifecycle import (
    ApplicationLifecycle,
    RegistrationLifecycle,
    SubscriptionLifecycle,
)
from mtmf_core.domain.mixins import ImmutableFieldGuard

__all__ = [
    "Application",
    "ApplicationTenantRegistration",
    "TenantApplicationSubscription",
    "normalize_application_key",
    "validate_application_transition",
    "validate_registration_transition",
    "validate_subscription_end_change",
    "validate_subscription_transition",
    "validate_subscription_window",
]

# A normalized application key: lowercase alphanumeric plus ``.``, ``_``
# and ``-``, bounded to 128 characters, beginning and ending with an
# alphanumeric character. It deliberately does not reuse the Action/Role
# URN grammar.
_APPLICATION_KEY_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")

_MAX_APPLICATION_KEY_LENGTH = 128

#: Legal lifecycle transitions. A transition is always between two
#: distinct members; a no-op transition is rejected.
_APPLICATION_TRANSITIONS: frozenset[tuple[ApplicationLifecycle, ApplicationLifecycle]] = frozenset(
    {
        (ApplicationLifecycle.ACTIVE, ApplicationLifecycle.SUSPENDED),
        (ApplicationLifecycle.SUSPENDED, ApplicationLifecycle.ACTIVE),
        (ApplicationLifecycle.ACTIVE, ApplicationLifecycle.RETIRED),
        (ApplicationLifecycle.SUSPENDED, ApplicationLifecycle.RETIRED),
    }
)

_REGISTRATION_TRANSITIONS: frozenset[tuple[RegistrationLifecycle, RegistrationLifecycle]] = (
    frozenset(
        {
            (RegistrationLifecycle.ACTIVE, RegistrationLifecycle.REVOKED),
        }
    )
)

_SUBSCRIPTION_TRANSITIONS: frozenset[tuple[SubscriptionLifecycle, SubscriptionLifecycle]] = (
    frozenset(
        {
            (SubscriptionLifecycle.PENDING, SubscriptionLifecycle.ACTIVE),
            (SubscriptionLifecycle.PENDING, SubscriptionLifecycle.CANCELLED),
            (SubscriptionLifecycle.ACTIVE, SubscriptionLifecycle.SUSPENDED),
            (SubscriptionLifecycle.ACTIVE, SubscriptionLifecycle.CANCELLED),
            (SubscriptionLifecycle.ACTIVE, SubscriptionLifecycle.EXPIRED),
            (SubscriptionLifecycle.SUSPENDED, SubscriptionLifecycle.ACTIVE),
            (SubscriptionLifecycle.SUSPENDED, SubscriptionLifecycle.CANCELLED),
            (SubscriptionLifecycle.SUSPENDED, SubscriptionLifecycle.EXPIRED),
        }
    )
)

#: Subscription lifecycle states with no outgoing transition. A terminal
#: subscription cannot be updated at all (PR 13-1 decision A1).
_TERMINAL_SUBSCRIPTION_LIFECYCLES: frozenset[SubscriptionLifecycle] = frozenset(
    {SubscriptionLifecycle.CANCELLED, SubscriptionLifecycle.EXPIRED}
)


def normalize_application_key(value: str) -> str:
    """Return the normalized, validated form of an application key.

    The key is lowercased and trimmed, then validated against the
    documented pattern. Normalization is deterministic so that an
    Application can never be registered twice under keys that differ only
    by case or surrounding whitespace.

    :raises ApplicationRegistryInvariantError: when ``value`` is not a
        string or does not match the normalized key grammar.
    """
    if not isinstance(value, str):
        raise ApplicationRegistryInvariantError("an application key must be a string")
    normalized = value.strip().lower()
    if not normalized:
        raise ApplicationRegistryInvariantError("an application key must not be empty")
    if len(normalized) > _MAX_APPLICATION_KEY_LENGTH:
        raise ApplicationRegistryInvariantError(
            f"an application key must be at most {_MAX_APPLICATION_KEY_LENGTH} characters"
        )
    if _APPLICATION_KEY_PATTERN.fullmatch(normalized) is None:
        raise ApplicationRegistryInvariantError(
            "an application key must contain only lowercase letters, digits, '.', '_', "
            "and '-', and must begin and end with a letter or digit"
        )
    return normalized


def _require_aware_utc(value: datetime, name: str) -> None:
    """Reject a naive instant; any fixed-offset aware instant is accepted."""
    if not isinstance(value, datetime):
        raise ApplicationRegistryInvariantError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ApplicationRegistryInvariantError(f"{name} must be timezone-aware")


def validate_application_transition(
    current: ApplicationLifecycle, target: ApplicationLifecycle
) -> None:
    """Validate one Application lifecycle transition.

    Only the documented transitions are legal; ``RETIRED`` is terminal and
    a no-op transition is rejected.

    :raises ApplicationRegistryInvariantError: on an illegal transition.
    """
    if (current, target) not in _APPLICATION_TRANSITIONS:
        raise ApplicationRegistryInvariantError(
            f"illegal Application lifecycle transition {current.name!r} -> {target.name!r}"
        )


def validate_registration_transition(
    current: RegistrationLifecycle, target: RegistrationLifecycle
) -> None:
    """Validate one registration lifecycle transition.

    ``REVOKED`` is terminal: a revoked registration is never reactivated.

    :raises ApplicationRegistryInvariantError: on an illegal transition.
    """
    if (current, target) not in _REGISTRATION_TRANSITIONS:
        raise ApplicationRegistryInvariantError(
            f"illegal registration lifecycle transition {current.name!r} -> {target.name!r}"
        )


def validate_subscription_transition(
    current: SubscriptionLifecycle, target: SubscriptionLifecycle
) -> None:
    """Validate one subscription lifecycle transition.

    ``CANCELLED`` and ``EXPIRED`` are terminal and cannot be reactivated;
    suspension may be lifted back to ``ACTIVE``. Time-based expiry is
    enforced separately (decision S7) and does not require this
    transition.

    :raises ApplicationRegistryInvariantError: on an illegal transition.
    """
    if (current, target) not in _SUBSCRIPTION_TRANSITIONS:
        raise ApplicationRegistryInvariantError(
            f"illegal subscription lifecycle transition {current.name!r} -> {target.name!r}"
        )


def validate_subscription_window(starts_at: datetime, ends_at: datetime | None) -> None:
    """Validate a subscription's ``[starts_at, ends_at)`` window.

    This is the **creation** rule. ``starts_at`` is required and
    timezone-aware. When present, ``ends_at`` must be timezone-aware and
    strictly greater than ``starts_at`` so the half-open interval is
    non-empty.

    :raises ApplicationRegistryInvariantError: on an invalid window.
    """
    _require_aware_utc(starts_at, "starts_at")
    if ends_at is not None:
        _require_aware_utc(ends_at, "ends_at")
        if ends_at <= starts_at:
            raise ApplicationRegistryInvariantError(
                "a subscription ends_at must be strictly after starts_at"
            )


def validate_subscription_end_change(
    old_end: datetime | None,
    new_end: datetime,
    starts_at: datetime,
) -> None:
    """Validate a **restrictive** subscription end-date amendment (A1).

    ``starts_at`` is immutable, so this only ever narrows the eligibility
    window:

    - ``new_end`` must be timezone-aware;
    - ``new_end`` must be strictly after ``starts_at``;
    - when a finite ``old_end`` already exists, ``new_end`` must be
      strictly earlier than it (a shortening); extension and equality are
      rejected;
    - when ``old_end`` is absent (open-ended), setting a finite ``new_end``
      is accepted.

    Clearing a finite end date is rejected because a bare ``None`` is not a
    valid ``new_end``: the domain API never expresses "clear" and the
    database guard rejects a finite-to-``NULL`` update independently.

    :raises ApplicationRegistryInvariantError: on a non-restrictive or
        invalid amendment.
    """
    _require_aware_utc(new_end, "ends_at")
    if new_end <= starts_at:
        raise ApplicationRegistryInvariantError(
            "a subscription ends_at amendment must be strictly after starts_at"
        )
    if old_end is not None and new_end >= old_end:
        raise ApplicationRegistryInvariantError(
            "a subscription ends_at may only be shortened to a strictly earlier instant; "
            "extension, replacement with a later instant, and clearing are not permitted"
        )


@dataclass(slots=True)
class Application(ImmutableFieldGuard):
    """A globally registered software Application (PR 13, decision S1).

    :attr:`id` is the immutable Application UUID identity;
    :attr:`application_key` is the immutable stable normalized key;
    :attr:`owner_identity_id` is immutable creator provenance only (it is
    not authorization and not a tenant relationship); :attr:`lifecycle`
    is the validated global lifecycle; :attr:`extension` is the opaque
    application extension object.

    An Application is not a Principal or Identity and carries no OAuth
    ``client_id`` or credential subject; the future credential mapping is
    owned by PR 14 and must never reuse :attr:`id` as proof of
    authentication. ``RETIRED`` is terminal: a retired Application accepts
    no further update (PR 13-1 decision A1), and the database guard
    enforces the same rule.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {"id", "application_key", "owner_identity_id"}
    )

    id: DomainId
    application_key: str
    name: str
    owner_identity_id: DomainId
    lifecycle: ApplicationLifecycle = ApplicationLifecycle.ACTIVE
    extension: JsonObject = field(default_factory=new_extension)

    def __post_init__(self) -> None:
        normalized = normalize_application_key(self.application_key)
        object.__setattr__(self, "application_key", normalized)
        if not isinstance(self.name, str) or not self.name.strip():
            raise ApplicationRegistryInvariantError(
                "an Application name must be a non-empty string"
            )
        if self.lifecycle not in (
            ApplicationLifecycle.ACTIVE,
            ApplicationLifecycle.SUSPENDED,
            ApplicationLifecycle.RETIRED,
        ):
            raise DomainInvariantError("an Application lifecycle is not a legal value")

    def transition_to(self, target: ApplicationLifecycle) -> None:
        """Apply a validated Application lifecycle transition in place.

        :raises ApplicationRegistryInvariantError: on an illegal transition.
        """
        validate_application_transition(self.lifecycle, target)
        self.lifecycle = target


@dataclass(slots=True)
class ApplicationTenantRegistration(ImmutableFieldGuard):
    """The explicit permission for an Application to operate for a Tenant.

    :attr:`id` is the immutable registration identity;
    :attr:`application_id` and :attr:`tenant_id` are the immutable
    association; :attr:`created_by_identity_id` is immutable creation
    provenance (not authentication and not authorization);
    :attr:`created_at` is the immutable creation instant; :attr:`lifecycle`
    is the mutable, validated lifecycle. ``REVOKED`` is terminal: a revoked
    registration accepts no further update (PR 13-1 decision A1), and the
    database guard enforces the same rule.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {
            "id",
            "application_id",
            "tenant_id",
            "created_by_identity_id",
            "created_at",
        }
    )

    id: DomainId
    application_id: DomainId
    tenant_id: DomainId
    created_by_identity_id: DomainId
    created_at: datetime
    lifecycle: RegistrationLifecycle = RegistrationLifecycle.ACTIVE

    def __post_init__(self) -> None:
        _require_aware_utc(self.created_at, "created_at")
        if self.lifecycle not in (
            RegistrationLifecycle.ACTIVE,
            RegistrationLifecycle.REVOKED,
        ):
            raise DomainInvariantError("a registration lifecycle is not a legal value")

    def transition_to(self, target: RegistrationLifecycle) -> None:
        """Apply a validated registration lifecycle transition in place.

        :raises ApplicationRegistryInvariantError: on an illegal transition.
        """
        validate_registration_transition(self.lifecycle, target)
        self.lifecycle = target

    def describes_pair(self, application_id: DomainId, tenant_id: DomainId) -> bool:
        """Whether this registration is exactly the ``(application, tenant)`` pair."""
        return self.application_id == application_id and self.tenant_id == tenant_id


@dataclass(slots=True)
class TenantApplicationSubscription(ImmutableFieldGuard):
    """A Tenant's time-bounded subscription to an Application (PR 13).

    :attr:`id` is the immutable subscription identity;
    :attr:`application_id` and :attr:`tenant_id` are the immutable
    association; :attr:`created_by_identity_id` is immutable creation
    provenance; :attr:`starts_at` and :attr:`created_at` are immutable
    instants; :attr:`ends_at` is the optional mutable end instant; and
    :attr:`lifecycle` is the mutable, validated lifecycle.

    Under PR 13-1 decision A1 the end-date field is **restrictive only**:
    it may be shortened or set on an open-ended subscription, but never
    extended, replaced with a later instant, or cleared to ``None``. A
    ``CANCELLED`` or ``EXPIRED`` subscription is terminal and accepts no
    update at all. The SQL guard enforces the same rules against the locked
    persisted row, so it remains authoritative for concurrent writers.

    A subscription is a commercial/fact relationship. It is never an
    authorization, never a Role or Permission, and never proof of an
    acting user's identity.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {
            "id",
            "application_id",
            "tenant_id",
            "created_by_identity_id",
            "starts_at",
            "created_at",
        }
    )

    id: DomainId
    application_id: DomainId
    tenant_id: DomainId
    created_by_identity_id: DomainId
    starts_at: datetime
    created_at: datetime
    ends_at: datetime | None = None
    lifecycle: SubscriptionLifecycle = SubscriptionLifecycle.PENDING

    def __post_init__(self) -> None:
        _require_aware_utc(self.created_at, "created_at")
        validate_subscription_window(self.starts_at, self.ends_at)
        if self.lifecycle not in (
            SubscriptionLifecycle.PENDING,
            SubscriptionLifecycle.ACTIVE,
            SubscriptionLifecycle.SUSPENDED,
            SubscriptionLifecycle.CANCELLED,
            SubscriptionLifecycle.EXPIRED,
        ):
            raise DomainInvariantError("a subscription lifecycle is not a legal value")

    def _require_nonterminal(self) -> None:
        """Reject any mutation of a terminal subscription (A1)."""
        if self.lifecycle in _TERMINAL_SUBSCRIPTION_LIFECYCLES:
            raise ApplicationRegistryInvariantError(
                f"a terminal subscription ({self.lifecycle.name}) cannot be updated"
            )

    def transition_to(self, target: SubscriptionLifecycle) -> None:
        """Apply a validated lifecycle-only transition in place.

        The end-date window is not changed. A terminal source and an
        illegal or same-state transition are rejected and leave the
        subscription untouched.

        :raises ApplicationRegistryInvariantError: on a terminal source or
            an illegal transition.
        """
        self._require_nonterminal()
        validate_subscription_transition(self.lifecycle, target)
        self.lifecycle = target

    def shorten_end_to(self, new_end: datetime) -> None:
        """Apply a validated restrictive end-date amendment in place.

        ``new_end`` must be strictly after ``starts_at`` and, when a finite
        end already exists, strictly earlier than it. Extension, replacing
        with a later instant, and clearing are rejected; the lifecycle is
        unchanged.

        :raises ApplicationRegistryInvariantError: on a terminal source or
            a non-restrictive amendment.
        """
        self._require_nonterminal()
        validate_subscription_end_change(self.ends_at, new_end, self.starts_at)
        self.ends_at = new_end

    def transition_and_shorten_to(self, target: SubscriptionLifecycle, new_end: datetime) -> None:
        """Apply a legal transition and a restrictive shortening atomically.

        Both changes are validated against the pre-change state **before**
        either field is assigned, so a rejected operation leaves both the
        lifecycle and the end date unchanged (matrix M07/M08/M09).

        :raises ApplicationRegistryInvariantError: on a terminal source, an
            illegal transition, or a non-restrictive amendment.
        """
        self._require_nonterminal()
        validate_subscription_transition(self.lifecycle, target)
        validate_subscription_end_change(self.ends_at, new_end, self.starts_at)
        self.lifecycle = target
        self.ends_at = new_end

    def describes_pair(self, application_id: DomainId, tenant_id: DomainId) -> bool:
        """Whether this subscription is exactly the ``(application, tenant)`` pair."""
        return self.application_id == application_id and self.tenant_id == tenant_id
