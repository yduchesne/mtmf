"""Verified-mutation provenance contract (PR 19A; scaffold only).

Roadmap PR 19A is scoped to durably auditing security-state mutations that
are reached through an **already authenticated and authorized** application
use case (a "category-A" path). This module defines the immutable internal
record that a trusted application orchestration method constructs *after*
actor verification and an exact authoritative Action ``ALLOW``; it does not
verify, authorize, or persist anything itself.

**Status: PARTIAL / BLOCKED.** Phase 0 of the PR 19A execution plan found no
category-A management mutation entry point in the current codebase: the
runtime service exposes only the batch decision endpoint and health probes,
and the only production write paths are the privileged development
bootstrap/initializer (category B) and test fixtures. Per the mandatory
early-STOP instruction, no management API, schema, stored function, or
grant was manufactured to create one. Only this contract and its
deterministic validation tests are implemented. See
``docs/pr-artifacts/pr-19a/``.

Trust model (normative intent, not a database guarantee)::

    VerifiedActorContext + exact authorized operation (trusted application)
        -> VerifiedMutationProvenance (this module)
        -> UnitOfWork / repository operation
        -> restricted runtime connection
        -> reviewed stored function
        -> authoritative mutation + append-only audit row (future PR)

The PostgreSQL role is an application credential, not an end-user identity.
A compromised application/runtime credential can forge these values unless a
separately designed database-verifiable attestation mechanism is introduced;
provenance is *application-verified*, never cryptographically attested by
PostgreSQL. This module is deliberately **not** re-exported from
``mtmf_core``/``mtmf_core.application`` or any ``mtmf-api`` DTO: it is an
internal record, not a public capability or transport contract.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from uuid import UUID

from mtmf_core.domain.iam_urn import ActionUrn
from mtmf_core.domain.identity import DomainId

__all__ = [
    "IDENTITY_GROUP_MEMBERSHIP_ADD_ACTION",
    "MutationProvenanceError",
    "UnregisteredMutationError",
    "VerifiedMutationProvenance",
    "registered_mutations",
    "require_registered_mutation",
]

#: Bounded length for the closed ``target_kind`` discriminator.
_MAX_TARGET_KIND_LENGTH = 64

#: The single exact Action approved for the Identity-to-Group membership-add
#: target kind (PR 19C, Amendment 01 §A). Approval is a human policy decision;
#: this constant is a whitelist entry, never an authorization grant.
IDENTITY_GROUP_MEMBERSHIP_ADD_ACTION = ActionUrn(
    "urn:mtmf:iam:actions:system:identity-group-membership:add-object"
)

#: Closed registration of the operations that may produce provenance. Each
#: key is a ``target_kind`` and each value is the frozenset of exact Action
#: URN values approved for that target kind. Registration is a whitelist, not
#: proof of authentication or authorization: the reviewed orchestration path
#: still verifies the actor and obtains an authoritative ALLOW first.
_MIGRATED_MUTATIONS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "identity_group_membership": frozenset({IDENTITY_GROUP_MEMBERSHIP_ADD_ACTION.value}),
    }
)


class MutationProvenanceError(ValueError):
    """A would-be provenance record is structurally invalid.

    Raised for a missing or malformed operation UUID, actor/tenant/
    application/target identity, Action URN, target kind, or non-UTC
    ``authorized_at`` instant. It is a deterministic rejection and never a
    statement about authentication or authorization.
    """


class UnregisteredMutationError(MutationProvenanceError):
    """The ``target_kind``/Action pairing is not an approved mutation.

    Fail-closed: an unregistered pairing can never be treated as an audited
    security-state mutation, even though it is structurally well formed.
    """


def _require_uuid(name: str, value: object) -> UUID:
    if not isinstance(value, UUID):
        raise MutationProvenanceError(f"{name} must be a UUID")
    return value


def _require_domain_id(name: str, value: object) -> DomainId:
    if not isinstance(value, DomainId):
        raise MutationProvenanceError(f"{name} must be a DomainId")
    return value


def _require_action_urn(value: object) -> ActionUrn:
    if not isinstance(value, ActionUrn):
        raise MutationProvenanceError("action_urn must be an ActionUrn")
    return value


def _require_target_kind(value: object) -> str:
    if not isinstance(value, str):
        raise MutationProvenanceError("target_kind must be a string")
    if not value:
        raise MutationProvenanceError("target_kind must not be empty")
    if value != value.strip() or any(character.isspace() for character in value):
        raise MutationProvenanceError("target_kind must not contain whitespace")
    if len(value) > _MAX_TARGET_KIND_LENGTH:
        raise MutationProvenanceError("target_kind exceeds the bounded length")
    return value


def _require_utc(value: object) -> datetime:
    if not isinstance(value, datetime):
        raise MutationProvenanceError("authorized_at must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise MutationProvenanceError("authorized_at must be timezone-aware UTC")
    if value.utcoffset() != timedelta(0):
        raise MutationProvenanceError("authorized_at must be timezone-aware UTC")
    return value


@dataclass(frozen=True, slots=True)
class VerifiedMutationProvenance:
    """Immutable record of one verified-and-authorized mutation attempt.

    Construct this **only** inside the reviewed application orchestration
    method, after the actor has been independently verified and the exact
    Action for the bound target has received an authoritative ``ALLOW``.
    The constructor performs structural validation, not authentication:
    accepting one of these fields as a caller-supplied identifier is never
    proof that the actor was verified or authorized.

    Fields are immutable and no public ``from_actor_id``/``trusted`` factory
    exists. ``operation_id`` is a per-attempt, server-generated UUID (not a
    client idempotency key); ``target_kind`` and ``target_id`` identify the
    logical object; ``authorized_at`` must be a timezone-aware UTC instant.
    """

    operation_id: UUID
    actor_identity_id: DomainId
    actor_principal_id: DomainId
    tenant_id: DomainId
    application_id: DomainId
    action_urn: ActionUrn
    target_kind: str
    target_id: DomainId
    authorized_at: datetime

    def __post_init__(self) -> None:
        _require_uuid("operation_id", self.operation_id)
        _require_domain_id("actor_identity_id", self.actor_identity_id)
        _require_domain_id("actor_principal_id", self.actor_principal_id)
        _require_domain_id("tenant_id", self.tenant_id)
        _require_domain_id("application_id", self.application_id)
        _require_action_urn(self.action_urn)
        _require_target_kind(self.target_kind)
        _require_domain_id("target_id", self.target_id)
        _require_utc(self.authorized_at)

    @property
    def authorized_at_utc(self) -> datetime:
        """Return ``authorized_at`` normalized to the canonical UTC zone.

        The validated instant is offset-zero; this only re-labels the same
        instant with :data:`datetime.UTC` for stable formatting/comparison.
        """
        return self.authorized_at.astimezone(UTC)


def registered_mutations() -> Mapping[str, frozenset[str]]:
    """Return the currently approved ``target_kind`` -> Action-URN mapping.

    The returned mapping is read-only. Since PR 19C it registers exactly
    ``identity_group_membership`` with the single approved membership-add
    Action.
    """
    return _MIGRATED_MUTATIONS


def require_registered_mutation(provenance: VerifiedMutationProvenance) -> None:
    """Fail closed unless the target-kind/Action pairing is approved.

    This is the guard a reviewed orchestration path must call before passing
    provenance to persistence. It is intentionally separate from
    construction: structural validity never implies that the database write
    is covered by an approved audit path.

    :raises UnregisteredMutationError: when ``target_kind`` is not
        registered or the exact Action URN is not approved for it.
    """
    allowed = _MIGRATED_MUTATIONS.get(provenance.target_kind)
    if allowed is None:
        raise UnregisteredMutationError(
            f"target kind {provenance.target_kind!r} is not an approved mutation target"
        )
    if provenance.action_urn.value not in allowed:
        raise UnregisteredMutationError(
            f"Action {provenance.action_urn.value!r} is not approved for target kind "
            f"{provenance.target_kind!r}"
        )
