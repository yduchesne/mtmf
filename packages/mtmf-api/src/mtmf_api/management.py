"""Detached public DTOs for the PR 19C management membership-add operation.

These are immutable, transport-independent snapshots. They import no core,
SQL, FastAPI or service package and expose no live domain object. The
request carries only the three target identifiers; it never carries an
actor, Principal, Application, Action, Role, Permission, steward flag,
audit field or policy decision.

Nothing here authenticates, authorizes, resolves policy or performs I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from mtmf_api.errors import ApiContractValidationError

__all__ = [
    "IdentityGroupMembershipAddRequest",
    "IdentityGroupMembershipAddResponse",
]


def _require_uuid(value: object, field: str) -> UUID:
    if not isinstance(value, UUID):
        raise ApiContractValidationError(f"{field} must be a UUID")
    if value.int == 0:
        raise ApiContractValidationError(f"{field} must not be the nil UUID")
    return value


@dataclass(frozen=True, slots=True)
class IdentityGroupMembershipAddRequest:
    """One detached membership-add request.

    ``tenant_id`` is a requested context selector, never proof of
    membership; the verified service reconciles it against the persisted
    actor and target state.
    """

    tenant_id: UUID
    identity_id: UUID
    group_id: UUID

    def __post_init__(self) -> None:
        _require_uuid(self.tenant_id, "tenant_id")
        _require_uuid(self.identity_id, "identity_id")
        _require_uuid(self.group_id, "group_id")


@dataclass(frozen=True, slots=True)
class IdentityGroupMembershipAddResponse:
    """One detached membership-add result.

    ``created`` is ``True`` for a newly committed membership and ``False``
    for an authorized idempotent no-op. It never exposes an audit id,
    operation id, actor or policy detail.
    """

    tenant_id: UUID
    identity_id: UUID
    group_id: UUID
    created: bool

    def __post_init__(self) -> None:
        _require_uuid(self.tenant_id, "tenant_id")
        _require_uuid(self.identity_id, "identity_id")
        _require_uuid(self.group_id, "group_id")
        if not isinstance(self.created, bool):
            raise ApiContractValidationError("created must be a boolean")
