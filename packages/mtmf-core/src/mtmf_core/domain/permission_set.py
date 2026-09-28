"""PermissionSet: a Role-owned ALLOW/DENY effect carrier with Permissions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from mtmf_core.domain.errors import DomainInvariantError
from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.mixins import ImmutableFieldGuard
from mtmf_core.domain.permission import Permission
from mtmf_core.domain.policy import PermissionEffect


@dataclass(slots=True)
class PermissionSet(ImmutableFieldGuard):
    """A Policy component owned by exactly one Role.

    Carries one :attr:`effect` (ALLOW or DENY), owns an ordered,
    non-empty list of Permissions, and has an immutable UUID object
    identity. The owning Role is identified by its canonical Role URN.
    PermissionSet ordering is structural and must never influence
    authorization precedence.

    Every owned Permission must point back at this PermissionSet's
    immutable ``id``; a mismatched owner is rejected and never
    auto-reparented.

    A PermissionSet has no name, description, extension, security
    scope, or assignment context, and it is not independently
    assignable.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"id", "role_urn", "effect"})

    id: DomainId
    role_urn: RoleUrn
    effect: PermissionEffect
    permissions: tuple[Permission, ...]

    def __post_init__(self) -> None:
        if not self.permissions:
            raise DomainInvariantError("a PermissionSet must own at least one Permission")
        for permission in self.permissions:
            if permission.permission_set_id != self.id:
                raise DomainInvariantError(
                    "owned Permission points at a different PermissionSet; "
                    "mismatched ownership is rejected and never auto-reparented"
                )
