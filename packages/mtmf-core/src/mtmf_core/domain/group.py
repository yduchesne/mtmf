"""Group domain entity.

A Group is a tenant-bound collection of Identities exposed through
IdentityGroupMembership. Groups have TENANT security scope and must not
embed members directly; nested Groups and Principal membership remain
UNRESOLVED and are not represented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, new_extension
from mtmf_core.domain.lifecycle import DeletionStatus
from mtmf_core.domain.mixins import ImmutableFieldGuard, SoftDeletableMixin
from mtmf_core.domain.scope import SecurityScope


@dataclass(slots=True)
class Group(ImmutableFieldGuard, SoftDeletableMixin):
    """A tenant-bound collection of Identities.

    :attr:`id` and the structural :attr:`tenant_id` cannot be replaced.
    :attr:`name` is mutable, non-unique presentation metadata.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"id", "tenant_id"})

    id: DomainId
    tenant_id: DomainId
    name: str
    deletion_status: DeletionStatus = DeletionStatus.NOT_DELETED
    extension: JsonObject = field(default_factory=new_extension)

    @property
    def scope(self) -> SecurityScope:
        """Every Group carries TENANT security scope."""
        return SecurityScope.TENANT
