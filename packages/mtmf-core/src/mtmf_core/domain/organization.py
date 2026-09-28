"""Organization domain entity.

An Organization belongs to exactly one Tenant and carries immutable
creator-Identity ownership. Organization creation must atomically
establish the owner's IdentityOrgMembership; PR 2 models and validates
that relationship but deliberately introduces no application/persistence
transaction (that is a persistence PR concern).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, new_extension
from mtmf_core.domain.lifecycle import DeletionStatus
from mtmf_core.domain.mixins import ImmutableFieldGuard, SoftDeletableMixin


@dataclass(slots=True)
class Organization(ImmutableFieldGuard, SoftDeletableMixin):
    """A subdivision of exactly one Tenant.

    :attr:`id`, the structural :attr:`tenant_id`, and the immutable
    creator :attr:`owner_identity_id` cannot be replaced. :attr:`name`
    is mutable, non-unique presentation metadata.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {"id", "tenant_id", "owner_identity_id"}
    )

    id: DomainId
    tenant_id: DomainId
    name: str
    owner_identity_id: DomainId
    deletion_status: DeletionStatus = DeletionStatus.NOT_DELETED
    extension: JsonObject = field(default_factory=new_extension)
