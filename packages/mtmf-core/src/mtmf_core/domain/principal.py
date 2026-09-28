"""Principal domain entity.

A Principal is the underlying account or actor represented by MTMF. It
is a global object: it has no owning Tenant and no Organization/Group
ownership fields or Role assignments. Tenant participation is explicit
only through typed PrincipalTenantMembership relationships.

Principal kinds (human/service/agent) remain UNRESOLVED and are not
represented here. The mandatory local MTMF Identity requirement is
enforced by later bootstrap PRs, not by invented federation fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, new_extension
from mtmf_core.domain.lifecycle import DeletionStatus
from mtmf_core.domain.mixins import ImmutableFieldGuard, SoftDeletableMixin


@dataclass(slots=True)
class Principal(ImmutableFieldGuard, SoftDeletableMixin):
    """A global MTMF account/actor with one or more Identities.

    :attr:`id` cannot be replaced. :attr:`name` is mutable, non-unique
    presentation metadata.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"id"})

    id: DomainId
    name: str
    deletion_status: DeletionStatus = DeletionStatus.NOT_DELETED
    extension: JsonObject = field(default_factory=new_extension)
