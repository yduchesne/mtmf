"""Identity domain entity.

An Identity is a concrete identity associated with exactly one
Principal. It is a global object: it has no owning Tenant, Tenant list,
Group list, or Organization list. Tenant usability is explicit only
through IdentityTenantMembership relationships, independent of sibling
Identities of the same Principal.

The exact external/federated Identity representation is deferred to IdP
design (PR 9 territory) and is deliberately not represented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, new_extension
from mtmf_core.domain.lifecycle import DeletionStatus
from mtmf_core.domain.mixins import ImmutableFieldGuard, SoftDeletableMixin


@dataclass(slots=True)
class Identity(ImmutableFieldGuard, SoftDeletableMixin):
    """A concrete identity belonging to exactly one Principal.

    :attr:`id` and the structural :attr:`principal_id` cannot be
    replaced. :attr:`name` is mutable, non-unique presentation metadata.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"id", "principal_id"})

    id: DomainId
    principal_id: DomainId
    name: str
    deletion_status: DeletionStatus = DeletionStatus.NOT_DELETED
    extension: JsonObject = field(default_factory=new_extension)
