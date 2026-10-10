"""Identity domain entity.

An Identity is a concrete identity associated with exactly one
Principal. It is a global object: it has no owning Tenant, Tenant list,
Group list, or Organization list. Tenant usability is explicit only
through IdentityTenantMembership relationships, independent of sibling
Identities of the same Principal.

PR 10 adds the explicit immutable :class:`IdentityOrigin` classification
(``LOCAL``/``FEDERATED``). It is a stable attribute, not an IdP or
credential implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, new_extension
from mtmf_core.domain.lifecycle import DeletionStatus, IdentityOrigin
from mtmf_core.domain.mixins import ImmutableFieldGuard, SoftDeletableMixin


@dataclass(slots=True)
class Identity(ImmutableFieldGuard, SoftDeletableMixin):
    """A concrete identity belonging to exactly one Principal.

    :attr:`id`, the structural :attr:`principal_id`, and the immutable
    :attr:`origin` classification cannot be replaced. :attr:`name` is
    mutable, non-unique presentation metadata. ``origin`` is an explicit
    LOCAL/FEDERATED classification and is never inferred from a name,
    email, UUID, or external-login availability.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"id", "principal_id", "origin"})

    id: DomainId
    principal_id: DomainId
    name: str
    origin: IdentityOrigin
    deletion_status: DeletionStatus = DeletionStatus.NOT_DELETED
    extension: JsonObject = field(default_factory=new_extension)
