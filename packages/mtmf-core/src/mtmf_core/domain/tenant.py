"""Tenant domain entity.

A Tenant is the primary tenancy and security boundary. Exactly one root
Tenant is created during bootstrap (PR 10 owns bootstrap/root invariants);
this representation only records the settled legal scope values and does
not invent any global root-uniqueness mechanism.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from mtmf_core.domain.errors import DomainInvariantError
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, new_extension
from mtmf_core.domain.lifecycle import DeletionStatus
from mtmf_core.domain.mixins import ImmutableFieldGuard, SoftDeletableMixin
from mtmf_core.domain.scope import SecurityScope


@dataclass(slots=True)
class Tenant(ImmutableFieldGuard, SoftDeletableMixin):
    """A primary tenancy/security boundary.

    The stable :attr:`id` and the immutable creator
    :attr:`owner_identity_id` (provenance only) cannot be replaced.
    :attr:`name` is mutable, non-unique presentation metadata.

    :param scope: :attr:`SecurityScope.ROOT` for the single root Tenant
        or :attr:`SecurityScope.TENANT` for every ordinary Tenant.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"id", "owner_identity_id"})

    id: DomainId
    name: str
    scope: SecurityScope
    owner_identity_id: DomainId
    deletion_status: DeletionStatus = DeletionStatus.NOT_DELETED
    extension: JsonObject = field(default_factory=new_extension)

    def __post_init__(self) -> None:
        if self.scope not in (SecurityScope.ROOT, SecurityScope.TENANT):
            raise DomainInvariantError(
                "Tenant scope must be ROOT or TENANT: the unique root Tenant is ROOT "
                "and every ordinary Tenant is TENANT"
            )
