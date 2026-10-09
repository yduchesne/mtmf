"""Typed, Tenant-bound Role assignments (PR 9).

MTMF uses two explicit assignment entities rather than a polymorphic
``(subject_type, subject_id)`` relationship:

- :class:`IdentityRoleAssignment` assigns a Role directly to an Identity;
- :class:`GroupRoleAssignment` assigns a Role to a Group (from which its
  member Identities derive the Role).

Every assignment is bound to exactly one Tenant and may optionally refine
that context to an Organization belonging to the same Tenant. The
assignment identity ``id``, the structural ``tenant_id``/subject, the
target ``role_urn``, and the optional ``organization_id`` are all
immutable. The entity carries no mutable state, so assignment rows are
physical current-state facts: revoking an assignment removes its row and
a later regrant uses a new UUID.

Assignment entities are structural persistence facts only. They do not
authorize anything: authenticating and authorizing grant/revoke
operations belongs to the application layer, and possessing a repository
does not confer the authority to call it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.mixins import ImmutableFieldGuard

__all__ = [
    "GroupRoleAssignment",
    "IdentityRoleAssignment",
]


@dataclass(slots=True)
class IdentityRoleAssignment(ImmutableFieldGuard):
    """A Role assigned directly to one Identity in one Tenant context.

    :attr:`id` is the immutable assignment identity; :attr:`tenant_id`
    and :attr:`identity_id` are the immutable assignment context;
    :attr:`role_urn` is the assigned Role's immutable URN; and
    :attr:`organization_id` optionally refines the context to an
    Organization belonging to :attr:`tenant_id` (``None`` means
    Tenant-wide). None of these may be replaced.

    The subject is always an Identity: there is no polymorphic
    ``subject_type``/``subject_id`` target and no implicit Principal
    assignment. Cross-field prerequisites (an active Identity-Tenant
    membership, and an Organization that belongs to the assignment
    Tenant) are validated by the pure validators in
    :mod:`mtmf_core.domain.invariants` and enforced again at the trusted
    persistence boundary.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {"id", "tenant_id", "identity_id", "role_urn", "organization_id"}
    )

    id: DomainId
    tenant_id: DomainId
    identity_id: DomainId
    role_urn: RoleUrn
    organization_id: DomainId | None = None


@dataclass(slots=True)
class GroupRoleAssignment(ImmutableFieldGuard):
    """A Role assigned to one Group in one Tenant context.

    :attr:`id` is the immutable assignment identity; :attr:`tenant_id`
    and :attr:`group_id` are the immutable assignment context;
    :attr:`role_urn` is the assigned Role's immutable URN; and
    :attr:`organization_id` optionally refines the context to an
    Organization belonging to :attr:`tenant_id` (``None`` means
    Tenant-wide). None of these may be replaced.

    The subject is always a Group: there is no polymorphic target. An
    Identity derives this Role only through a same-Tenant
    IdentityGroupMembership, and no Identity of the Group's Tenant
    inherits the assignment otherwise.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {"id", "tenant_id", "group_id", "role_urn", "organization_id"}
    )

    id: DomainId
    tenant_id: DomainId
    group_id: DomainId
    role_urn: RoleUrn
    organization_id: DomainId | None = None
