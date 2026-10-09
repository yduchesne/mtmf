"""Typed repository contracts for the MTMF persistence SPI.

Repositories expose domain persistence operations only. They never
expose rows, SQL, query objects, cursors, connections, or driver
exceptions, and they persist state rather than authorize: no
SessionContext, AuthorizationRequest, Permission, Action, or acting
Identity is passed to a repository operation to make an authorization
decision.

Entity operations use immutable domain identities:

- UUID-identified aggregate roots support ``add``, ``get``, ``save``;
- Role is persisted as one ``Role -> PermissionSet -> Permission``
  aggregate owned by its Role URN;
- Action is a shared exact definition identified by its immutable
  Action URN.

Typed memberships remain typed relationships: there is no polymorphic
``member_type``/``member_id`` persistence model, no surrogate identity,
and no generic hard-delete semantics (soft deletion is domain state
persisted through ``save``).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mtmf_core.domain.action import Action
from mtmf_core.domain.group import Group
from mtmf_core.domain.iam_urn import ActionUrn, RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.memberships import (
    GroupOrgMembership,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityTenantMembership,
    PrincipalTenantMembership,
)
from mtmf_core.domain.organization import Organization
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.role import Role
from mtmf_core.domain.role_assignment import GroupRoleAssignment, IdentityRoleAssignment
from mtmf_core.domain.tenant import Tenant


@runtime_checkable
class TenantRepository(Protocol):
    """Persistence operations for :class:`~mtmf_core.domain.tenant.Tenant`."""

    def add(self, tenant: Tenant) -> None:
        """Stage a new Tenant identity."""
        ...

    def get(self, id: DomainId) -> Tenant | None:
        """Return the Tenant with ``id``, or ``None`` when unknown."""
        ...

    def save(self, tenant: Tenant) -> None:
        """Stage an update to an existing Tenant identity."""
        ...


@runtime_checkable
class OrganizationRepository(Protocol):
    """Persistence operations for :class:`~mtmf_core.domain.organization.Organization`."""

    def add(self, organization: Organization) -> None:
        """Stage a new Organization identity."""
        ...

    def get(self, id: DomainId) -> Organization | None:
        """Return the Organization with ``id``, or ``None`` when unknown."""
        ...

    def save(self, organization: Organization) -> None:
        """Stage an update to an existing Organization identity."""
        ...


@runtime_checkable
class PrincipalRepository(Protocol):
    """Persistence operations for :class:`~mtmf_core.domain.principal.Principal`."""

    def add(self, principal: Principal) -> None:
        """Stage a new Principal identity."""
        ...

    def get(self, id: DomainId) -> Principal | None:
        """Return the Principal with ``id``, or ``None`` when unknown."""
        ...

    def save(self, principal: Principal) -> None:
        """Stage an update to an existing Principal identity."""
        ...


@runtime_checkable
class IdentityRepository(Protocol):
    """Persistence operations for :class:`~mtmf_core.domain.identity_entity.Identity`."""

    def add(self, identity: Identity) -> None:
        """Stage a new Identity identity."""
        ...

    def get(self, id: DomainId) -> Identity | None:
        """Return the Identity with ``id``, or ``None`` when unknown."""
        ...

    def save(self, identity: Identity) -> None:
        """Stage an update to an existing Identity identity."""
        ...


@runtime_checkable
class GroupRepository(Protocol):
    """Persistence operations for :class:`~mtmf_core.domain.group.Group`."""

    def add(self, group: Group) -> None:
        """Stage a new Group identity."""
        ...

    def get(self, id: DomainId) -> Group | None:
        """Return the Group with ``id``, or ``None`` when unknown."""
        ...

    def save(self, group: Group) -> None:
        """Stage an update to an existing Group identity."""
        ...


@runtime_checkable
class RoleRepository(Protocol):
    """Persistence operations for the :class:`~mtmf_core.domain.role.Role` aggregate.

    A Role owns its ordered PermissionSets, which in turn own their
    Permissions; the whole aggregate is added, loaded, and saved
    atomically. PermissionSets and Permissions are not independently
    assignable aggregates.
    """

    def add(self, role: Role) -> None:
        """Stage a new Role aggregate keyed by its immutable Role URN."""
        ...

    def get(self, urn: RoleUrn) -> Role | None:
        """Return the Role aggregate with canonical URN, or ``None`` when unknown."""
        ...

    def save(self, role: Role) -> None:
        """Stage an update to an existing Role aggregate."""
        ...


@runtime_checkable
class IdentityRoleAssignmentRepository(Protocol):
    """Persistence for :class:`~mtmf_core.domain.role_assignment.IdentityRoleAssignment`.

    Assignments are physical current-state facts with an immutable
    surrogate identity. ``add`` rejects a duplicate surrogate identity and
    a duplicate logical assignment tuple ``(tenant, identity, role,
    organization)`` (with a NULL organization treated as a real, distinct
    value). ``remove`` physically deletes exactly the addressed assignment
    and reports an unknown identity as
    :class:`~mtmf_core.persistence.errors.UnknownPersistenceIdentityError`;
    there is no history or tombstone in PR 9. Reads are detached snapshots
    and add/get are always scoped by the caller's Tenant and subject.
    """

    def add(self, assignment: IdentityRoleAssignment) -> None:
        """Stage a new direct Identity Role assignment."""
        ...

    def get(self, id: DomainId) -> IdentityRoleAssignment | None:
        """Return the assignment with ``id``, or ``None`` when unknown."""
        ...

    def find_by_tenant_and_identity(
        self, tenant_id: DomainId, identity_id: DomainId
    ) -> tuple[IdentityRoleAssignment, ...]:
        """Return every assignment of one Identity in exactly one Tenant."""
        ...

    def remove(self, id: DomainId) -> None:
        """Physically remove one assignment, rejecting an unknown identity."""
        ...


@runtime_checkable
class GroupRoleAssignmentRepository(Protocol):
    """Persistence for :class:`~mtmf_core.domain.role_assignment.GroupRoleAssignment`.

    Assignments are physical current-state facts with an immutable
    surrogate identity. ``add`` rejects a duplicate surrogate identity and
    a duplicate logical assignment tuple ``(tenant, group, role,
    organization)`` (with a NULL organization treated as a real, distinct
    value). ``remove`` physically deletes exactly the addressed assignment
    and reports an unknown identity as
    :class:`~mtmf_core.persistence.errors.UnknownPersistenceIdentityError`.
    Reads are detached snapshots scoped by the caller's Tenant and Group.
    """

    def add(self, assignment: GroupRoleAssignment) -> None:
        """Stage a new Group Role assignment."""
        ...

    def get(self, id: DomainId) -> GroupRoleAssignment | None:
        """Return the assignment with ``id``, or ``None`` when unknown."""
        ...

    def find_by_tenant_and_group(
        self, tenant_id: DomainId, group_id: DomainId
    ) -> tuple[GroupRoleAssignment, ...]:
        """Return every assignment of one Group in exactly one Tenant."""
        ...

    def remove(self, id: DomainId) -> None:
        """Physically remove one assignment, rejecting an unknown identity."""
        ...


@runtime_checkable
class ActionRepository(Protocol):
    """Persistence operations for the shared exact :class:`~mtmf_core.domain.action.Action`.

    An Action's canonical identity is its immutable exact Action URN;
    wildcards can never appear in an Action URN. An Action carries no
    mutable state, so only ``add`` and ``get`` exist.
    """

    def add(self, action: Action) -> None:
        """Stage a new Action definition keyed by its exact Action URN."""
        ...

    def get(self, urn: ActionUrn) -> Action | None:
        """Return the Action with exact URN, or ``None`` when unknown."""
        ...


@runtime_checkable
class PrincipalTenantMembershipRepository(Protocol):
    """Persistence for :class:`~mtmf_core.domain.memberships.PrincipalTenantMembership`."""

    def add(self, membership: PrincipalTenantMembership) -> None:
        """Stage a new typed Principal-Tenant membership fact."""
        ...

    def get(self, principal_id: DomainId, tenant_id: DomainId) -> PrincipalTenantMembership | None:
        """Return the exact membership fact, or ``None`` when unknown."""
        ...

    def find_by_principal(self, principal_id: DomainId) -> tuple[PrincipalTenantMembership, ...]:
        """Return every membership fact of one Principal."""
        ...

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[PrincipalTenantMembership, ...]:
        """Return every Principal membership fact in one Tenant."""
        ...


@runtime_checkable
class IdentityTenantMembershipRepository(Protocol):
    """Persistence for :class:`~mtmf_core.domain.memberships.IdentityTenantMembership`."""

    def add(self, membership: IdentityTenantMembership) -> None:
        """Stage a new typed Identity-Tenant membership fact."""
        ...

    def get(self, identity_id: DomainId, tenant_id: DomainId) -> IdentityTenantMembership | None:
        """Return the exact membership fact, or ``None`` when unknown."""
        ...

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityTenantMembership, ...]:
        """Return every membership fact of one Identity."""
        ...

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[IdentityTenantMembership, ...]:
        """Return every Identity membership fact in one Tenant."""
        ...


@runtime_checkable
class GroupTenantMembershipRepository(Protocol):
    """Persistence for :class:`~mtmf_core.domain.memberships.GroupTenantMembership`."""

    def add(self, membership: GroupTenantMembership) -> None:
        """Stage a new typed Group-Tenant membership fact."""
        ...

    def get(self, group_id: DomainId, tenant_id: DomainId) -> GroupTenantMembership | None:
        """Return the exact membership fact, or ``None`` when unknown."""
        ...

    def find_by_group(self, group_id: DomainId) -> tuple[GroupTenantMembership, ...]:
        """Return every membership fact of one Group."""
        ...

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[GroupTenantMembership, ...]:
        """Return every Group membership fact in one Tenant."""
        ...


@runtime_checkable
class IdentityGroupMembershipRepository(Protocol):
    """Persistence for :class:`~mtmf_core.domain.memberships.IdentityGroupMembership`."""

    def add(self, membership: IdentityGroupMembership) -> None:
        """Stage a new typed Identity-Group membership fact."""
        ...

    def get(self, identity_id: DomainId, group_id: DomainId) -> IdentityGroupMembership | None:
        """Return the exact membership fact, or ``None`` when unknown."""
        ...

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityGroupMembership, ...]:
        """Return every membership fact of one Identity."""
        ...

    def find_by_group(self, group_id: DomainId) -> tuple[IdentityGroupMembership, ...]:
        """Return every Identity membership fact of one Group."""
        ...


@runtime_checkable
class IdentityOrgMembershipRepository(Protocol):
    """Persistence for :class:`~mtmf_core.domain.memberships.IdentityOrgMembership`."""

    def add(self, membership: IdentityOrgMembership) -> None:
        """Stage a new typed Identity-Organization membership fact."""
        ...

    def get(self, identity_id: DomainId, organization_id: DomainId) -> IdentityOrgMembership | None:
        """Return the exact membership fact, or ``None`` when unknown."""
        ...

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityOrgMembership, ...]:
        """Return every membership fact of one Identity."""
        ...

    def find_by_organization(self, organization_id: DomainId) -> tuple[IdentityOrgMembership, ...]:
        """Return every Identity membership fact of one Organization."""
        ...


@runtime_checkable
class GroupOrgMembershipRepository(Protocol):
    """Persistence for :class:`~mtmf_core.domain.memberships.GroupOrgMembership`."""

    def add(self, membership: GroupOrgMembership) -> None:
        """Stage a new typed Group-Organization membership fact."""
        ...

    def get(self, group_id: DomainId, organization_id: DomainId) -> GroupOrgMembership | None:
        """Return the exact membership fact, or ``None`` when unknown."""
        ...

    def find_by_group(self, group_id: DomainId) -> tuple[GroupOrgMembership, ...]:
        """Return every membership fact of one Group."""
        ...

    def find_by_organization(self, organization_id: DomainId) -> tuple[GroupOrgMembership, ...]:
        """Return every Group membership fact of one Organization."""
        ...
