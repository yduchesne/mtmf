"""Concrete PostgreSQL repositories for the MTMF persistence SPI.

Every repository operation calls exactly one reviewed, schema-qualified,
owner-owned ``SECURITY DEFINER`` stored function through the owning
:class:`~mtmf_core.persistence.postgres.unit_of_work.PostgresUnitOfWork`.
No repository issues table DML or a raw table ``SELECT`` from the
restricted runtime login, and no repository exposes a row, cursor,
connection, or driver exception.

Semantics mirror the provider-neutral contracts and the deterministic
in-memory provider:

- ``add`` inserts a new immutable identity and reports a duplicate
  (committed or staged in the same transaction) as
  :class:`~mtmf_core.persistence.errors.DuplicatePersistenceIdentityError`;
- ``save`` updates an existing identity and reports an unknown identity
  as :class:`~mtmf_core.persistence.errors.UnknownPersistenceIdentityError`;
  it never silently creates or replaces an identity;
- ``get`` returns ``None`` only for a genuinely absent identity;
- detached domain objects are rebuilt from strict JSON payloads;
- typed membership repositories expose no removal operation;
- the whole ``Role -> PermissionSet -> Permission`` aggregate is written
  by a single stored-function call inside the caller's transaction.
"""

from __future__ import annotations

from typing import ClassVar

from psycopg.types.json import Jsonb

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
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    PersistenceIntegrityError,
    UnknownPersistenceIdentityError,
)
from mtmf_core.persistence.postgres.mapping import (
    group_from_payload,
    group_role_assignment_from_payload,
    identity_from_payload,
    identity_role_assignment_from_payload,
    organization_from_payload,
    principal_from_payload,
    role_from_payload,
    role_to_payload,
    tenant_from_payload,
)
from mtmf_core.persistence.postgres.unit_of_work import PostgresUnitOfWork

__all__ = [
    "PostgresActionRepository",
    "PostgresGroupOrgMembershipRepository",
    "PostgresGroupRepository",
    "PostgresGroupRoleAssignmentRepository",
    "PostgresGroupTenantMembershipRepository",
    "PostgresIdentityGroupMembershipRepository",
    "PostgresIdentityOrgMembershipRepository",
    "PostgresIdentityRepository",
    "PostgresIdentityRoleAssignmentRepository",
    "PostgresIdentityTenantMembershipRepository",
    "PostgresOrganizationRepository",
    "PostgresPrincipalRepository",
    "PostgresPrincipalTenantMembershipRepository",
    "PostgresRoleRepository",
    "PostgresTenantRepository",
]


def _extension_param(extension: object) -> Jsonb:
    """Wrap an extension value, rejecting a non-object before any SQL runs."""
    if not isinstance(extension, dict):
        raise PersistenceIntegrityError(
            "an application extension must be a JSON object, not a scalar, list, or null"
        )
    return Jsonb(extension)


class _Repository:
    """Shared private execution helpers for PostgreSQL repositories."""

    def __init__(self, uow: PostgresUnitOfWork) -> None:
        self._uow = uow

    def _bool(self, query: str, params: tuple[object, ...]) -> bool:
        """Run a reviewed function returning one boolean."""
        row = self._uow._execute(query, params).fetchone()
        return bool(row is not None and row[0])

    def _payload(self, query: str, params: tuple[object, ...]) -> object | None:
        """Run a reviewed function returning one JSON object or SQL NULL."""
        row = self._uow._execute(query, params).fetchone()
        return None if row is None else row[0]

    def _uuids(self, query: str, params: tuple[object, ...]) -> tuple[DomainId, ...]:
        """Run a reviewed ``SETOF uuid`` function and return detached identifiers."""
        rows = self._uow._execute(query, params).fetchall()
        return tuple(DomainId(row[0]) for row in rows)


class PostgresTenantRepository(_Repository):
    """PostgreSQL :class:`~mtmf_core.persistence.repositories.TenantRepository`."""

    def add(self, tenant: Tenant) -> None:
        """Stage a new Tenant, rejecting an existing immutable identity."""
        added = self._bool(
            "SELECT mtmf.tenant_add(%s, %s, %s, %s, %s, %s)",
            (
                tenant.id.value,
                tenant.name,
                int(tenant.scope),
                tenant.owner_identity_id.value,
                int(tenant.deletion_status),
                _extension_param(tenant.extension),
            ),
        )
        if not added:
            raise DuplicatePersistenceIdentityError(
                f"Tenant: identity {tenant.id!r} already exists"
            )

    def get(self, id: DomainId) -> Tenant | None:
        """Return the Tenant with ``id``, or ``None`` when unknown."""
        payload = self._payload("SELECT mtmf.tenant_get(%s)", (id.value,))
        return None if payload is None else tenant_from_payload(payload)

    def save(self, tenant: Tenant) -> None:
        """Stage an update to an existing Tenant identity."""
        updated = self._bool(
            "SELECT mtmf.tenant_save(%s, %s, %s, %s)",
            (
                tenant.id.value,
                tenant.name,
                int(tenant.deletion_status),
                _extension_param(tenant.extension),
            ),
        )
        if not updated:
            raise UnknownPersistenceIdentityError(
                f"Tenant: cannot save unknown identity {tenant.id!r}; "
                "introduce new identities with add"
            )


class PostgresOrganizationRepository(_Repository):
    """PostgreSQL :class:`~mtmf_core.persistence.repositories.OrganizationRepository`."""

    def add(self, organization: Organization) -> None:
        """Stage a new Organization, rejecting an existing immutable identity."""
        added = self._bool(
            "SELECT mtmf.organization_add(%s, %s, %s, %s, %s, %s)",
            (
                organization.id.value,
                organization.tenant_id.value,
                organization.name,
                organization.owner_identity_id.value,
                int(organization.deletion_status),
                _extension_param(organization.extension),
            ),
        )
        if not added:
            raise DuplicatePersistenceIdentityError(
                f"Organization: identity {organization.id!r} already exists"
            )

    def get(self, id: DomainId) -> Organization | None:
        """Return the Organization with ``id``, or ``None`` when unknown."""
        payload = self._payload("SELECT mtmf.organization_get(%s)", (id.value,))
        return None if payload is None else organization_from_payload(payload)

    def save(self, organization: Organization) -> None:
        """Stage an update to an existing Organization identity."""
        updated = self._bool(
            "SELECT mtmf.organization_save(%s, %s, %s, %s)",
            (
                organization.id.value,
                organization.name,
                int(organization.deletion_status),
                _extension_param(organization.extension),
            ),
        )
        if not updated:
            raise UnknownPersistenceIdentityError(
                f"Organization: cannot save unknown identity {organization.id!r}; "
                "introduce new identities with add"
            )


class PostgresPrincipalRepository(_Repository):
    """PostgreSQL :class:`~mtmf_core.persistence.repositories.PrincipalRepository`."""

    def add(self, principal: Principal) -> None:
        """Stage a new Principal, rejecting an existing immutable identity."""
        added = self._bool(
            "SELECT mtmf.principal_add(%s, %s, %s, %s)",
            (
                principal.id.value,
                principal.name,
                int(principal.deletion_status),
                _extension_param(principal.extension),
            ),
        )
        if not added:
            raise DuplicatePersistenceIdentityError(
                f"Principal: identity {principal.id!r} already exists"
            )

    def get(self, id: DomainId) -> Principal | None:
        """Return the Principal with ``id``, or ``None`` when unknown."""
        payload = self._payload("SELECT mtmf.principal_get(%s)", (id.value,))
        return None if payload is None else principal_from_payload(payload)

    def save(self, principal: Principal) -> None:
        """Stage an update to an existing Principal identity."""
        updated = self._bool(
            "SELECT mtmf.principal_save(%s, %s, %s, %s)",
            (
                principal.id.value,
                principal.name,
                int(principal.deletion_status),
                _extension_param(principal.extension),
            ),
        )
        if not updated:
            raise UnknownPersistenceIdentityError(
                f"Principal: cannot save unknown identity {principal.id!r}; "
                "introduce new identities with add"
            )


class PostgresIdentityRepository(_Repository):
    """PostgreSQL :class:`~mtmf_core.persistence.repositories.IdentityRepository`."""

    def add(self, identity: Identity) -> None:
        """Stage a new Identity, rejecting an existing immutable identity."""
        added = self._bool(
            "SELECT mtmf.identity_add(%s, %s, %s, %s, %s)",
            (
                identity.id.value,
                identity.principal_id.value,
                identity.name,
                int(identity.deletion_status),
                _extension_param(identity.extension),
            ),
        )
        if not added:
            raise DuplicatePersistenceIdentityError(
                f"Identity: identity {identity.id!r} already exists"
            )

    def get(self, id: DomainId) -> Identity | None:
        """Return the Identity with ``id``, or ``None`` when unknown."""
        payload = self._payload("SELECT mtmf.identity_get(%s)", (id.value,))
        return None if payload is None else identity_from_payload(payload)

    def save(self, identity: Identity) -> None:
        """Stage an update to an existing Identity identity."""
        updated = self._bool(
            "SELECT mtmf.identity_save(%s, %s, %s, %s)",
            (
                identity.id.value,
                identity.name,
                int(identity.deletion_status),
                _extension_param(identity.extension),
            ),
        )
        if not updated:
            raise UnknownPersistenceIdentityError(
                f"Identity: cannot save unknown identity {identity.id!r}; "
                "introduce new identities with add"
            )


class PostgresGroupRepository(_Repository):
    """PostgreSQL :class:`~mtmf_core.persistence.repositories.GroupRepository`."""

    def add(self, group: Group) -> None:
        """Stage a new Group, rejecting an existing immutable identity."""
        added = self._bool(
            "SELECT mtmf.group_add(%s, %s, %s, %s, %s)",
            (
                group.id.value,
                group.tenant_id.value,
                group.name,
                int(group.deletion_status),
                _extension_param(group.extension),
            ),
        )
        if not added:
            raise DuplicatePersistenceIdentityError(f"Group: identity {group.id!r} already exists")

    def get(self, id: DomainId) -> Group | None:
        """Return the Group with ``id``, or ``None`` when unknown."""
        payload = self._payload("SELECT mtmf.group_get(%s)", (id.value,))
        return None if payload is None else group_from_payload(payload)

    def save(self, group: Group) -> None:
        """Stage an update to an existing Group identity."""
        updated = self._bool(
            "SELECT mtmf.group_save(%s, %s, %s, %s)",
            (
                group.id.value,
                group.name,
                int(group.deletion_status),
                _extension_param(group.extension),
            ),
        )
        if not updated:
            raise UnknownPersistenceIdentityError(
                f"Group: cannot save unknown identity {group.id!r}; "
                "introduce new identities with add"
            )


class PostgresRoleRepository(_Repository):
    """PostgreSQL :class:`~mtmf_core.persistence.repositories.RoleRepository`."""

    def add(self, role: Role) -> None:
        """Stage a new Role aggregate keyed by its immutable Role URN."""
        added = self._bool("SELECT mtmf.role_add(%s)", (Jsonb(role_to_payload(role)),))
        if not added:
            raise DuplicatePersistenceIdentityError(f"Role: URN {role.urn.value!r} already exists")

    def get(self, urn: RoleUrn) -> Role | None:
        """Return the Role aggregate with canonical ``urn``, or ``None``."""
        payload = self._payload("SELECT mtmf.role_get(%s)", (urn.value,))
        return None if payload is None else role_from_payload(payload)

    def save(self, role: Role) -> None:
        """Stage an update to an existing Role aggregate."""
        updated = self._bool("SELECT mtmf.role_save(%s)", (Jsonb(role_to_payload(role)),))
        if not updated:
            raise UnknownPersistenceIdentityError(
                f"Role: cannot save unknown URN {role.urn.value!r}; "
                "introduce new aggregates with add"
            )


class PostgresActionRepository(_Repository):
    """PostgreSQL :class:`~mtmf_core.persistence.repositories.ActionRepository`."""

    def add(self, action: Action) -> None:
        """Stage a new Action, rejecting one whose exact URN already exists."""
        added = self._bool("SELECT mtmf.action_add(%s)", (action.urn.value,))
        if not added:
            raise DuplicatePersistenceIdentityError(
                f"Action: URN {action.urn.value!r} already exists"
            )

    def get(self, urn: ActionUrn) -> Action | None:
        """Return the Action with exact ``urn``, or ``None`` when unknown."""
        present = self._bool("SELECT mtmf.action_get(%s)", (urn.value,))
        return Action(urn) if present else None


class _RoleAssignmentRepository[AssignmentT]:
    """Shared add/get/remove mechanics for one typed Role assignment."""

    _add_query: ClassVar[str]
    _get_query: ClassVar[str]
    _remove_query: ClassVar[str]
    _collection: ClassVar[str]
    _find_query: ClassVar[str]

    def __init__(self, uow: PostgresUnitOfWork) -> None:
        self._uow = uow

    def _add(self, params: tuple[object, ...]) -> None:
        row = self._uow._execute(self._add_query, params).fetchone()
        if not (row is not None and row[0]):
            raise DuplicatePersistenceIdentityError(
                f"{self._collection}: the requested assignment already exists"
            )

    def _get(self, key: object) -> dict[str, object] | None:
        row = self._uow._execute(self._get_query, (key,)).fetchone()
        if row is None or row[0] is None:
            return None
        payload = row[0]
        if not isinstance(payload, dict):
            raise PersistenceIntegrityError(
                f"{self._collection}: stored assignment payload is not a JSON object"
            )
        return payload

    def _find(self, params: tuple[object, ...]) -> tuple[AssignmentT, ...]:
        rows = self._uow._execute(self._find_query, params).fetchall()
        return tuple(self._from_payload(row[0]) for row in rows)

    def _from_payload(self, payload: object) -> AssignmentT:
        raise NotImplementedError

    def _remove(self, id: DomainId) -> None:
        row = self._uow._execute(self._remove_query, (id.value,)).fetchone()
        if not (row is not None and row[0]):
            raise UnknownPersistenceIdentityError(
                f"{self._collection}: cannot remove unknown identity {id!r}"
            )


class PostgresIdentityRoleAssignmentRepository(_RoleAssignmentRepository[IdentityRoleAssignment]):
    """PostgreSQL direct Identity Role-assignment repository."""

    _collection = "IdentityRoleAssignment"
    _add_query = "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, %s)"
    _get_query = "SELECT mtmf.identity_role_assignment_get(%s)"
    _find_query = "SELECT * FROM mtmf.identity_role_assignment_find_by_tenant_and_identity(%s, %s)"
    _remove_query = "SELECT mtmf.identity_role_assignment_remove(%s)"

    def _from_payload(self, payload: object) -> IdentityRoleAssignment:
        return identity_role_assignment_from_payload(payload)

    def add(self, assignment: IdentityRoleAssignment) -> None:
        """Stage a new direct Identity Role assignment."""
        self._add(
            (
                assignment.id.value,
                assignment.tenant_id.value,
                assignment.identity_id.value,
                assignment.role_urn.value,
                None if assignment.organization_id is None else assignment.organization_id.value,
            )
        )

    def get(self, id: DomainId) -> IdentityRoleAssignment | None:
        """Return the assignment with ``id``, or ``None`` when unknown."""
        payload = self._get(id.value)
        return None if payload is None else self._from_payload(payload)

    def find_by_tenant_and_identity(
        self, tenant_id: DomainId, identity_id: DomainId
    ) -> tuple[IdentityRoleAssignment, ...]:
        """Return every assignment of one Identity in exactly one Tenant."""
        return self._find((tenant_id.value, identity_id.value))

    def remove(self, id: DomainId) -> None:
        """Physically remove one assignment, rejecting an unknown identity."""
        self._remove(id)


class PostgresGroupRoleAssignmentRepository(_RoleAssignmentRepository[GroupRoleAssignment]):
    """PostgreSQL Group Role-assignment repository."""

    _collection = "GroupRoleAssignment"
    _add_query = "SELECT mtmf.group_role_assignment_add(%s, %s, %s, %s, %s)"
    _get_query = "SELECT mtmf.group_role_assignment_get(%s)"
    _find_query = "SELECT * FROM mtmf.group_role_assignment_find_by_tenant_and_group(%s, %s)"
    _remove_query = "SELECT mtmf.group_role_assignment_remove(%s)"

    def _from_payload(self, payload: object) -> GroupRoleAssignment:
        return group_role_assignment_from_payload(payload)

    def add(self, assignment: GroupRoleAssignment) -> None:
        """Stage a new Group Role assignment."""
        self._add(
            (
                assignment.id.value,
                assignment.tenant_id.value,
                assignment.group_id.value,
                assignment.role_urn.value,
                None if assignment.organization_id is None else assignment.organization_id.value,
            )
        )

    def get(self, id: DomainId) -> GroupRoleAssignment | None:
        """Return the assignment with ``id``, or ``None`` when unknown."""
        payload = self._get(id.value)
        return None if payload is None else self._from_payload(payload)

    def find_by_tenant_and_group(
        self, tenant_id: DomainId, group_id: DomainId
    ) -> tuple[GroupRoleAssignment, ...]:
        """Return every assignment of one Group in exactly one Tenant."""
        return self._find((tenant_id.value, group_id.value))

    def remove(self, id: DomainId) -> None:
        """Physically remove one assignment, rejecting an unknown identity."""
        self._remove(id)


class _MembershipRepository[MembershipT]:
    """Shared add/get mechanics for one typed membership relationship."""

    _add_query: ClassVar[str]
    _get_query: ClassVar[str]

    def __init__(self, uow: PostgresUnitOfWork) -> None:
        self._uow = uow

    def _add(self, first: DomainId, second: DomainId) -> None:
        row = self._uow._execute(self._add_query, (first.value, second.value)).fetchone()
        if not (row is not None and row[0]):
            raise DuplicatePersistenceIdentityError(
                f"{type(self).__name__}: relationship ({first!s}, {second!s}) already exists"
            )

    def _get(self, first: DomainId, second: DomainId) -> bool:
        row = self._uow._execute(self._get_query, (first.value, second.value)).fetchone()
        return bool(row is not None and row[0])

    def _find(self, query: str, value: DomainId) -> tuple[DomainId, ...]:
        rows = self._uow._execute(query, (value.value,)).fetchall()
        return tuple(DomainId(row[0]) for row in rows)


class PostgresPrincipalTenantMembershipRepository(_MembershipRepository[PrincipalTenantMembership]):
    """PostgreSQL Principal-Tenant membership repository."""

    _add_query = "SELECT mtmf.principal_tenant_membership_add(%s, %s)"
    _get_query = "SELECT mtmf.principal_tenant_membership_get(%s, %s)"

    def add(self, membership: PrincipalTenantMembership) -> None:
        """Stage a new typed Principal-Tenant membership fact."""
        self._add(membership.principal_id, membership.tenant_id)

    def get(self, principal_id: DomainId, tenant_id: DomainId) -> PrincipalTenantMembership | None:
        """Return the exact Principal-Tenant membership fact, or ``None``."""
        if not self._get(principal_id, tenant_id):
            return None
        return PrincipalTenantMembership(principal_id, tenant_id)

    def find_by_principal(self, principal_id: DomainId) -> tuple[PrincipalTenantMembership, ...]:
        """Return every membership fact of one Principal."""
        return tuple(
            PrincipalTenantMembership(principal_id, tenant_id)
            for tenant_id in self._find(
                "SELECT mtmf.principal_tenant_membership_find_by_principal(%s)", principal_id
            )
        )

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[PrincipalTenantMembership, ...]:
        """Return every Principal membership fact in one Tenant."""
        return tuple(
            PrincipalTenantMembership(principal_id, tenant_id)
            for principal_id in self._find(
                "SELECT mtmf.principal_tenant_membership_find_by_tenant(%s)", tenant_id
            )
        )


class PostgresIdentityTenantMembershipRepository(_MembershipRepository[IdentityTenantMembership]):
    """PostgreSQL Identity-Tenant membership repository."""

    _add_query = "SELECT mtmf.identity_tenant_membership_add(%s, %s)"
    _get_query = "SELECT mtmf.identity_tenant_membership_get(%s, %s)"

    def add(self, membership: IdentityTenantMembership) -> None:
        """Stage a new typed Identity-Tenant membership fact."""
        self._add(membership.identity_id, membership.tenant_id)

    def get(self, identity_id: DomainId, tenant_id: DomainId) -> IdentityTenantMembership | None:
        """Return the exact Identity-Tenant membership fact, or ``None``."""
        if not self._get(identity_id, tenant_id):
            return None
        return IdentityTenantMembership(identity_id, tenant_id)

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityTenantMembership, ...]:
        """Return every membership fact of one Identity."""
        return tuple(
            IdentityTenantMembership(identity_id, tenant_id)
            for tenant_id in self._find(
                "SELECT mtmf.identity_tenant_membership_find_by_identity(%s)", identity_id
            )
        )

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[IdentityTenantMembership, ...]:
        """Return every Identity membership fact in one Tenant."""
        return tuple(
            IdentityTenantMembership(identity_id, tenant_id)
            for identity_id in self._find(
                "SELECT mtmf.identity_tenant_membership_find_by_tenant(%s)", tenant_id
            )
        )


class PostgresGroupTenantMembershipRepository(_MembershipRepository[GroupTenantMembership]):
    """PostgreSQL Group-Tenant membership repository."""

    _add_query = "SELECT mtmf.group_tenant_membership_add(%s, %s)"
    _get_query = "SELECT mtmf.group_tenant_membership_get(%s, %s)"

    def add(self, membership: GroupTenantMembership) -> None:
        """Stage a new typed Group-Tenant membership fact."""
        self._add(membership.group_id, membership.tenant_id)

    def get(self, group_id: DomainId, tenant_id: DomainId) -> GroupTenantMembership | None:
        """Return the exact Group-Tenant membership fact, or ``None``."""
        if not self._get(group_id, tenant_id):
            return None
        return GroupTenantMembership(group_id, tenant_id)

    def find_by_group(self, group_id: DomainId) -> tuple[GroupTenantMembership, ...]:
        """Return every membership fact of one Group."""
        return tuple(
            GroupTenantMembership(group_id, tenant_id)
            for tenant_id in self._find(
                "SELECT mtmf.group_tenant_membership_find_by_group(%s)", group_id
            )
        )

    def find_by_tenant(self, tenant_id: DomainId) -> tuple[GroupTenantMembership, ...]:
        """Return every Group membership fact in one Tenant."""
        return tuple(
            GroupTenantMembership(group_id, tenant_id)
            for group_id in self._find(
                "SELECT mtmf.group_tenant_membership_find_by_tenant(%s)", tenant_id
            )
        )


class PostgresIdentityGroupMembershipRepository(_MembershipRepository[IdentityGroupMembership]):
    """PostgreSQL Identity-Group membership repository."""

    _add_query = "SELECT mtmf.identity_group_membership_add(%s, %s)"
    _get_query = "SELECT mtmf.identity_group_membership_get(%s, %s)"

    def add(self, membership: IdentityGroupMembership) -> None:
        """Stage a new typed Identity-Group membership fact."""
        self._add(membership.identity_id, membership.group_id)

    def get(self, identity_id: DomainId, group_id: DomainId) -> IdentityGroupMembership | None:
        """Return the exact Identity-Group membership fact, or ``None``."""
        if not self._get(identity_id, group_id):
            return None
        return IdentityGroupMembership(identity_id, group_id)

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityGroupMembership, ...]:
        """Return every membership fact of one Identity."""
        return tuple(
            IdentityGroupMembership(identity_id, group_id)
            for group_id in self._find(
                "SELECT mtmf.identity_group_membership_find_by_identity(%s)", identity_id
            )
        )

    def find_by_group(self, group_id: DomainId) -> tuple[IdentityGroupMembership, ...]:
        """Return every Identity membership fact of one Group."""
        return tuple(
            IdentityGroupMembership(identity_id, group_id)
            for identity_id in self._find(
                "SELECT mtmf.identity_group_membership_find_by_group(%s)", group_id
            )
        )


class PostgresIdentityOrgMembershipRepository(_MembershipRepository[IdentityOrgMembership]):
    """PostgreSQL Identity-Organization membership repository."""

    _add_query = "SELECT mtmf.identity_org_membership_add(%s, %s)"
    _get_query = "SELECT mtmf.identity_org_membership_get(%s, %s)"

    def add(self, membership: IdentityOrgMembership) -> None:
        """Stage a new typed Identity-Organization membership fact."""
        self._add(membership.identity_id, membership.organization_id)

    def get(self, identity_id: DomainId, organization_id: DomainId) -> IdentityOrgMembership | None:
        """Return the exact Identity-Organization membership fact, or ``None``."""
        if not self._get(identity_id, organization_id):
            return None
        return IdentityOrgMembership(identity_id, organization_id)

    def find_by_identity(self, identity_id: DomainId) -> tuple[IdentityOrgMembership, ...]:
        """Return every membership fact of one Identity."""
        return tuple(
            IdentityOrgMembership(identity_id, organization_id)
            for organization_id in self._find(
                "SELECT mtmf.identity_org_membership_find_by_identity(%s)", identity_id
            )
        )

    def find_by_organization(self, organization_id: DomainId) -> tuple[IdentityOrgMembership, ...]:
        """Return every Identity membership fact of one Organization."""
        return tuple(
            IdentityOrgMembership(identity_id, organization_id)
            for identity_id in self._find(
                "SELECT mtmf.identity_org_membership_find_by_organization(%s)", organization_id
            )
        )


class PostgresGroupOrgMembershipRepository(_MembershipRepository[GroupOrgMembership]):
    """PostgreSQL Group-Organization membership repository."""

    _add_query = "SELECT mtmf.group_org_membership_add(%s, %s)"
    _get_query = "SELECT mtmf.group_org_membership_get(%s, %s)"

    def add(self, membership: GroupOrgMembership) -> None:
        """Stage a new typed Group-Organization membership fact."""
        self._add(membership.group_id, membership.organization_id)

    def get(self, group_id: DomainId, organization_id: DomainId) -> GroupOrgMembership | None:
        """Return the exact Group-Organization membership fact, or ``None``."""
        if not self._get(group_id, organization_id):
            return None
        return GroupOrgMembership(group_id, organization_id)

    def find_by_group(self, group_id: DomainId) -> tuple[GroupOrgMembership, ...]:
        """Return every membership fact of one Group."""
        return tuple(
            GroupOrgMembership(group_id, organization_id)
            for organization_id in self._find(
                "SELECT mtmf.group_org_membership_find_by_group(%s)", group_id
            )
        )

    def find_by_organization(self, organization_id: DomainId) -> tuple[GroupOrgMembership, ...]:
        """Return every Group membership fact of one Organization."""
        return tuple(
            GroupOrgMembership(group_id, organization_id)
            for group_id in self._find(
                "SELECT mtmf.group_org_membership_find_by_organization(%s)", organization_id
            )
        )
