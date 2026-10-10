"""Provider-level persistence SPI: :class:`MtmfSpi`.

There is exactly one provider-level persistence SPI per MTMF runtime. It
owns factories for UnitOfWork instances and for every typed repository.

Every repository factory takes its UnitOfWork explicitly; a repository
is never created detached from a UnitOfWork, and repositories created
from one UnitOfWork share one transactional view. A multi-repository
commit commits all staged changes; rollback commits none.

Migration management (upgrade/downgrade/revision/schema lifecycle) and
external IdP integrations are deliberately outside this SPI: schema
lifecycle is a deployment concern and identity providers are not
persistence providers.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mtmf_core.persistence.repositories import (
    ActionRepository,
    GroupOrgMembershipRepository,
    GroupRepository,
    GroupRoleAssignmentRepository,
    GroupTenantMembershipRepository,
    IdentityGroupMembershipRepository,
    IdentityOrgMembershipRepository,
    IdentityRepository,
    IdentityRoleAssignmentRepository,
    IdentityTenantMembershipRepository,
    OrganizationRepository,
    PrincipalRepository,
    PrincipalTenantMembershipRepository,
    RoleRepository,
    TenantManagementGroupActorEligibilityRepository,
    TenantManagementGroupMembershipRepository,
    TenantManagementGroupRepository,
    TenantRepository,
)
from mtmf_core.persistence.unit_of_work import UnitOfWork


@runtime_checkable
class MtmfSpi(Protocol):
    """Provider-neutral persistence Service Provider Interface.

    An implementation owns the complete persistence implementation for
    one MTMF runtime: committed durable state, transaction semantics,
    and every repository. A repository factory must reject a UnitOfWork
    that was not created by the same provider instance.

    This contract never exposes connection, cursor, session, engine,
    database-driver, migration, or IdP objects.
    """

    def create_unit_of_work(self) -> UnitOfWork:
        """Create an independent UnitOfWork bound to this provider."""
        ...

    def create_tenant_repository(self, uow: UnitOfWork) -> TenantRepository:
        """Create a Tenant repository bound to ``uow``."""
        ...

    def create_organization_repository(self, uow: UnitOfWork) -> OrganizationRepository:
        """Create an Organization repository bound to ``uow``."""
        ...

    def create_principal_repository(self, uow: UnitOfWork) -> PrincipalRepository:
        """Create a Principal repository bound to ``uow``."""
        ...

    def create_identity_repository(self, uow: UnitOfWork) -> IdentityRepository:
        """Create an Identity repository bound to ``uow``."""
        ...

    def create_group_repository(self, uow: UnitOfWork) -> GroupRepository:
        """Create a Group repository bound to ``uow``."""
        ...

    def create_role_repository(self, uow: UnitOfWork) -> RoleRepository:
        """Create a Role aggregate repository bound to ``uow``."""
        ...

    def create_action_repository(self, uow: UnitOfWork) -> ActionRepository:
        """Create an Action repository bound to ``uow``."""
        ...

    def create_identity_role_assignment_repository(
        self, uow: UnitOfWork
    ) -> IdentityRoleAssignmentRepository:
        """Create a direct Identity Role-assignment repository bound to ``uow``."""
        ...

    def create_group_role_assignment_repository(
        self, uow: UnitOfWork
    ) -> GroupRoleAssignmentRepository:
        """Create a Group Role-assignment repository bound to ``uow``."""
        ...

    def create_principal_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> PrincipalTenantMembershipRepository:
        """Create a Principal-Tenant membership repository bound to ``uow``."""
        ...

    def create_identity_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityTenantMembershipRepository:
        """Create an Identity-Tenant membership repository bound to ``uow``."""
        ...

    def create_group_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> GroupTenantMembershipRepository:
        """Create a Group-Tenant membership repository bound to ``uow``."""
        ...

    def create_identity_group_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityGroupMembershipRepository:
        """Create an Identity-Group membership repository bound to ``uow``."""
        ...

    def create_identity_org_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityOrgMembershipRepository:
        """Create an Identity-Organization membership repository bound to ``uow``."""
        ...

    def create_group_org_membership_repository(
        self, uow: UnitOfWork
    ) -> GroupOrgMembershipRepository:
        """Create a Group-Organization membership repository bound to ``uow``."""
        ...

    def create_tenant_management_group_repository(
        self, uow: UnitOfWork
    ) -> TenantManagementGroupRepository:
        """Create a TenantManagementGroup repository bound to ``uow``."""
        ...

    def create_tenant_management_group_membership_repository(
        self, uow: UnitOfWork
    ) -> TenantManagementGroupMembershipRepository:
        """Create a managed-Tenant membership repository bound to ``uow``."""
        ...

    def create_tenant_management_group_actor_eligibility_repository(
        self, uow: UnitOfWork
    ) -> TenantManagementGroupActorEligibilityRepository:
        """Create an eligibility-designation repository bound to ``uow``."""
        ...
