"""Production PostgreSQL :class:`~mtmf_core.persistence.spi.MtmfSpi` provider.

:class:`PostgresMtmfSpi` owns the complete PostgreSQL persistence
implementation for one MTMF runtime. It is constructed from an explicit
runtime-only :class:`~mtmf_core.persistence.postgres.config.PostgresConfig`
and refuses any administrator or migrator configuration at construction,
before a connection is opened. Repository factories reject a UnitOfWork
created by another provider instance.

The provider exposes no connection, cursor, session, engine, SQL text,
migration object, or driver exception through its public contract.
"""

from __future__ import annotations

from mtmf_core.persistence.errors import (
    ForeignUnitOfWorkError,
    PersistenceConfigurationError,
)
from mtmf_core.persistence.postgres.config import PostgresConfig, PostgresRole
from mtmf_core.persistence.postgres.repositories import (
    PostgresActionRepository,
    PostgresGroupOrgMembershipRepository,
    PostgresGroupRepository,
    PostgresGroupRoleAssignmentRepository,
    PostgresGroupTenantMembershipRepository,
    PostgresIdentityGroupMembershipRepository,
    PostgresIdentityOrgMembershipRepository,
    PostgresIdentityRepository,
    PostgresIdentityRoleAssignmentRepository,
    PostgresIdentityTenantMembershipRepository,
    PostgresOrganizationRepository,
    PostgresPrincipalRepository,
    PostgresPrincipalTenantMembershipRepository,
    PostgresRoleRepository,
    PostgresTenantRepository,
)
from mtmf_core.persistence.postgres.unit_of_work import PostgresUnitOfWork
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
    TenantRepository,
)
from mtmf_core.persistence.unit_of_work import UnitOfWork

__all__ = ["PostgresMtmfSpi"]


class PostgresMtmfSpi:
    """PostgreSQL provider implementing the provider-neutral persistence SPI."""

    def __init__(self, config: PostgresConfig) -> None:
        """Bind the provider to an explicit restricted-runtime configuration.

        :raises PersistenceConfigurationError: if ``config`` does not
            describe the restricted runtime identity. A migration or
            administrator credential may never back the application
            runtime.
        """
        if config.role is not PostgresRole.RUNTIME:
            raise PersistenceConfigurationError(
                "the PostgreSQL persistence provider requires the restricted runtime "
                "identity; administrator and migrator credentials may never back the "
                "application runtime"
            )
        self._config = config

    def create_unit_of_work(self) -> UnitOfWork:
        """Create an independent UnitOfWork bound to this provider."""
        return PostgresUnitOfWork(self._config, self)

    def _require_own_uow(self, uow: UnitOfWork) -> PostgresUnitOfWork:
        """Return ``uow`` after rejecting UnitOfWorks from another provider."""
        if not isinstance(uow, PostgresUnitOfWork) or uow._spi is not self:
            raise ForeignUnitOfWorkError(
                "repository factories accept only UnitOfWork objects created by this "
                "persistence provider instance"
            )
        return uow

    def create_tenant_repository(self, uow: UnitOfWork) -> TenantRepository:
        """Create a Tenant repository bound to ``uow``."""
        return PostgresTenantRepository(self._require_own_uow(uow))

    def create_organization_repository(self, uow: UnitOfWork) -> OrganizationRepository:
        """Create an Organization repository bound to ``uow``."""
        return PostgresOrganizationRepository(self._require_own_uow(uow))

    def create_principal_repository(self, uow: UnitOfWork) -> PrincipalRepository:
        """Create a Principal repository bound to ``uow``."""
        return PostgresPrincipalRepository(self._require_own_uow(uow))

    def create_identity_repository(self, uow: UnitOfWork) -> IdentityRepository:
        """Create an Identity repository bound to ``uow``."""
        return PostgresIdentityRepository(self._require_own_uow(uow))

    def create_group_repository(self, uow: UnitOfWork) -> GroupRepository:
        """Create a Group repository bound to ``uow``."""
        return PostgresGroupRepository(self._require_own_uow(uow))

    def create_role_repository(self, uow: UnitOfWork) -> RoleRepository:
        """Create a Role aggregate repository bound to ``uow``."""
        return PostgresRoleRepository(self._require_own_uow(uow))

    def create_action_repository(self, uow: UnitOfWork) -> ActionRepository:
        """Create an Action repository bound to ``uow``."""
        return PostgresActionRepository(self._require_own_uow(uow))

    def create_identity_role_assignment_repository(
        self, uow: UnitOfWork
    ) -> IdentityRoleAssignmentRepository:
        """Create a direct Identity Role-assignment repository bound to ``uow``."""
        return PostgresIdentityRoleAssignmentRepository(self._require_own_uow(uow))

    def create_group_role_assignment_repository(
        self, uow: UnitOfWork
    ) -> GroupRoleAssignmentRepository:
        """Create a Group Role-assignment repository bound to ``uow``."""
        return PostgresGroupRoleAssignmentRepository(self._require_own_uow(uow))

    def create_principal_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> PrincipalTenantMembershipRepository:
        """Create a Principal-Tenant membership repository bound to ``uow``."""
        return PostgresPrincipalTenantMembershipRepository(self._require_own_uow(uow))

    def create_identity_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityTenantMembershipRepository:
        """Create an Identity-Tenant membership repository bound to ``uow``."""
        return PostgresIdentityTenantMembershipRepository(self._require_own_uow(uow))

    def create_group_tenant_membership_repository(
        self, uow: UnitOfWork
    ) -> GroupTenantMembershipRepository:
        """Create a Group-Tenant membership repository bound to ``uow``."""
        return PostgresGroupTenantMembershipRepository(self._require_own_uow(uow))

    def create_identity_group_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityGroupMembershipRepository:
        """Create an Identity-Group membership repository bound to ``uow``."""
        return PostgresIdentityGroupMembershipRepository(self._require_own_uow(uow))

    def create_identity_org_membership_repository(
        self, uow: UnitOfWork
    ) -> IdentityOrgMembershipRepository:
        """Create an Identity-Organization membership repository bound to ``uow``."""
        return PostgresIdentityOrgMembershipRepository(self._require_own_uow(uow))

    def create_group_org_membership_repository(
        self, uow: UnitOfWork
    ) -> GroupOrgMembershipRepository:
        """Create a Group-Organization membership repository bound to ``uow``."""
        return PostgresGroupOrgMembershipRepository(self._require_own_uow(uow))
