"""MTMF persistence SPI and UnitOfWork contracts.

``mtmf_core.persistence`` defines the provider-neutral persistence
boundary: :class:`MtmfSpi`, the :class:`UnitOfWork` transaction
contract, typed repository contracts, and the minimal provider-neutral
error hierarchy.

Repositories participating in one business operation are explicitly
bound to and share one UnitOfWork. Commit is explicit; normal context
exit without commit rolls back; exceptional exit rolls back without
suppressing the original exception; completed UnitOfWorks and their
repositories are not reusable.

The deterministic in-memory contract provider lives in
:mod:`mtmf_core.persistence.testing` and is not a production provider.
PostgreSQL, SQL, stored functions, Alembic/migrations, and external IdP
integrations are deliberately outside this package.
"""

from __future__ import annotations

from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    ForeignUnitOfWorkError,
    PersistenceConcurrencyError,
    PersistenceConfigurationError,
    PersistenceConnectionError,
    PersistenceConstraintError,
    PersistenceDataError,
    PersistenceError,
    PersistenceIntegrityError,
    PersistenceReferenceError,
    PersistenceTransactionError,
    PersistenceValueError,
    UnitOfWorkError,
    UnitOfWorkStateError,
    UnknownPersistenceIdentityError,
)
from mtmf_core.persistence.repositories import (
    ActionRepository,
    GroupOrgMembershipRepository,
    GroupRepository,
    GroupTenantMembershipRepository,
    IdentityGroupMembershipRepository,
    IdentityOrgMembershipRepository,
    IdentityRepository,
    IdentityTenantMembershipRepository,
    OrganizationRepository,
    PrincipalRepository,
    PrincipalTenantMembershipRepository,
    RoleRepository,
    TenantRepository,
)
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_core.persistence.unit_of_work import UnitOfWork

__all__ = [
    "ActionRepository",
    "DuplicatePersistenceIdentityError",
    "ForeignUnitOfWorkError",
    "GroupOrgMembershipRepository",
    "GroupRepository",
    "GroupTenantMembershipRepository",
    "IdentityGroupMembershipRepository",
    "IdentityOrgMembershipRepository",
    "IdentityRepository",
    "IdentityTenantMembershipRepository",
    "MtmfSpi",
    "OrganizationRepository",
    "PersistenceConcurrencyError",
    "PersistenceConfigurationError",
    "PersistenceConnectionError",
    "PersistenceConstraintError",
    "PersistenceDataError",
    "PersistenceError",
    "PersistenceIntegrityError",
    "PersistenceReferenceError",
    "PersistenceTransactionError",
    "PersistenceValueError",
    "PrincipalRepository",
    "PrincipalTenantMembershipRepository",
    "RoleRepository",
    "TenantRepository",
    "UnitOfWork",
    "UnitOfWorkError",
    "UnitOfWorkStateError",
    "UnknownPersistenceIdentityError",
]
