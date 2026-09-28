"""MTMF core domain: entities, typed memberships, session, and invariants."""

from mtmf_core.domain.errors import (
    DomainInvariantError,
    ImmutabilityError,
    MembershipPrerequisiteError,
    SessionContextError,
    TenantBoundaryError,
)
from mtmf_core.domain.group import Group
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.invariants import (
    validate_group_org_membership,
    validate_group_tenant_membership,
    validate_identity_group_membership,
    validate_identity_org_membership,
    validate_identity_tenant_membership,
    validate_session_context,
)
from mtmf_core.domain.json_types import JsonObject, JsonScalar, JsonValue, new_extension
from mtmf_core.domain.lifecycle import ActiveStatus, DeletionStatus
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
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.session import SessionContext
from mtmf_core.domain.tenant import Tenant
from mtmf_core.domain.urn import Urn

__all__ = [
    "ActiveStatus",
    "DeletionStatus",
    "DomainId",
    "DomainInvariantError",
    "Group",
    "GroupOrgMembership",
    "GroupTenantMembership",
    "Identity",
    "IdentityGroupMembership",
    "IdentityOrgMembership",
    "IdentityTenantMembership",
    "ImmutabilityError",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "MembershipPrerequisiteError",
    "Organization",
    "Principal",
    "PrincipalTenantMembership",
    "SecurityScope",
    "SessionContext",
    "SessionContextError",
    "Tenant",
    "TenantBoundaryError",
    "Urn",
    "new_extension",
    "validate_group_org_membership",
    "validate_group_tenant_membership",
    "validate_identity_group_membership",
    "validate_identity_org_membership",
    "validate_identity_tenant_membership",
    "validate_session_context",
]
