"""MTMF core domain: entities, typed memberships, session, invariants, and policy."""

from mtmf_core.domain.action import BASELINE_ACTIONS, Action
from mtmf_core.domain.errors import (
    DomainInvariantError,
    ImmutabilityError,
    ManagementGroupInvariantError,
    MembershipPrerequisiteError,
    RootInvariantError,
    SessionContextError,
    StewardshipInvariantError,
    TenantBoundaryError,
    TenantLifecycleError,
)
from mtmf_core.domain.group import Group
from mtmf_core.domain.iam_urn import ActionUrn, PermissionUrn, RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.invariants import (
    validate_group_org_membership,
    validate_group_role_assignment,
    validate_group_tenant_membership,
    validate_identity_group_membership,
    validate_identity_org_membership,
    validate_identity_role_assignment,
    validate_identity_tenant_membership,
    validate_session_context,
)
from mtmf_core.domain.json_types import JsonObject, JsonScalar, JsonValue, new_extension
from mtmf_core.domain.lifecycle import (
    ActiveStatus,
    DeletionStatus,
    IdentityOrigin,
    TenantLifecycle,
)
from mtmf_core.domain.management_group import (
    TenantManagementGroup,
    TenantManagementGroupMembership,
    TenantManagementScope,
    validate_tenant_management_group,
    validate_tenant_management_group_membership,
)
from mtmf_core.domain.memberships import (
    GroupOrgMembership,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityTenantMembership,
    PrincipalTenantMembership,
)
from mtmf_core.domain.organization import Organization
from mtmf_core.domain.permission import Permission
from mtmf_core.domain.permission_matching import (
    NO_MATCH,
    MatchResult,
    MatchSpecificity,
    match_permission,
    match_permission_urn,
)
from mtmf_core.domain.permission_set import PermissionSet
from mtmf_core.domain.policy import DefinitionNamespace, PermissionEffect
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.role import Role
from mtmf_core.domain.role_assignment import GroupRoleAssignment, IdentityRoleAssignment
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.session import SessionContext
from mtmf_core.domain.stewardship import (
    RootBootstrapRecord,
    TenantStewardshipDesignation,
    validate_root_bootstrap_record,
    validate_stewardship_designation,
    validate_tenant_lifecycle_transition,
)
from mtmf_core.domain.tenant import Tenant
from mtmf_core.domain.urn import Urn

__all__ = [
    "BASELINE_ACTIONS",
    "NO_MATCH",
    "Action",
    "ActionUrn",
    "ActiveStatus",
    "DefinitionNamespace",
    "DeletionStatus",
    "DomainId",
    "DomainInvariantError",
    "Group",
    "GroupOrgMembership",
    "GroupRoleAssignment",
    "GroupTenantMembership",
    "Identity",
    "IdentityGroupMembership",
    "IdentityOrgMembership",
    "IdentityOrigin",
    "IdentityRoleAssignment",
    "IdentityTenantMembership",
    "ImmutabilityError",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "ManagementGroupInvariantError",
    "MatchResult",
    "MatchSpecificity",
    "MembershipPrerequisiteError",
    "Organization",
    "Permission",
    "PermissionEffect",
    "PermissionSet",
    "PermissionUrn",
    "Principal",
    "PrincipalTenantMembership",
    "Role",
    "RoleUrn",
    "RootBootstrapRecord",
    "RootInvariantError",
    "SecurityScope",
    "SessionContext",
    "SessionContextError",
    "StewardshipInvariantError",
    "Tenant",
    "TenantBoundaryError",
    "TenantLifecycle",
    "TenantLifecycleError",
    "TenantManagementGroup",
    "TenantManagementGroupMembership",
    "TenantManagementScope",
    "TenantStewardshipDesignation",
    "Urn",
    "match_permission",
    "match_permission_urn",
    "new_extension",
    "validate_group_org_membership",
    "validate_group_role_assignment",
    "validate_group_tenant_membership",
    "validate_identity_group_membership",
    "validate_identity_org_membership",
    "validate_identity_role_assignment",
    "validate_identity_tenant_membership",
    "validate_root_bootstrap_record",
    "validate_session_context",
    "validate_stewardship_designation",
    "validate_tenant_lifecycle_transition",
    "validate_tenant_management_group",
    "validate_tenant_management_group_membership",
]
