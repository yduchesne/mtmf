"""Pure deterministic cross-object invariant validation.

Validators receive all required context explicitly. They never query
persistence, never consult global registries, and never infer or
auto-create a missing membership: a relationship that lacks a required
explicit predecessor membership is rejected.
"""

from __future__ import annotations

from collections.abc import Iterable

from mtmf_core.domain.errors import MembershipPrerequisiteError, TenantBoundaryError
from mtmf_core.domain.group import Group
from mtmf_core.domain.iam_urn import RoleUrn
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
from mtmf_core.domain.session import validate_session_context

__all__ = [
    "validate_group_org_membership",
    "validate_group_role_assignment",
    "validate_group_tenant_membership",
    "validate_identity_group_membership",
    "validate_identity_org_membership",
    "validate_identity_role_assignment",
    "validate_identity_tenant_membership",
    "validate_session_context",
]


def validate_identity_tenant_membership(
    membership: IdentityTenantMembership,
    identity: Identity,
    principal: Principal,
    principal_tenant_memberships: Iterable[PrincipalTenantMembership],
) -> None:
    """Validate an IdentityTenantMembership and its prerequisites.

    Requires ``identity`` to belong to ``principal`` (structural
    ``Identity.principal_id == Principal.id``) and an explicit
    :class:`PrincipalTenantMembership` for that Principal and the
    membership Tenant. The mandatory local Identity is never
    auto-membered, and a missing prerequisite is rejected.
    """
    if membership.identity_id != identity.id:
        raise MembershipPrerequisiteError(
            "IdentityTenantMembership does not correspond to the supplied Identity"
        )
    if identity.principal_id != principal.id:
        raise MembershipPrerequisiteError(
            "IdentityTenantMembership requires an Identity that belongs to the supplied Principal"
        )
    if not any(
        ptm.principal_id == principal.id and ptm.tenant_id == membership.tenant_id
        for ptm in principal_tenant_memberships
    ):
        raise MembershipPrerequisiteError(
            "IdentityTenantMembership requires a PrincipalTenantMembership "
            "for the same Principal and Tenant"
        )


def validate_group_tenant_membership(
    membership: GroupTenantMembership,
    group: Group,
) -> None:
    """Validate that a GroupTenantMembership agrees with the Group.

    The membership Tenant must equal the Group's structural
    ``tenant_id``; disagreement is a Tenant-boundary violation.
    """
    if membership.group_id != group.id:
        raise MembershipPrerequisiteError(
            "GroupTenantMembership does not correspond to the supplied Group"
        )
    if membership.tenant_id != group.tenant_id:
        raise TenantBoundaryError(
            f"GroupTenantMembership Tenant {membership.tenant_id} disagrees "
            f"with Group structural Tenant {group.tenant_id}"
        )


def validate_identity_group_membership(
    membership: IdentityGroupMembership,
    identity: Identity,
    group: Group,
    identity_tenant_memberships: Iterable[IdentityTenantMembership],
) -> None:
    """Validate an IdentityGroupMembership and its prerequisites.

    Requires an explicit IdentityTenantMembership of the Identity in the
    Group's Tenant. Principal membership alone is insufficient; sibling
    Identity memberships never transfer.
    """
    if membership.identity_id != identity.id:
        raise MembershipPrerequisiteError(
            "IdentityGroupMembership does not correspond to the supplied Identity"
        )
    if membership.group_id != group.id:
        raise MembershipPrerequisiteError(
            "IdentityGroupMembership does not correspond to the supplied Group"
        )
    if not any(
        itm.identity_id == identity.id and itm.tenant_id == group.tenant_id
        for itm in identity_tenant_memberships
    ):
        raise MembershipPrerequisiteError(
            "IdentityGroupMembership requires an IdentityTenantMembership "
            "of the Identity in the Group's Tenant"
        )


def validate_identity_org_membership(
    membership: IdentityOrgMembership,
    identity: Identity,
    organization: Organization,
    identity_tenant_memberships: Iterable[IdentityTenantMembership],
) -> None:
    """Validate an IdentityOrgMembership and its prerequisites.

    Requires an explicit IdentityTenantMembership of the Identity in the
    Organization's Tenant; cross-Tenant membership is rejected.
    """
    if membership.identity_id != identity.id:
        raise MembershipPrerequisiteError(
            "IdentityOrgMembership does not correspond to the supplied Identity"
        )
    if membership.organization_id != organization.id:
        raise MembershipPrerequisiteError(
            "IdentityOrgMembership does not correspond to the supplied Organization"
        )
    if not any(
        itm.identity_id == identity.id and itm.tenant_id == organization.tenant_id
        for itm in identity_tenant_memberships
    ):
        raise MembershipPrerequisiteError(
            "IdentityOrgMembership requires an IdentityTenantMembership "
            "of the Identity in the Organization's Tenant"
        )


def validate_group_org_membership(
    membership: GroupOrgMembership,
    group: Group,
    organization: Organization,
    group_tenant_memberships: Iterable[GroupTenantMembership],
) -> None:
    """Validate a GroupOrgMembership and its prerequisites.

    Requires the Group and Organization to share one Tenant and an
    explicit GroupTenantMembership of the Group in that Tenant.
    """
    if membership.group_id != group.id or membership.organization_id != organization.id:
        raise MembershipPrerequisiteError(
            "GroupOrgMembership does not correspond to the supplied Group and Organization"
        )
    if group.tenant_id != organization.tenant_id:
        raise TenantBoundaryError(
            f"GroupOrgMembership crosses Tenant boundaries: Group Tenant {group.tenant_id} "
            f"differs from Organization Tenant {organization.tenant_id}"
        )
    if not any(
        gtm.group_id == group.id and gtm.tenant_id == group.tenant_id
        for gtm in group_tenant_memberships
    ):
        raise MembershipPrerequisiteError(
            "GroupOrgMembership requires a GroupTenantMembership of the Group in its Tenant"
        )


def _validate_assignment_role_and_organization(
    *,
    assigned_role_urn: RoleUrn,
    assignment_tenant_id: DomainId,
    role: Role,
    organization: Organization | None,
) -> None:
    """Validate the shared Role-definition and Organization-context invariants.

    The assigned Role URN must match the supplied Role, a TENANT-defined
    Role may only be assigned inside its defining Tenant, and an
    Organization refinement must belong to the assignment Tenant.
    """
    if assigned_role_urn != role.urn:
        raise MembershipPrerequisiteError(
            "role assignment does not correspond to the supplied Role URN"
        )
    if role.defining_tenant_id is not None and role.defining_tenant_id != assignment_tenant_id:
        raise TenantBoundaryError(
            "a TENANT-defined Role may only be assigned within its defining Tenant"
        )
    if organization is not None and organization.tenant_id != assignment_tenant_id:
        raise TenantBoundaryError(
            "a Role-assignment Organization refinement must belong to the assignment Tenant"
        )


def validate_identity_role_assignment(
    assignment: IdentityRoleAssignment,
    identity: Identity,
    role: Role,
    identity_tenant_memberships: Iterable[IdentityTenantMembership],
    organization: Organization | None = None,
) -> None:
    """Validate a direct Identity Role assignment and its prerequisites.

    Requires the assignment to target the supplied Identity, an explicit
    :class:`IdentityTenantMembership` of that Identity in the assignment
    Tenant, the supplied Role to be the assigned Role, and a TENANT-defined
    Role to be assigned only in its defining Tenant. When
    ``organization`` is supplied (an Organization-refined assignment), the
    Organization must belong to the assignment Tenant.
    """
    if assignment.identity_id != identity.id:
        raise MembershipPrerequisiteError(
            "IdentityRoleAssignment does not correspond to the supplied Identity"
        )
    if not any(
        itm.identity_id == identity.id and itm.tenant_id == assignment.tenant_id
        for itm in identity_tenant_memberships
    ):
        raise MembershipPrerequisiteError(
            "IdentityRoleAssignment requires an IdentityTenantMembership of the "
            "Identity in the assignment Tenant"
        )
    _validate_assignment_role_and_organization(
        assigned_role_urn=assignment.role_urn,
        assignment_tenant_id=assignment.tenant_id,
        role=role,
        organization=organization,
    )


def validate_group_role_assignment(
    assignment: GroupRoleAssignment,
    group: Group,
    role: Role,
    group_tenant_memberships: Iterable[GroupTenantMembership],
    organization: Organization | None = None,
) -> None:
    """Validate a Group Role assignment and its prerequisites.

    Requires the assignment to target the supplied Group, an explicit
    :class:`GroupTenantMembership` of that Group in the assignment
    Tenant, the assigned Group's structural Tenant to agree with the
    assignment Tenant, the supplied Role to be the assigned Role, and a
    TENANT-defined Role to be assigned only in its defining Tenant. When
    ``organization`` is supplied, it must belong to the assignment Tenant.
    """
    if assignment.group_id != group.id:
        raise MembershipPrerequisiteError(
            "GroupRoleAssignment does not correspond to the supplied Group"
        )
    if group.tenant_id != assignment.tenant_id:
        raise TenantBoundaryError(
            "GroupRoleAssignment Tenant disagrees with the Group structural Tenant"
        )
    if not any(
        gtm.group_id == group.id and gtm.tenant_id == assignment.tenant_id
        for gtm in group_tenant_memberships
    ):
        raise MembershipPrerequisiteError(
            "GroupRoleAssignment requires a GroupTenantMembership of the Group "
            "in the assignment Tenant"
        )
    _validate_assignment_role_and_organization(
        assigned_role_urn=assignment.role_urn,
        assignment_tenant_id=assignment.tenant_id,
        role=role,
        organization=organization,
    )
