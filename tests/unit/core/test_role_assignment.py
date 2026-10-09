"""Typed Role-assignment domain tests (plan matrix D01-D03).

Assignments are immutable structural facts. They carry a typed subject
(Identity or Group) rather than a polymorphic ``subject_type``/``subject_id``
pair, and their identity, context, Role URN, and optional Organization may
never be replaced.
"""

from __future__ import annotations

import pytest
from helpers import (
    make_group,
    make_id,
    make_identity,
    make_organization,
    make_role,
    make_role_urn,
)

from mtmf_core import (
    DomainInvariantError,
    GroupOrgMembership,
    GroupRoleAssignment,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityRoleAssignment,
    IdentityTenantMembership,
    ImmutabilityError,
    MembershipPrerequisiteError,
    TenantBoundaryError,
    validate_group_role_assignment,
    validate_identity_role_assignment,
)


def test_d01_direct_identity_assignment_is_accepted_and_detached() -> None:
    tenant_id = make_id()
    identity_id = make_id()
    role = make_role(tenant_id=tenant_id)
    assignment = IdentityRoleAssignment(make_id(), tenant_id, identity_id, role.urn)
    assert assignment.tenant_id == tenant_id
    assert assignment.identity_id == identity_id
    assert assignment.role_urn == role.urn
    assert assignment.organization_id is None


def test_d01b_group_assignment_is_accepted() -> None:
    tenant_id = make_id()
    group_id = make_id()
    assignment = GroupRoleAssignment(make_id(), tenant_id, group_id, make_role_urn())
    assert assignment.group_id == group_id
    assert not hasattr(assignment, "subject_type")
    assert not hasattr(assignment, "subject_id")


@pytest.mark.parametrize(
    "field",
    ("id", "tenant_id", "identity_id", "role_urn", "organization_id"),
)
def test_d02_immutable_identity_fields_cannot_be_replaced(field: str) -> None:
    assignment = IdentityRoleAssignment(make_id(), make_id(), make_id(), make_role_urn())
    with pytest.raises(ImmutabilityError):
        setattr(assignment, field, make_id())


@pytest.mark.parametrize(
    "field",
    ("id", "tenant_id", "group_id", "role_urn", "organization_id"),
)
def test_d02b_group_assignment_immutable_fields_cannot_be_replaced(field: str) -> None:
    assignment = GroupRoleAssignment(make_id(), make_id(), make_id(), make_role_urn())
    with pytest.raises(ImmutabilityError):
        setattr(assignment, field, make_id())


def test_d03_group_assignment_has_a_typed_target_only() -> None:
    assignment = GroupRoleAssignment(make_id(), make_id(), make_id(), make_role_urn())
    assert isinstance(assignment, GroupRoleAssignment)
    assert not isinstance(assignment, IdentityRoleAssignment)


# --- validators --------------------------------------------------------------


def test_direct_assignment_requires_same_tenant_identity_membership() -> None:
    tenant_id = make_id()
    identity = make_identity()
    role = make_role(tenant_id=tenant_id)
    assignment = IdentityRoleAssignment(make_id(), tenant_id, identity.id, role.urn)
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_role_assignment(assignment, identity, role, ())
    validate_identity_role_assignment(
        assignment,
        identity,
        role,
        (IdentityTenantMembership(identity.id, tenant_id),),
    )


def test_direct_assignment_rejects_tenant_role_outside_defining_tenant() -> None:
    defining_tenant = make_id()
    other_tenant = make_id()
    identity = make_identity()
    role = make_role(tenant_id=defining_tenant)
    assignment = IdentityRoleAssignment(make_id(), other_tenant, identity.id, role.urn)
    with pytest.raises(TenantBoundaryError):
        validate_identity_role_assignment(
            assignment,
            identity,
            role,
            (IdentityTenantMembership(identity.id, other_tenant),),
        )


def test_direct_assignment_rejects_organization_from_another_tenant() -> None:
    tenant_id = make_id()
    identity = make_identity()
    role = make_role(tenant_id=tenant_id)
    organization = make_organization(tenant_id=make_id())
    assignment = IdentityRoleAssignment(
        make_id(), tenant_id, identity.id, role.urn, organization.id
    )
    # The validator rejects through the Organization Tenant mismatch, but the
    # membership prerequisite is checked first, so supply it.
    with pytest.raises(TenantBoundaryError):
        validate_identity_role_assignment(
            assignment,
            identity,
            role,
            (IdentityTenantMembership(identity.id, tenant_id),),
            organization,
        )


def test_group_assignment_requires_group_tenant_membership() -> None:
    tenant_id = make_id()
    group = make_group(tenant_id=tenant_id)
    role = make_role(tenant_id=tenant_id)
    assignment = GroupRoleAssignment(make_id(), tenant_id, group.id, role.urn)
    with pytest.raises(MembershipPrerequisiteError):
        validate_group_role_assignment(assignment, group, role, ())
    validate_group_role_assignment(
        assignment,
        group,
        role,
        (GroupTenantMembership(group.id, tenant_id),),
    )


def test_group_assignment_rejects_cross_tenant_group() -> None:
    tenant_id = make_id()
    group = make_group(tenant_id=make_id())
    role = make_role(tenant_id=tenant_id)
    assignment = GroupRoleAssignment(make_id(), tenant_id, group.id, role.urn)
    with pytest.raises(TenantBoundaryError):
        validate_group_role_assignment(
            assignment,
            group,
            role,
            (GroupTenantMembership(group.id, group.tenant_id),),
        )


def test_group_assignment_organization_refinement_must_match_tenant() -> None:
    tenant_id = make_id()
    group = make_group(tenant_id=tenant_id)
    role = make_role(tenant_id=tenant_id)
    organization = make_organization(tenant_id=make_id())
    assignment = GroupRoleAssignment(make_id(), tenant_id, group.id, role.urn, organization.id)
    with pytest.raises(TenantBoundaryError):
        validate_group_role_assignment(
            assignment,
            group,
            role,
            (GroupTenantMembership(group.id, tenant_id),),
            organization,
        )


def test_role_assignment_membership_entities_are_importable() -> None:
    # The typed organization and group memberships remain available for the
    # resolver prerequisites; this guards against an accidental removal.
    assert IdentityOrgMembership(make_id(), make_id())
    assert GroupOrgMembership(make_id(), make_id())
    assert IdentityGroupMembership(make_id(), make_id())


def test_domain_invariant_error_is_the_common_base() -> None:
    assert issubclass(MembershipPrerequisiteError, DomainInvariantError)
    assert issubclass(TenantBoundaryError, DomainInvariantError)
