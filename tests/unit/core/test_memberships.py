"""Unit tests for typed memberships and their validators (U17-U30)."""

import pytest
from helpers import make_group, make_id, make_identity, make_organization, make_principal

from mtmf_core import (
    GroupOrgMembership,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityTenantMembership,
    MembershipPrerequisiteError,
    PrincipalTenantMembership,
    TenantBoundaryError,
    validate_group_org_membership,
    validate_group_tenant_membership,
    validate_identity_group_membership,
    validate_identity_org_membership,
    validate_identity_tenant_membership,
)

# --- PrincipalTenantMembership -------------------------------------------------


def test_principal_may_be_member_of_two_tenants() -> None:
    principal = make_principal()
    tenant_a_id = make_id()
    tenant_b_id = make_id()
    first = PrincipalTenantMembership(principal.id, tenant_a_id)
    second = PrincipalTenantMembership(principal.id, tenant_b_id)
    # No validation rejects multi-Tenant Principal membership.
    assert first.principal_id == principal.id
    assert second.tenant_id == tenant_b_id
    assert first != second


def test_principal_memberships_are_value_objects() -> None:
    principal = make_principal()
    tenant_a_id = make_id()
    assert PrincipalTenantMembership(principal.id, tenant_a_id) == PrincipalTenantMembership(
        principal.id, tenant_a_id
    )


# --- IdentityTenantMembership (U18, U19, U20, U21) -----------------------------


def test_identity_membership_with_principal_same_tenant_membership_is_valid() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    tenant_id = make_id()
    principal_membership = PrincipalTenantMembership(principal.id, tenant_id)
    membership = IdentityTenantMembership(identity.id, tenant_id)
    validate_identity_tenant_membership(membership, identity, principal, [principal_membership])


def test_identity_membership_without_principal_same_tenant_membership_rejected() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    other_tenant = make_id()
    membership = IdentityTenantMembership(identity.id, other_tenant)
    # The Principal is only a member of a different Tenant.
    principal_membership = PrincipalTenantMembership(principal.id, make_id())
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_tenant_membership(membership, identity, principal, [principal_membership])


def test_identity_membership_rejected_when_principal_has_no_memberships() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    membership = IdentityTenantMembership(identity.id, make_id())
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_tenant_membership(membership, identity, principal, [])


def test_identity_membership_of_identity_belonging_to_other_principal_rejected() -> None:
    principal = make_principal()
    other_identity = make_identity(principal_id=make_id())
    membership = IdentityTenantMembership(other_identity.id, make_id())
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_tenant_membership(membership, other_identity, principal, [])


def test_identity_membership_with_wrong_identity_evidence_rejected() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    wrong_membership = IdentityTenantMembership(make_id(), make_id())
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_tenant_membership(wrong_membership, identity, principal, [])


def test_identity_membership_is_a_subset_of_principal_tenants() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    tenant_a = make_id()
    tenant_b = make_id()
    principal_memberships = [
        PrincipalTenantMembership(principal.id, tenant_a),
        PrincipalTenantMembership(principal.id, tenant_b),
    ]
    # Identity participates only in Tenant A although its Principal is in
    # both Tenants (U20).
    membership = IdentityTenantMembership(identity.id, tenant_a)
    validate_identity_tenant_membership(membership, identity, principal, principal_memberships)


def test_sibling_identity_does_not_inherit_tenant_membership() -> None:
    # U21: only the `first` Identity received an explicit
    # IdentityTenantMembership. The sibling's membership requires its own
    # explicit membership object; it is never implied by having a
    # same-Principal sibling.
    principal = make_principal()
    first = make_identity(principal_id=principal.id)
    second = make_identity(principal_id=principal.id)
    tenant_id = make_id()
    principal_membership = PrincipalTenantMembership(principal.id, tenant_id)
    identity_memberships = [IdentityTenantMembership(first.id, tenant_id)]
    assert IdentityTenantMembership(second.id, tenant_id) not in identity_memberships
    validate_identity_tenant_membership(
        IdentityTenantMembership(first.id, tenant_id), first, principal, [principal_membership]
    )


# --- GroupTenantMembership (U22, U23) ------------------------------------------


def test_group_tenant_membership_same_tenant_is_valid() -> None:
    group = make_group()
    membership = GroupTenantMembership(group.id, group.tenant_id)
    validate_group_tenant_membership(membership, group)


def test_group_tenant_membership_cross_tenant_rejected() -> None:
    group = make_group()
    membership = GroupTenantMembership(group.id, make_id())
    with pytest.raises(TenantBoundaryError):
        validate_group_tenant_membership(membership, group)


def test_group_tenant_membership_with_wrong_group_evidence_rejected() -> None:
    group = make_group()
    membership = GroupTenantMembership(make_id(), group.tenant_id)
    with pytest.raises(MembershipPrerequisiteError):
        validate_group_tenant_membership(membership, group)


# --- IdentityGroupMembership (U24, U25, U26) ------------------------------------


def test_identity_group_membership_with_tenant_prerequisite_is_valid() -> None:
    tenant_id = make_id()
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    group = make_group(tenant_id=tenant_id)
    tenant_memberships = [IdentityTenantMembership(identity.id, tenant_id)]
    membership = IdentityGroupMembership(identity.id, group.id)
    validate_identity_group_membership(membership, identity, group, tenant_memberships)


def test_identity_group_membership_without_prerequisite_rejected() -> None:
    tenant_id = make_id()
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    group = make_group(tenant_id=tenant_id)
    membership = IdentityGroupMembership(identity.id, group.id)
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_group_membership(membership, identity, group, [])


def test_sibling_identity_group_membership_not_inherited() -> None:
    # U26: `first` belongs to the Group through an explicit
    # IdentityGroupMembership; the sibling's membership must be its own
    # explicit object and is never derived from the first Identity's.
    tenant_id = make_id()
    principal = make_principal()
    first = make_identity(principal_id=principal.id)
    second = make_identity(principal_id=principal.id)
    group = make_group(tenant_id=tenant_id)
    tenant_memberships = [
        IdentityTenantMembership(first.id, tenant_id),
        IdentityTenantMembership(second.id, tenant_id),
    ]
    group_identity_memberships = [IdentityGroupMembership(first.id, group.id)]
    assert IdentityGroupMembership(second.id, group.id) not in group_identity_memberships
    validate_identity_group_membership(
        group_identity_memberships[0], first, group, tenant_memberships
    )


def test_identity_group_membership_with_wrong_evidence_rejected() -> None:
    tenant_id = make_id()
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    group = make_group(tenant_id=tenant_id)
    tenant_memberships = [IdentityTenantMembership(identity.id, tenant_id)]
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_group_membership(
            IdentityGroupMembership(make_id(), group.id), identity, group, tenant_memberships
        )
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_group_membership(
            IdentityGroupMembership(identity.id, make_id()), identity, group, tenant_memberships
        )


# --- IdentityOrgMembership (U27, U28) ------------------------------------------


def test_identity_org_membership_same_tenant_is_valid() -> None:
    tenant_id = make_id()
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    organization = make_organization(tenant_id=tenant_id)
    tenant_memberships = [IdentityTenantMembership(identity.id, tenant_id)]
    membership = IdentityOrgMembership(identity.id, organization.id)
    validate_identity_org_membership(membership, identity, organization, tenant_memberships)


def test_identity_org_membership_cross_tenant_rejected() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    organization = make_organization(tenant_id=make_id())
    membership = IdentityOrgMembership(identity.id, organization.id)
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_org_membership(membership, identity, organization, [])


def test_identity_org_membership_does_not_substitute_for_tenant_membership() -> None:
    tenant_id = make_id()
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    organization = make_organization(tenant_id=tenant_id)
    # An existing IdentityOrgMembership in another Tenant never creates
    # the required same-Tenant IdentityTenantMembership.
    other_org = make_organization(tenant_id=make_id())
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_org_membership(
            IdentityOrgMembership(identity.id, organization.id),
            identity,
            organization,
            [IdentityTenantMembership(identity.id, other_org.tenant_id)],
        )


def test_identity_org_membership_with_wrong_evidence_rejected() -> None:
    tenant_id = make_id()
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    organization = make_organization(tenant_id=tenant_id)
    tenant_memberships = [IdentityTenantMembership(identity.id, tenant_id)]
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_org_membership(
            IdentityOrgMembership(make_id(), organization.id),
            identity,
            organization,
            tenant_memberships,
        )
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_org_membership(
            IdentityOrgMembership(identity.id, make_id()),
            identity,
            organization,
            tenant_memberships,
        )


# --- GroupOrgMembership (U29, U30) ----------------------------------------------


def test_group_org_membership_same_tenant_is_valid() -> None:
    tenant_id = make_id()
    group = make_group(tenant_id=tenant_id)
    organization = make_organization(tenant_id=tenant_id)
    group_memberships = [GroupTenantMembership(group.id, tenant_id)]
    membership = GroupOrgMembership(group.id, organization.id)
    validate_group_org_membership(membership, group, organization, group_memberships)


def test_group_org_membership_cross_tenant_rejected() -> None:
    group = make_group(tenant_id=make_id())
    organization = make_organization(tenant_id=make_id())
    membership = GroupOrgMembership(group.id, organization.id)
    group_memberships = [GroupTenantMembership(group.id, group.tenant_id)]
    with pytest.raises(TenantBoundaryError):
        validate_group_org_membership(membership, group, organization, group_memberships)


def test_group_org_membership_requires_group_tenant_membership() -> None:
    tenant_id = make_id()
    group = make_group(tenant_id=tenant_id)
    organization = make_organization(tenant_id=tenant_id)
    membership = GroupOrgMembership(group.id, organization.id)
    with pytest.raises(MembershipPrerequisiteError):
        validate_group_org_membership(membership, group, organization, [])


def test_group_org_membership_with_wrong_evidence_rejected() -> None:
    tenant_id = make_id()
    group = make_group(tenant_id=tenant_id)
    organization = make_organization(tenant_id=tenant_id)
    group_memberships = [GroupTenantMembership(group.id, tenant_id)]
    with pytest.raises(MembershipPrerequisiteError):
        validate_group_org_membership(
            GroupOrgMembership(make_id(), organization.id), group, organization, group_memberships
        )
    with pytest.raises(MembershipPrerequisiteError):
        validate_group_org_membership(
            GroupOrgMembership(group.id, make_id()), group, organization, group_memberships
        )


# --- Validator posture ----------------------------------------------------------


def test_membership_validators_fail_closed_on_empty_evidence() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    tenant_id = make_id()
    group = make_group(tenant_id=tenant_id)
    organization = make_organization(tenant_id=tenant_id)
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_tenant_membership(
            IdentityTenantMembership(identity.id, tenant_id), identity, principal, []
        )
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_group_membership(
            IdentityGroupMembership(identity.id, group.id), identity, group, []
        )
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_org_membership(
            IdentityOrgMembership(identity.id, organization.id), identity, organization, []
        )
    with pytest.raises(MembershipPrerequisiteError):
        validate_group_org_membership(
            GroupOrgMembership(group.id, organization.id), group, organization, []
        )


def test_validators_never_auto_create_memberships() -> None:
    # Rejections must not silently repair; the supplied evidence remains
    # the only source of truth and is unchanged.
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    tenant_id = make_id()
    evidence: list[PrincipalTenantMembership] = []
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_tenant_membership(
            IdentityTenantMembership(identity.id, tenant_id), identity, principal, evidence
        )
    assert evidence == []


def test_memberships_are_explicit_value_objects() -> None:
    tenant_id = make_id()
    group = make_group(tenant_id=tenant_id)
    organization = make_organization(tenant_id=tenant_id)
    identity = make_identity()
    assert GroupOrgMembership(group.id, organization.id) == GroupOrgMembership(
        group.id, organization.id
    )
    assert IdentityOrgMembership(identity.id, organization.id) != IdentityOrgMembership(
        identity.id, make_id()
    )
    assert GroupTenantMembership(group.id, tenant_id) != GroupTenantMembership(make_id(), tenant_id)
