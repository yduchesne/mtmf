"""Canonical in-memory vertical slice (two Tenants, two Identities).

Builds the settled tenancy graph and proves structural isolation without
simulating authorization.
"""

import pytest
from helpers import make_group, make_identity, make_organization, make_principal, make_tenant

from mtmf_core import (
    GroupOrgMembership,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityTenantMembership,
    MembershipPrerequisiteError,
    PrincipalTenantMembership,
    SessionContext,
    SessionContextError,
    validate_group_org_membership,
    validate_group_tenant_membership,
    validate_identity_group_membership,
    validate_identity_org_membership,
    validate_identity_tenant_membership,
    validate_session_context,
)


@pytest.fixture
def graph():
    """The canonical two-Tenant/two-Identity domain graph.

    Principal P
    +-- Identity I1
    +-- Identity I2

    Tenant A
    +-- PrincipalTenantMembership(P, A)
    +-- IdentityTenantMembership(I1, A)
    +-- Group GA (Tenant A)
    |    +-- IdentityGroupMembership(I1, GA)
    +-- Organization OA (Tenant A)
         +-- IdentityOrgMembership(I1, OA)
         +-- GroupOrgMembership(GA, OA)

    Tenant B
    +-- PrincipalTenantMembership(P, B)
    +-- IdentityTenantMembership(I2, B)
    """

    principal = make_principal("P")
    identity_one = make_identity(principal_id=principal.id, name="I1")
    identity_two = make_identity(principal_id=principal.id, name="I2")
    tenant_a = make_tenant("A")
    tenant_b = make_tenant("B")
    group_ga = make_group(name="GA", tenant_id=tenant_a.id)
    organization_oa = make_organization(name="OA", tenant_id=tenant_a.id, owner=identity_one.id)

    principal_memberships = [
        PrincipalTenantMembership(principal.id, tenant_a.id),
        PrincipalTenantMembership(principal.id, tenant_b.id),
    ]
    identity_memberships = [
        IdentityTenantMembership(identity_one.id, tenant_a.id),
        IdentityTenantMembership(identity_two.id, tenant_b.id),
    ]
    group_memberships = [GroupTenantMembership(group_ga.id, tenant_a.id)]
    group_identity_memberships = [IdentityGroupMembership(identity_one.id, group_ga.id)]
    organization_memberships = [IdentityOrgMembership(identity_one.id, organization_oa.id)]

    return {
        "principal": principal,
        "identity_one": identity_one,
        "identity_two": identity_two,
        "tenant_a": tenant_a,
        "tenant_b": tenant_b,
        "group_ga": group_ga,
        "organization_oa": organization_oa,
        "principal_memberships": principal_memberships,
        "identity_memberships": identity_memberships,
        "group_memberships": group_memberships,
        "group_identity_memberships": group_identity_memberships,
        "organization_memberships": organization_memberships,
    }


def _session(graph, tenant, identity):
    return SessionContext(tenant.id, graph["principal"].id, identity.id)


def test_every_explicit_relationship_validates(graph) -> None:
    identity_memberships = graph["identity_memberships"]
    validate_identity_tenant_membership(
        identity_memberships[0],  # ITM(I1, A)
        graph["identity_one"],
        graph["principal"],
        graph["principal_memberships"],
    )
    validate_identity_tenant_membership(
        identity_memberships[1],  # ITM(I2, B)
        graph["identity_two"],
        graph["principal"],
        graph["principal_memberships"],
    )
    for group_membership in graph["group_memberships"]:
        validate_group_tenant_membership(group_membership, graph["group_ga"])
    for group_identity_membership in graph["group_identity_memberships"]:
        validate_identity_group_membership(
            group_identity_membership,
            graph["identity_one"],
            graph["group_ga"],
            identity_memberships,
        )
    for organization_membership in graph["organization_memberships"]:
        validate_identity_org_membership(
            organization_membership,
            graph["identity_one"],
            graph["organization_oa"],
            identity_memberships,
        )
    validate_group_org_membership(
        GroupOrgMembership(graph["group_ga"].id, graph["organization_oa"].id),
        graph["group_ga"],
        graph["organization_oa"],
        graph["group_memberships"],
    )


def test_session_a_p_i1_is_structurally_valid(graph) -> None:
    session = _session(graph, graph["tenant_a"], graph["identity_one"])
    validate_session_context(
        session,
        graph["tenant_a"],
        graph["principal"],
        graph["identity_one"],
        graph["principal_memberships"],
        graph["identity_memberships"],
    )


def test_session_b_p_i2_is_structurally_valid(graph) -> None:
    session = _session(graph, graph["tenant_b"], graph["identity_two"])
    validate_session_context(
        session,
        graph["tenant_b"],
        graph["principal"],
        graph["identity_two"],
        graph["principal_memberships"],
        graph["identity_memberships"],
    )


def test_session_a_p_i2_is_invalid(graph) -> None:
    session = _session(graph, graph["tenant_a"], graph["identity_two"])
    with pytest.raises(SessionContextError):
        validate_session_context(
            session,
            graph["tenant_a"],
            graph["principal"],
            graph["identity_two"],
            graph["principal_memberships"],
            graph["identity_memberships"],
        )


def test_session_b_p_i1_is_invalid(graph) -> None:
    session = _session(graph, graph["tenant_b"], graph["identity_one"])
    with pytest.raises(SessionContextError):
        validate_session_context(
            session,
            graph["tenant_b"],
            graph["principal"],
            graph["identity_one"],
            graph["principal_memberships"],
            graph["identity_memberships"],
        )


def test_identity_one_group_membership_does_not_affect_identity_two(graph) -> None:
    # I1 is in Group GA of Tenant A; I2 must not inherit that membership.
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_group_membership(
            IdentityGroupMembership(graph["identity_two"].id, graph["group_ga"].id),
            graph["identity_two"],
            graph["group_ga"],
            graph["identity_memberships"],
        )


def test_organization_membership_does_not_create_tenant_membership(graph) -> None:
    # I1 is an Organization member in Tenant A but has no IdentityTenant
    # membership for Tenant B; the I1->OA membership never implies it.
    assert (
        IdentityTenantMembership(graph["identity_one"].id, graph["tenant_b"].id)
        not in graph["identity_memberships"]
    )
    with pytest.raises(MembershipPrerequisiteError):
        validate_identity_tenant_membership(
            IdentityTenantMembership(graph["identity_one"].id, graph["tenant_b"].id),
            graph["identity_one"],
            graph["principal"],
            [],  # no evidence is ever invented
        )


def test_tenant_a_state_is_never_unioned_into_tenant_b(graph) -> None:
    tenant_b_identity_memberships = [
        membership
        for membership in graph["identity_memberships"]
        if membership.tenant_id == graph["tenant_b"].id
    ]
    assert tenant_b_identity_memberships == [
        IdentityTenantMembership(graph["identity_two"].id, graph["tenant_b"].id)
    ]
    # Structural tenant relationships of A objects point only at A.
    assert graph["group_ga"].tenant_id == graph["tenant_a"].id
    assert graph["organization_oa"].tenant_id == graph["tenant_a"].id
    assert graph["group_ga"].tenant_id != graph["tenant_b"].id
