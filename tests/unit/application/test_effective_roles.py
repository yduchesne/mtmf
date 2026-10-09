"""Effective-Role resolution tests (plan matrix R01-R13, R19).

Every test seeds a real in-memory persistence graph (two Tenants, one
Principal with multiple Identities, Groups, Organizations, Roles, typed
memberships, and assignments) and resolves through
:class:`~mtmf_core.application.effective_roles.EffectiveRoleResolver` in a
real UnitOfWork. The resolver is application-layer logic; it must never
return a Role that crosses Tenant, Identity, Principal, or Organization
boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from helpers import (
    make_group,
    make_id,
    make_identity,
    make_organization,
    make_principal,
    make_role,
    make_tenant,
)

from mtmf_core import (
    DomainId,
    GroupRoleAssignment,
    GroupTenantMembership,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityRoleAssignment,
    IdentityTenantMembership,
    InMemoryMtmfSpi,
    MtmfSpi,
    PrincipalTenantMembership,
    Role,
    SessionContext,
    TenantBoundaryError,
)
from mtmf_core.application import (
    EffectiveRoleIntegrityError,
    EffectiveRoleResolver,
    build_authorization_context,
)
from mtmf_core.domain.errors import SessionContextError
from mtmf_core.domain.identity_entity import Identity


@dataclass
class _Graph:
    """Mutable in-memory fixture graph exposed to each test."""

    spi: MtmfSpi
    tenant_a: DomainId
    tenant_b: DomainId
    principal: DomainId
    identity_a: Identity
    identity_b: Identity
    identity_multi: Identity
    group_a: DomainId
    group_b: DomainId
    org_a: DomainId
    org_b: DomainId
    system_role: Role
    tenant_role_a: Role
    tenant_role_b: Role

    def session_a(self) -> SessionContext:
        return SessionContext(self.tenant_a, self.principal, self.identity_a.id)

    def session_b(self) -> SessionContext:
        return SessionContext(self.tenant_b, self.principal, self.identity_b.id)

    def resolve(
        self,
        session: SessionContext,
        *,
        target_tenant_id: DomainId | None = None,
        target_organization_id: DomainId | None = None,
    ):
        resolver = EffectiveRoleResolver(self.spi)
        with self.spi.create_unit_of_work() as uow:
            return resolver.resolve(
                uow,
                session=session,
                target_tenant_id=target_tenant_id
                if target_tenant_id is not None
                else session.tenant_id,
                target_organization_id=target_organization_id,
            )


def _seed() -> _Graph:
    spi = InMemoryMtmfSpi()
    tenant_a = make_tenant("A")
    tenant_b = make_tenant("B")
    principal = make_principal()
    identity_a = make_identity(principal_id=principal.id, name="A")
    identity_b = make_identity(principal_id=principal.id, name="B")
    identity_multi = make_identity(principal_id=principal.id, name="multi")
    group_a = make_group(tenant_id=tenant_a.id)
    group_b = make_group(tenant_id=tenant_b.id)
    org_a = make_organization(tenant_id=tenant_a.id)
    org_b = make_organization(tenant_id=tenant_b.id)
    system_role = make_role()
    tenant_role_a = make_role(tenant_id=tenant_a.id)
    tenant_role_b = make_role(tenant_id=tenant_b.id)

    with spi.create_unit_of_work() as uow:
        tenants = spi.create_tenant_repository(uow)
        tenants.add(tenant_a)
        tenants.add(tenant_b)
        spi.create_principal_repository(uow).add(principal)
        identities = spi.create_identity_repository(uow)
        for identity in (identity_a, identity_b, identity_multi):
            identities.add(identity)
        groups = spi.create_group_repository(uow)
        groups.add(group_a)
        groups.add(group_b)
        organizations = spi.create_organization_repository(uow)
        organizations.add(org_a)
        organizations.add(org_b)
        roles = spi.create_role_repository(uow)
        roles.add(system_role)
        roles.add(tenant_role_a)
        roles.add(tenant_role_b)

        ptm = spi.create_principal_tenant_membership_repository(uow)
        ptm.add(PrincipalTenantMembership(principal.id, tenant_a.id))
        ptm.add(PrincipalTenantMembership(principal.id, tenant_b.id))
        itm = spi.create_identity_tenant_membership_repository(uow)
        itm.add(IdentityTenantMembership(identity_a.id, tenant_a.id))
        itm.add(IdentityTenantMembership(identity_b.id, tenant_b.id))
        itm.add(IdentityTenantMembership(identity_multi.id, tenant_a.id))
        itm.add(IdentityTenantMembership(identity_multi.id, tenant_b.id))
        gtm = spi.create_group_tenant_membership_repository(uow)
        gtm.add(GroupTenantMembership(group_a.id, tenant_a.id))
        gtm.add(GroupTenantMembership(group_b.id, tenant_b.id))
        iom = spi.create_identity_org_membership_repository(uow)
        iom.add(IdentityOrgMembership(identity_a.id, org_a.id))
        uow.commit()

    return _Graph(
        spi=spi,
        tenant_a=tenant_a.id,
        tenant_b=tenant_b.id,
        principal=principal.id,
        identity_a=identity_a,
        identity_b=identity_b,
        identity_multi=identity_multi,
        group_a=group_a.id,
        group_b=group_b.id,
        org_a=org_a.id,
        org_b=org_b.id,
        system_role=system_role,
        tenant_role_a=tenant_role_a,
        tenant_role_b=tenant_role_b,
    )


def _add_direct(
    graph: _Graph,
    *,
    tenant_id: DomainId,
    identity_id: DomainId,
    role_urn,
    organization_id: DomainId | None = None,
) -> IdentityRoleAssignment:
    assignment = IdentityRoleAssignment(
        make_id(), tenant_id, identity_id, role_urn, organization_id
    )
    with graph.spi.create_unit_of_work() as uow:
        graph.spi.create_identity_role_assignment_repository(uow).add(assignment)
        uow.commit()
    return assignment


def _add_group(
    graph: _Graph,
    *,
    tenant_id: DomainId,
    group_id: DomainId,
    role_urn,
    organization_id: DomainId | None = None,
) -> GroupRoleAssignment:
    assignment = GroupRoleAssignment(make_id(), tenant_id, group_id, role_urn, organization_id)
    with graph.spi.create_unit_of_work() as uow:
        graph.spi.create_group_role_assignment_repository(uow).add(assignment)
        uow.commit()
    return assignment


def _join_group(graph: _Graph, identity_id: DomainId, group_id: DomainId) -> None:
    with graph.spi.create_unit_of_work() as uow:
        graph.spi.create_identity_group_membership_repository(uow).add(
            IdentityGroupMembership(identity_id, group_id)
        )
        uow.commit()


def test_r01_direct_assignment_is_scoped_to_its_tenant() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
    )
    resolved_a = graph.resolve(graph.session_a())
    assert [role.urn for role in resolved_a.applicable_roles] == [graph.system_role.urn]
    # Identity B is a different Identity of the same Principal in Tenant B.
    resolved_b = graph.resolve(graph.session_b())
    assert resolved_b.applicable_roles == ()


def test_r02_group_membership_derives_group_role() -> None:
    graph = _seed()
    _join_group(graph, graph.identity_a.id, graph.group_a)
    _add_group(
        graph, tenant_id=graph.tenant_a, group_id=graph.group_a, role_urn=graph.system_role.urn
    )
    resolved = graph.resolve(graph.session_a())
    assert [role.urn for role in resolved.applicable_roles] == [graph.system_role.urn]


def test_r03_direct_and_group_roles_do_not_leak_to_a_sibling_identity() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
    )
    _join_group(graph, graph.identity_a.id, graph.group_a)
    _add_group(
        graph, tenant_id=graph.tenant_a, group_id=graph.group_a, role_urn=graph.tenant_role_a.urn
    )
    resolved_b = graph.resolve(graph.session_b())
    assert resolved_b.applicable_roles == ()


def test_r04_roles_are_not_unioned_across_tenants_for_one_identity() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_multi.id,
        role_urn=graph.system_role.urn,
    )
    _add_direct(
        graph,
        tenant_id=graph.tenant_b,
        identity_id=graph.identity_multi.id,
        role_urn=graph.tenant_role_b.urn,
    )
    session_a = SessionContext(graph.tenant_a, graph.principal, graph.identity_multi.id)
    session_b = SessionContext(graph.tenant_b, graph.principal, graph.identity_multi.id)
    assert [role.urn for role in graph.resolve(session_a).applicable_roles] == [
        graph.system_role.urn
    ]
    assert [role.urn for role in graph.resolve(session_b).applicable_roles] == [
        graph.tenant_role_b.urn
    ]


def test_r05_group_in_another_tenant_contributes_nothing() -> None:
    graph = _seed()
    _join_group(graph, graph.identity_a.id, graph.group_b)
    _add_group(
        graph, tenant_id=graph.tenant_b, group_id=graph.group_b, role_urn=graph.tenant_role_b.urn
    )
    assert graph.resolve(graph.session_a()).applicable_roles == ()


def test_r06_organization_refined_direct_grant_is_included_with_prerequisites() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
        organization_id=graph.org_a,
    )
    resolved = graph.resolve(graph.session_a(), target_organization_id=graph.org_a)
    assert [role.urn for role in resolved.applicable_roles] == [graph.system_role.urn]


def test_r07_organization_refined_grant_excluded_for_other_or_no_organization() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
        organization_id=graph.org_a,
    )
    assert graph.resolve(graph.session_a()).applicable_roles == ()
    # A different Organization in the same Tenant does not satisfy it.
    other_org = make_organization(tenant_id=graph.tenant_a)
    with graph.spi.create_unit_of_work() as uow:
        graph.spi.create_organization_repository(uow).add(other_org)
        uow.commit()
    assert (
        graph.resolve(graph.session_a(), target_organization_id=other_org.id).applicable_roles == ()
    )


def test_r08_organization_refined_grant_requires_typed_org_membership() -> None:
    graph = _seed()
    # Identity B has no IdentityOrgMembership for org_a; a direct org-refined
    # grant must not be effective even though the session Tenant matches.
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_multi.id,
        role_urn=graph.system_role.urn,
        organization_id=graph.org_a,
    )
    session = SessionContext(graph.tenant_a, graph.principal, graph.identity_multi.id)
    assert graph.resolve(session, target_organization_id=graph.org_a).applicable_roles == ()


def test_r09_tenant_wide_grant_is_included_for_an_organization_target() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
    )
    resolved = graph.resolve(graph.session_a(), target_organization_id=graph.org_a)
    assert [role.urn for role in resolved.applicable_roles] == [graph.system_role.urn]


def test_r10_tenant_role_assigned_outside_defining_tenant_fails_closed() -> None:
    graph = _seed()
    # Bypass the trusted persistence boundary: a Tenant-B-defined Role
    # assigned in Tenant A is corrupt context state and must fail closed,
    # never be silently treated as a non-match.
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.tenant_role_b.urn,
    )
    with pytest.raises(EffectiveRoleIntegrityError):
        graph.resolve(graph.session_a())


def test_r11_system_role_is_scoped_to_the_valid_tenant() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
    )
    _add_direct(
        graph,
        tenant_id=graph.tenant_b,
        identity_id=graph.identity_b.id,
        role_urn=graph.system_role.urn,
    )
    assert [role.urn for role in graph.resolve(graph.session_a()).applicable_roles] == [
        graph.system_role.urn
    ]
    assert [role.urn for role in graph.resolve(graph.session_b()).applicable_roles] == [
        graph.system_role.urn
    ]


def test_r12_deleted_group_prerequisite_yields_no_grant() -> None:
    graph = _seed()
    _join_group(graph, graph.identity_a.id, graph.group_a)
    _add_group(
        graph, tenant_id=graph.tenant_a, group_id=graph.group_a, role_urn=graph.system_role.urn
    )
    with graph.spi.create_unit_of_work() as uow:
        groups = graph.spi.create_group_repository(uow)
        group = groups.get(graph.group_a)
        assert group is not None
        group.soft_delete()
        groups.save(group)
        uow.commit()
    assert graph.resolve(graph.session_a()).applicable_roles == ()


def test_r12b_missing_group_tenant_membership_yields_no_grant() -> None:
    graph = _seed()
    # A Group with no GroupTenantMembership is a missing prerequisite: the
    # Identity may hold an IdentityGroupMembership row, but the Group's
    # Tenant membership is absent, so its Role assignments contribute
    # nothing.
    group_without_membership = make_group(tenant_id=graph.tenant_a)
    with graph.spi.create_unit_of_work() as uow:
        graph.spi.create_group_repository(uow).add(group_without_membership)
        uow.commit()
    _join_group(graph, graph.identity_a.id, group_without_membership.id)
    _add_group(
        graph,
        tenant_id=graph.tenant_a,
        group_id=group_without_membership.id,
        role_urn=graph.system_role.urn,
    )
    assert graph.resolve(graph.session_a()).applicable_roles == ()


def test_r13_duplicate_role_via_direct_and_group_is_one_effective_role() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
    )
    _join_group(graph, graph.identity_a.id, graph.group_a)
    _add_group(
        graph, tenant_id=graph.tenant_a, group_id=graph.group_a, role_urn=graph.system_role.urn
    )
    resolved = graph.resolve(graph.session_a())
    assert [role.urn for role in resolved.applicable_roles] == [graph.system_role.urn]
    assert len(resolved.applicable_roles) == 1


def test_r19_reordering_assignments_does_not_change_applicable_roles() -> None:
    graph = _seed()
    _join_group(graph, graph.identity_a.id, graph.group_a)
    _add_group(
        graph, tenant_id=graph.tenant_a, group_id=graph.group_a, role_urn=graph.tenant_role_a.urn
    )
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
    )
    first = graph.resolve(graph.session_a())
    second = graph.resolve(graph.session_a())
    assert first.applicable_roles == second.applicable_roles
    # Deterministic URN ordering; ordering is diagnostics only.
    assert [role.urn.value for role in first.applicable_roles] == sorted(
        role.urn.value for role in first.applicable_roles
    )


def test_session_and_cross_tenant_target_validation() -> None:
    graph = _seed()
    with pytest.raises(SessionContextError):
        graph.resolve(graph.session_a(), target_tenant_id=graph.tenant_b)
    with pytest.raises(TenantBoundaryError):
        graph.resolve(graph.session_a(), target_organization_id=graph.org_b)
    with pytest.raises(SessionContextError):
        graph.resolve(SessionContext(graph.tenant_a, graph.principal, graph.identity_b.id))


def test_build_authorization_context_carries_resolved_roles() -> None:
    graph = _seed()
    _add_direct(
        graph,
        tenant_id=graph.tenant_a,
        identity_id=graph.identity_a.id,
        role_urn=graph.system_role.urn,
    )
    state = graph.resolve(graph.session_a())
    context = build_authorization_context(state)
    assert context.applicable_roles == state.applicable_roles
    assert context.session == graph.session_a()
    assert context.tenant.id == graph.tenant_a
