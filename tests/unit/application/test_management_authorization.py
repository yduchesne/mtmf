"""Application-layer delegated-authorization orchestration tests (PR 11).

These build a real in-memory persistence graph (manager/target/root
Tenants, the approved management Role, a SYSTEM management group, an
explicit managed-Tenant relationship, and an Identity eligibility
designation) and prove the full slice from persisted facts through
:class:`ManagementAuthorizationResolver` into the authoritative
:class:`Authorizer`.
"""

from __future__ import annotations

from helpers import (
    make_action_urn,
    make_id,
    make_identity,
    make_permission,
    make_principal,
    make_tenant,
)

from mtmf_core import (
    ROOT_MANAGEMENT_ROLE_URN,
    SYSTEM_MANAGEMENT_ROLE_URN,
    Action,
    AuthorizationDecision,
    AuthorizationRequest,
    Authorizer,
    DenyReason,
    IdentityTenantMembership,
    InMemoryMtmfSpi,
    ManagementAuthorizationResolver,
    PermissionEffect,
    PermissionSet,
    PrincipalTenantMembership,
    Role,
    RoleUrn,
    SecurityScope,
    SessionContext,
    Tenant,
    TenantManagementGroup,
    TenantManagementGroupActorEligibility,
    TenantManagementGroupMembership,
    TenantManagementScope,
)


def _management_role(role_urn: str) -> Role:
    urn = RoleUrn(role_urn)
    set_id = make_id()
    permission = make_permission(
        permission_set_id=set_id, resource="tenant", verb="get", qualifier="object"
    )
    return Role(
        urn,
        "Management",
        "",
        None,
        (PermissionSet(set_id, urn, PermissionEffect.ALLOW, (permission,)),),
    )


def _seed_tenants(spi, tenant: Tenant) -> None:
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()


def _request(context, action, target_tenant_id, resolution):
    return AuthorizationRequest(context, action, target_tenant_id, management_scope=resolution)


def test_system_delegation_positive_slice() -> None:
    spi = InMemoryMtmfSpi()
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    for tenant in (root, manager, target):
        _seed_tenants(spi, tenant)

    role = _management_role(SYSTEM_MANAGEMENT_ROLE_URN)
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    group = TenantManagementGroup(
        make_id(), manager.id, RoleUrn(SYSTEM_MANAGEMENT_ROLE_URN), TenantManagementScope.SYSTEM
    )
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        spi.create_tenant_management_group_repository(uow).add(group)
        spi.create_tenant_management_group_membership_repository(uow).add(
            TenantManagementGroupMembership(make_id(), group.id, target.id)
        )
        spi.create_tenant_management_group_actor_eligibility_repository(uow).add(
            TenantManagementGroupActorEligibility(make_id(), group.id, identity.id)
        )
        uow.commit()

    session = SessionContext(manager.id, principal.id, identity.id)
    resolution = ManagementAuthorizationResolver(spi).resolve(
        session=session,
        target_tenant_id=target.id,
        manager_tenant=manager,
        manager_principal=principal,
        manager_identity=identity,
        principal_tenant_memberships=(PrincipalTenantMembership(principal.id, manager.id),),
        identity_tenant_memberships=(IdentityTenantMembership(identity.id, manager.id),),
        target_tenant=target,
        canonical_root_tenant_id=root.id,
        canonical_root_identity_id=None,
    )
    assert resolution.is_elevated is True
    assert resolution.context.applicable_roles == (role,)
    action = Action(make_action_urn(resource="tenant", verb="get", qualifier="object"))
    decision = Authorizer().authorize(
        _request(resolution.context, action, target.id, resolution.management_scope)
    )
    assert decision.allowed is True


def test_system_delegation_negative_without_eligibility() -> None:
    spi = InMemoryMtmfSpi()
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    for tenant in (root, manager, target):
        _seed_tenants(spi, tenant)

    role = _management_role(SYSTEM_MANAGEMENT_ROLE_URN)
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    group = TenantManagementGroup(
        make_id(), manager.id, RoleUrn(SYSTEM_MANAGEMENT_ROLE_URN), TenantManagementScope.SYSTEM
    )
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        spi.create_tenant_management_group_repository(uow).add(group)
        spi.create_tenant_management_group_membership_repository(uow).add(
            TenantManagementGroupMembership(make_id(), group.id, target.id)
        )
        uow.commit()

    session = SessionContext(manager.id, principal.id, identity.id)
    resolution = ManagementAuthorizationResolver(spi).resolve(
        session=session,
        target_tenant_id=target.id,
        manager_tenant=manager,
        manager_principal=principal,
        manager_identity=identity,
        principal_tenant_memberships=(PrincipalTenantMembership(principal.id, manager.id),),
        identity_tenant_memberships=(IdentityTenantMembership(identity.id, manager.id),),
        target_tenant=target,
        canonical_root_tenant_id=root.id,
        canonical_root_identity_id=None,
    )
    assert resolution.is_elevated is False
    assert resolution.context.applicable_roles == ()
    action = Action(make_action_urn(resource="tenant", verb="get", qualifier="object"))
    decision = Authorizer().authorize(
        _request(resolution.context, action, target.id, resolution.management_scope)
    )
    assert decision == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)


def test_root_delegation_uses_canonical_identity() -> None:
    spi = InMemoryMtmfSpi()
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    target = make_tenant("Target")
    for tenant in (root, target):
        _seed_tenants(spi, tenant)

    role = _management_role(ROOT_MANAGEMENT_ROLE_URN)
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    group = TenantManagementGroup(
        make_id(), root.id, RoleUrn(ROOT_MANAGEMENT_ROLE_URN), TenantManagementScope.ROOT
    )
    with spi.create_unit_of_work() as uow:
        spi.create_role_repository(uow).add(role)
        spi.create_tenant_management_group_repository(uow).add(group)
        uow.commit()

    session = SessionContext(root.id, principal.id, identity.id)
    resolution = ManagementAuthorizationResolver(spi).resolve(
        session=session,
        target_tenant_id=target.id,
        manager_tenant=root,
        manager_principal=principal,
        manager_identity=identity,
        principal_tenant_memberships=(PrincipalTenantMembership(principal.id, root.id),),
        identity_tenant_memberships=(IdentityTenantMembership(identity.id, root.id),),
        target_tenant=target,
        canonical_root_tenant_id=root.id,
        canonical_root_identity_id=identity.id,
    )
    assert resolution.is_elevated is True
    assert resolution.context.applicable_roles == (role,)
