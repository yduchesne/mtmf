"""Authorizer TenantManagementGroup delegation tests (PR 11).

These tests exercise the authoritative :class:`Authorizer` cross-Tenant
delegation path. A cross-Tenant evaluation is allowed only when the request
carries a positively resolved management scope (coverage + explicit actor
eligibility), the action is not an extension mutation, and the applicable
policy is exactly the approved management Role.
"""

from __future__ import annotations

from helpers import (
    make_action_urn,
    make_id,
    make_identity,
    make_permission,
    make_principal,
    make_role_urn,
    make_tenant,
)

from mtmf_core import (
    SYSTEM_MANAGEMENT_ROLE_URN,
    Action,
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationRequest,
    Authorizer,
    DenyReason,
    IdentityTenantMembership,
    ManagementScopeCandidate,
    ManagementScopeResolution,
    PermissionEffect,
    PermissionSet,
    PrincipalTenantMembership,
    Role,
    RoleUrn,
    SessionContext,
    TenantManagementScope,
)


def _management_role(
    *,
    role_urn: str = SYSTEM_MANAGEMENT_ROLE_URN,
    resource: str = "tenant",
    verb: str = "get",
    qualifier: str = "object",
    effect: PermissionEffect = PermissionEffect.ALLOW,
) -> Role:
    urn = RoleUrn(role_urn)
    set_id = make_id()
    permission = make_permission(
        permission_set_id=set_id,
        resource=resource,
        verb=verb,
        qualifier=qualifier,
    )
    permission_set = PermissionSet(set_id, urn, effect, (permission,))
    return Role(urn, "Tenant Management", "", None, (permission_set,))


def _context(*, manager_tenant, roles):
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    session = SessionContext(manager_tenant.id, principal.id, identity.id)
    return AuthorizationContext(
        session,
        manager_tenant,
        principal,
        identity,
        (PrincipalTenantMembership(principal.id, manager_tenant.id),),
        (IdentityTenantMembership(identity.id, manager_tenant.id),),
        roles,
    )


def _eligible_resolution(group_id):
    return ManagementScopeResolution(
        candidate=ManagementScopeCandidate(
            management_group_id=group_id,
            scope=TenantManagementScope.SYSTEM,
            management_role_urn=RoleUrn(SYSTEM_MANAGEMENT_ROLE_URN),
        ),
        actor_eligible=True,
        blocked_reason=None,
    )


def _request(context, action, target_tenant_id, *, management_scope=None):
    return AuthorizationRequest(
        context,
        action,
        target_tenant_id,
        management_scope=management_scope,
    )


def test_cross_tenant_without_management_scope_is_denied() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    context = _context(manager_tenant=manager, roles=(_management_role(),))
    decision = Authorizer().authorize(_request(context, Action(make_action_urn()), target.id))
    assert decision == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)


def test_cross_tenant_with_ineligible_actor_is_denied() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    context = _context(manager_tenant=manager, roles=(_management_role(),))
    resolution = ManagementScopeResolution(
        candidate=_eligible_resolution(make_id()).candidate,
        actor_eligible=False,
        blocked_reason="not eligible",
    )
    decision = Authorizer().authorize(
        _request(context, Action(make_action_urn()), target.id, management_scope=resolution)
    )
    assert decision == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)


def test_eligible_management_role_allow_cross_tenant() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    role = _management_role()
    context = _context(manager_tenant=manager, roles=(role,))
    action = Action(make_action_urn(resource="tenant", verb="get", qualifier="object"))
    decision = Authorizer().authorize(
        _request(context, action, target.id, management_scope=_eligible_resolution(make_id()))
    )
    assert decision.allowed is True


def test_eligible_management_role_without_matching_action_denied() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    role = _management_role()
    context = _context(manager_tenant=manager, roles=(role,))
    action = Action(make_action_urn(resource="tenant", verb="update", qualifier="object"))
    decision = Authorizer().authorize(
        _request(context, action, target.id, management_scope=_eligible_resolution(make_id()))
    )
    assert decision == AuthorizationDecision.deny(DenyReason.NO_MATCH)


def test_management_path_rejects_unioned_ordinary_role() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    management_role = _management_role()
    ordinary_role = make_role_urn()  # a different Role
    ordinary_set_id = make_id()
    ordinary_permission = make_permission(
        permission_set_id=ordinary_set_id, resource="tenant", verb="get", qualifier="object"
    )
    ordinary = Role(
        ordinary_role,
        "Ordinary",
        "",
        None,
        (
            PermissionSet(
                ordinary_set_id, ordinary_role, PermissionEffect.ALLOW, (ordinary_permission,)
            ),
        ),
    )
    context = _context(manager_tenant=manager, roles=(management_role, ordinary))
    action = Action(make_action_urn(resource="tenant", verb="get", qualifier="object"))
    decision = Authorizer().authorize(
        _request(context, action, target.id, management_scope=_eligible_resolution(make_id()))
    )
    assert decision == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)


def test_management_path_denies_extension_mutation() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    role = _management_role(resource="tenant", verb="update", qualifier="extension")
    context = _context(manager_tenant=manager, roles=(role,))
    action = Action(make_action_urn(resource="tenant", verb="update", qualifier="extension"))
    decision = Authorizer().authorize(
        _request(context, action, target.id, management_scope=_eligible_resolution(make_id()))
    )
    assert decision == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)


def test_management_path_preserves_matched_deny() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    role = _management_role(effect=PermissionEffect.DENY)
    context = _context(manager_tenant=manager, roles=(role,))
    action = Action(make_action_urn(resource="tenant", verb="get", qualifier="object"))
    decision = Authorizer().authorize(
        _request(context, action, target.id, management_scope=_eligible_resolution(make_id()))
    )
    assert decision.allowed is False
    assert decision.reason is DenyReason.MATCHED_DENY


def test_same_tenant_ordinary_path_unaffected() -> None:
    tenant = make_tenant("Tenant")
    role = _management_role(role_urn="urn:mtmf:iam:roles:system:tenant-reader")
    context = _context(manager_tenant=tenant, roles=(role,))
    action = Action(make_action_urn(resource="tenant", verb="get", qualifier="object"))
    decision = Authorizer().authorize(_request(context, action, tenant.id))
    assert decision.allowed is True
