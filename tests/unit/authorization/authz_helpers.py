"""Helpers for building authorization evaluation inputs in tests.

Builders reuse the shared ``helpers`` factories while constructing the
narrow internal request/context seam that PR 4 exposes.
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
    Action,
    AuthorizationContext,
    AuthorizationRequest,
    DomainId,
    DominanceRequirement,
    Identity,
    IdentityTenantMembership,
    PermissionEffect,
    PermissionSet,
    Principal,
    PrincipalTenantMembership,
    Role,
    RoleUrn,
    SecurityScope,
    SessionContext,
    Tenant,
    UnsupportedConstraint,
)


def make_action(
    *,
    resource: str = "principal",
    verb: str = "get",
    qualifier: str = "object",
) -> Action:
    """Build an exact SYSTEM Action from tame operation components."""
    return Action(make_action_urn(resource=resource, verb=verb, qualifier=qualifier))


def make_permission_set_with_rules(
    *,
    role_urn: RoleUrn,
    effect: PermissionEffect = PermissionEffect.ALLOW,
    rules: tuple[tuple[str, str], ...] = (("set", "*"),),
) -> PermissionSet:
    """Build a PermissionSet whose owned Permissions express ``rules``.

    Each rule is a ``(verb, qualifier)`` pair on the ``principal``
    resource. The PermissionSet id is generated first so every owned
    Permission points back at it (the PR 3 ownership invariant).
    """
    set_id = make_id()
    permissions = tuple(
        make_permission(permission_set_id=set_id, verb=verb, qualifier=qualifier)
        for verb, qualifier in rules
    )
    return PermissionSet(set_id, role_urn, effect, permissions)


def make_role_from_sets(
    *,
    role_urn: RoleUrn | None = None,
    tenant_id: DomainId | None = None,
    permission_sets: tuple[PermissionSet, ...] | None = None,
    role_name: str = "Example Role",
) -> Role:
    """Build a Role with consistent URN/structural definition ownership.

    ``tenant_id`` selects the TENANT definition namespace; ``None`` means
    the SYSTEM definition namespace.
    """
    urn = role_urn if role_urn is not None else make_role_urn(tenant_id=tenant_id)
    sets = (
        permission_sets
        if permission_sets is not None
        else (make_permission_set_with_rules(role_urn=urn),)
    )
    return Role(urn, role_name, "", tenant_id, sets)


def corrupt_role(role_urn: RoleUrn, permission_sets: tuple[PermissionSet, ...]) -> Role:
    """Build a Role that bypasses PR 3 construction validation.

    Used only to prove the evaluator fails closed on structurally
    corrupted policy (for example a PermissionSet owned by a different
    Role) instead of guessing an ALLOW.
    """
    role = object.__new__(Role)
    Role.__setattr__(role, "urn", role_urn)
    Role.__setattr__(role, "name", "corrupt")
    Role.__setattr__(role, "description", "")
    Role.__setattr__(role, "defining_tenant_id", None)
    Role.__setattr__(role, "permission_sets", permission_sets)
    Role.__setattr__(role, "extension", {})
    return role


def build_authorization_request(
    *,
    tenant: Tenant | None = None,
    principal: Principal | None = None,
    identity: Identity | None = None,
    session: SessionContext | None = None,
    principal_tenant_memberships: tuple[PrincipalTenantMembership, ...] | None = None,
    identity_tenant_memberships: tuple[IdentityTenantMembership, ...] | None = None,
    roles: tuple[Role, ...] = (),
    action: Action | None = None,
    target_tenant_id: DomainId | None = None,
    dominance_requirement: DominanceRequirement = DominanceRequirement.NONE,
    subject_scope: SecurityScope | None = None,
    target_scope: SecurityScope | None = None,
    unsupported_constraints: tuple[UnsupportedConstraint, ...] = (),
) -> AuthorizationRequest:
    """Build a structurally valid internal request by default.

    Every security-relevant component can be overridden to exercise the
    documented failure modes while keeping the remaining facts valid.
    """
    tenant = tenant if tenant is not None else make_tenant("A")
    principal = principal if principal is not None else make_principal()
    identity = identity if identity is not None else make_identity(principal_id=principal.id)
    session = (
        session if session is not None else SessionContext(tenant.id, principal.id, identity.id)
    )
    principal_tenant_memberships = (
        principal_tenant_memberships
        if principal_tenant_memberships is not None
        else (PrincipalTenantMembership(principal.id, tenant.id),)
    )
    identity_tenant_memberships = (
        identity_tenant_memberships
        if identity_tenant_memberships is not None
        else (IdentityTenantMembership(identity.id, tenant.id),)
    )
    context = AuthorizationContext(
        session,
        tenant,
        principal,
        identity,
        principal_tenant_memberships,
        identity_tenant_memberships,
        roles,
    )
    return AuthorizationRequest(
        context,
        action if action is not None else make_action(),
        target_tenant_id if target_tenant_id is not None else tenant.id,
        dominance_requirement,
        subject_scope,
        target_scope,
        unsupported_constraints,
    )
