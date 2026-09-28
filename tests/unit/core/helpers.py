"""Factory helpers shared by core domain tests.

Helpers keep test graphs readable while exercising the real public
constructors on ``mtmf_core``.
"""

from mtmf_core import (
    ActionUrn,
    DomainId,
    Group,
    Identity,
    Organization,
    Permission,
    PermissionEffect,
    PermissionSet,
    PermissionUrn,
    Principal,
    Role,
    RoleUrn,
    SecurityScope,
    Tenant,
)


def make_id() -> DomainId:
    """Return a fresh random domain identifier."""
    return DomainId.generate()


def make_tenant(
    name: str = "Tenant",
    scope: SecurityScope = SecurityScope.TENANT,
    *,
    owner: DomainId | None = None,
) -> Tenant:
    """Build a Tenant with a fresh ID and the given (default TENANT) scope."""
    return Tenant(make_id(), name, scope, owner if owner is not None else make_id())


def make_organization(
    name: str = "Organization",
    *,
    tenant_id: DomainId | None = None,
    owner: DomainId | None = None,
) -> Organization:
    """Build an Organization bound to ``tenant_id`` (fresh if omitted)."""
    return Organization(
        make_id(),
        tenant_id if tenant_id is not None else make_id(),
        name,
        owner if owner is not None else make_id(),
    )


def make_principal(name: str = "Principal") -> Principal:
    """Build a global Principal with a fresh ID."""
    return Principal(make_id(), name)


def make_identity(*, principal_id: DomainId | None = None, name: str = "Identity") -> Identity:
    """Build a global Identity for ``principal_id`` (fresh if omitted)."""
    return Identity(make_id(), principal_id if principal_id is not None else make_id(), name)


def make_group(name: str = "Group", *, tenant_id: DomainId | None = None) -> Group:
    """Build a Tenant-bound Group in ``tenant_id`` (fresh if omitted)."""
    return Group(make_id(), tenant_id if tenant_id is not None else make_id(), name)


def make_action_urn(
    *,
    resource: str = "principal",
    verb: str = "get",
    qualifier: str = "object",
) -> ActionUrn:
    """Build an exact SYSTEM Action URN from tame operation components."""
    return ActionUrn(f"urn:mtmf:iam:actions:system:{resource}:{verb}-{qualifier}")


def make_permission_urn(
    *,
    resource: str = "principal",
    verb: str = "get",
    qualifier: str = "object",
) -> PermissionUrn:
    """Build a SYSTEM Permission matcher URN from tame operation components."""
    return PermissionUrn(f"urn:mtmf:iam:permissions:system:{resource}:{verb}-{qualifier}")


def make_role_urn(
    *,
    tenant_id: DomainId | None = None,
    role_name: str = "example-admin",
) -> RoleUrn:
    """Build a SYSTEM or TENANT Role URN."""
    if tenant_id is None:
        return RoleUrn(f"urn:mtmf:iam:roles:system:{role_name}")
    return RoleUrn(f"urn:mtmf:iam:roles:tenant:{tenant_id}:{role_name}")


def make_permission(
    *,
    permission_set_id: DomainId | None = None,
    resource: str = "principal",
    verb: str = "get",
    qualifier: str = "object",
) -> Permission:
    """Build a Permission owned by ``permission_set_id`` (fresh if omitted)."""
    return Permission(
        make_id(),
        permission_set_id if permission_set_id is not None else make_id(),
        make_permission_urn(resource=resource, verb=verb, qualifier=qualifier),
    )


def make_permission_set(
    *,
    role_urn: RoleUrn | None = None,
    effect: PermissionEffect = PermissionEffect.ALLOW,
    permissions: tuple[Permission, ...] | None = None,
) -> PermissionSet:
    """Build a PermissionSet owned by ``role_urn`` (fresh Role if omitted)."""
    set_id = make_id()
    return PermissionSet(
        set_id,
        role_urn if role_urn is not None else make_role_urn(),
        effect,
        permissions if permissions is not None else (make_permission(permission_set_id=set_id),),
    )


def make_role(
    *,
    urn: RoleUrn | None = None,
    name: str = "Example Admin",
    description: str = "",
    tenant_id: DomainId | None = None,
    permission_sets: tuple[PermissionSet, ...] | None = None,
) -> Role:
    """Build a Role with consistent URN/structural definition ownership.

    ``tenant_id`` selects the TENANT definition namespace; ``None`` means
    the SYSTEM definition namespace.
    """
    role_urn = urn if urn is not None else make_role_urn(tenant_id=tenant_id)
    if permission_sets is None:
        permission_sets = (make_permission_set(role_urn=role_urn),)
    return Role(role_urn, name, description, tenant_id, permission_sets)
