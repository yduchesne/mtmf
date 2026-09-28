"""Factory helpers shared by core domain tests.

Helpers keep test graphs readable while exercising the real public
constructors on ``mtmf_core``.
"""

from mtmf_core import (
    DomainId,
    Group,
    Identity,
    Organization,
    Principal,
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
