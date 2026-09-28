"""Unit tests for SessionContext and structural validation (U33-U38)."""

import pytest
from helpers import make_id, make_identity, make_principal, make_tenant

from mtmf_core import (
    IdentityTenantMembership,
    PrincipalTenantMembership,
    SessionContext,
    SessionContextError,
    validate_session_context,
)


def _session_fixture():
    """Return tenant, principal, identity, and both membership sets."""
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    principal_memberships = [PrincipalTenantMembership(principal.id, tenant.id)]
    identity_memberships = [IdentityTenantMembership(identity.id, tenant.id)]
    return tenant, principal, identity, principal_memberships, identity_memberships


def test_valid_session_structure_accepted() -> None:
    tenant, principal, identity, principal_memberships, identity_memberships = _session_fixture()
    session = SessionContext(tenant.id, principal.id, identity.id)
    validate_session_context(
        session, tenant, principal, identity, principal_memberships, identity_memberships
    )


def test_session_uses_stable_ids_not_names() -> None:
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    session = SessionContext(tenant.id, principal.id, identity.id)
    assert session.tenant_id == tenant.id
    assert session.principal_id == principal.id
    assert session.identity_id == identity.id


def test_session_tenant_mismatch_rejected() -> None:
    tenant, principal, identity, principal_memberships, identity_memberships = _session_fixture()
    session = SessionContext(make_id(), principal.id, identity.id)
    with pytest.raises(SessionContextError):
        validate_session_context(
            session, tenant, principal, identity, principal_memberships, identity_memberships
        )


def test_session_principal_mismatch_rejected() -> None:
    tenant, principal, identity, principal_memberships, identity_memberships = _session_fixture()
    session = SessionContext(tenant.id, make_id(), identity.id)
    with pytest.raises(SessionContextError):
        validate_session_context(
            session, tenant, principal, identity, principal_memberships, identity_memberships
        )


def test_session_identity_mismatch_rejected() -> None:
    tenant, principal, identity, principal_memberships, identity_memberships = _session_fixture()
    session = SessionContext(tenant.id, principal.id, make_id())
    with pytest.raises(SessionContextError):
        validate_session_context(
            session, tenant, principal, identity, principal_memberships, identity_memberships
        )


def test_session_identity_belonging_to_wrong_principal_rejected() -> None:
    # U34: Identity belongs to Principal B; the session names Principal A.
    tenant = make_tenant("A")
    principal_a = make_principal()
    principal_b = make_principal()
    identity = make_identity(principal_id=principal_b.id)
    session = SessionContext(tenant.id, principal_a.id, identity.id)
    with pytest.raises(SessionContextError):
        validate_session_context(session, tenant, principal_a, identity, [], [])


def test_session_principal_membership_wrong_tenant_rejected() -> None:
    # U35: Principal membership exists only for another Tenant.
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    session = SessionContext(tenant.id, principal.id, identity.id)
    principal_memberships = [PrincipalTenantMembership(principal.id, make_id())]
    identity_memberships = [IdentityTenantMembership(identity.id, tenant.id)]
    with pytest.raises(SessionContextError):
        validate_session_context(
            session, tenant, principal, identity, principal_memberships, identity_memberships
        )


def test_session_identity_membership_wrong_tenant_rejected() -> None:
    # U36: Identity membership exists only for another Tenant.
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    session = SessionContext(tenant.id, principal.id, identity.id)
    principal_memberships = [PrincipalTenantMembership(principal.id, tenant.id)]
    identity_memberships = [IdentityTenantMembership(identity.id, make_id())]
    with pytest.raises(SessionContextError):
        validate_session_context(
            session, tenant, principal, identity, principal_memberships, identity_memberships
        )


def test_sibling_identity_lacks_session_tenant_membership() -> None:
    # U37: Only a sibling of the acting Identity has the Tenant
    # membership; the acting Identity does not inherit it.
    tenant = make_tenant("A")
    principal = make_principal()
    sibling = make_identity(principal_id=principal.id)
    acting = make_identity(principal_id=principal.id)
    principal_memberships = [PrincipalTenantMembership(principal.id, tenant.id)]
    identity_memberships = [IdentityTenantMembership(sibling.id, tenant.id)]
    session = SessionContext(tenant.id, principal.id, acting.id)
    with pytest.raises(SessionContextError):
        validate_session_context(
            session, tenant, principal, acting, principal_memberships, identity_memberships
        )


def test_session_has_no_effective_authorization_embedded() -> None:
    # U38: The session carries the three stable IDs and nothing else.
    assert set(SessionContext.__dataclass_fields__) == {
        "tenant_id",
        "principal_id",
        "identity_id",
    }
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    session = SessionContext(tenant.id, principal.id, identity.id)
    for attribute in ("roles", "permissions", "groups", "authorization", "token", "active"):
        assert not hasattr(session, attribute)


def test_session_validation_never_unions_another_tenant_state() -> None:
    tenant_a = make_tenant("A")
    tenant_b = make_tenant("B")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    # Principal and Identity are members of B; the session Tenant is A.
    session = SessionContext(tenant_a.id, principal.id, identity.id)
    principal_memberships = [PrincipalTenantMembership(principal.id, tenant_b.id)]
    identity_memberships = [IdentityTenantMembership(identity.id, tenant_b.id)]
    with pytest.raises(SessionContextError):
        validate_session_context(
            session, tenant_a, principal, identity, principal_memberships, identity_memberships
        )
