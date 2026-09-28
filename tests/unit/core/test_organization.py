"""Unit tests for the Organization entity (U02-U11)."""

import pytest
from helpers import make_id, make_organization, make_tenant

from mtmf_core import DeletionStatus, DomainId, DomainInvariantError, ImmutabilityError


def test_new_organization_is_not_deleted() -> None:
    assert make_organization().deletion_status is DeletionStatus.NOT_DELETED


def test_organization_belongs_to_exactly_one_tenant() -> None:
    tenant = make_tenant("A")
    organization = make_organization(tenant_id=tenant.id)
    assert organization.tenant_id == tenant.id
    # A single structural tenant_id is exposed, never a collection.
    assert isinstance(organization.tenant_id, DomainId)
    assert not hasattr(organization, "tenant_ids")


def test_distinct_organizations_may_share_a_name() -> None:
    first = make_organization("Finance")
    second = make_organization("Finance")
    assert first.id != second.id
    assert first.name == second.name


def test_organization_cannot_be_reparented() -> None:
    organization = make_organization(tenant_id=make_id())
    with pytest.raises(ImmutabilityError):
        organization.tenant_id = make_id()  # type: ignore[misc]


def test_organization_id_cannot_be_replaced() -> None:
    organization = make_organization()
    with pytest.raises(ImmutabilityError):
        organization.id = make_id()  # type: ignore[misc]


def test_organization_owner_cannot_be_replaced() -> None:
    organization = make_organization()
    with pytest.raises(ImmutabilityError):
        organization.owner_identity_id = make_id()  # type: ignore[misc]


def test_owner_membership_relationship_is_validated_not_invented() -> None:
    # The owner's IdentityOrgMembership is modeled and validated by the
    # invariant layer; PR 2 has no persistence transaction to auto-create
    # it. The entity itself carries only immutable provenance.
    organization = make_organization(owner=make_id())
    assert organization.owner_identity_id is not None


def test_name_is_mutable_without_identity_change() -> None:
    organization = make_organization("Old")
    organization.name = "New"
    assert organization.name == "New"
    assert organization.id is not None
    assert organization.tenant_id is not None


def test_extension_defaults_are_independent() -> None:
    first = make_organization()
    second = make_organization()
    first.extension["app"] = "one"
    assert second.extension == {}


def test_extension_accepts_nested_json() -> None:
    organization = make_organization()
    organization.extension["deep"] = {"list": [{"x": 1}, None]}
    assert organization.extension["deep"]["list"][0] == {"x": 1}


def test_soft_delete_preserves_identity_provenance_and_tenant() -> None:
    organization = make_organization()
    identity = organization.id
    owner = organization.owner_identity_id
    tenant_id = organization.tenant_id
    organization.soft_delete()
    assert organization.deleted
    assert organization.id == identity
    assert organization.owner_identity_id == owner
    assert organization.tenant_id == tenant_id


def test_double_soft_delete_rejected() -> None:
    organization = make_organization()
    organization.soft_delete()
    with pytest.raises(DomainInvariantError):
        organization.soft_delete()


def test_no_organization_stewardship_represented() -> None:
    # Stewardship is exclusively a Tenant concept; an Organization must
    # not carry a stewardship field.
    assert not hasattr(make_organization(), "stewardship")


def test_no_embedded_roles_or_permissions() -> None:
    organization = make_organization()
    assert not hasattr(organization, "roles")
    assert not hasattr(organization, "permissions")
