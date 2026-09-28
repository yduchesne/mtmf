"""Unit tests for the global Identity entity (U02, U03, U05-U09, U13, U14)."""

import pytest
from helpers import make_id, make_identity, make_principal

from mtmf_core import DeletionStatus, DomainInvariantError, ImmutabilityError


def test_identity_references_exactly_one_principal() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    assert identity.principal_id == principal.id
    # A single structural principal_id is exposed, never a collection.
    assert not hasattr(identity, "principal_ids")


def test_identity_has_no_owning_tenant() -> None:
    assert not hasattr(make_identity(), "tenant_id")


def test_identity_has_no_embedded_relationship_state() -> None:
    identity = make_identity()
    for attribute in ("groups", "organizations", "roles", "tenants", "permissions"):
        assert not hasattr(identity, attribute)


def test_distinct_identities_may_share_a_name() -> None:
    principal = make_principal()
    first = make_identity(principal_id=principal.id, name="support")
    second = make_identity(principal_id=principal.id, name="support")
    assert first.id != second.id
    assert first.name == second.name


def test_identity_id_cannot_be_replaced() -> None:
    identity = make_identity()
    with pytest.raises(ImmutabilityError):
        identity.id = make_id()  # type: ignore[misc]


def test_identity_principal_reparent_rejected() -> None:
    identity = make_identity(principal_id=make_id())
    with pytest.raises(ImmutabilityError):
        identity.principal_id = make_id()  # type: ignore[misc]


def test_identity_name_is_mutable_without_affecting_principal() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id, name="old")
    identity.name = "new"
    assert identity.name == "new"
    assert identity.principal_id == principal.id


def test_new_identity_is_not_deleted() -> None:
    assert make_identity().deletion_status is DeletionStatus.NOT_DELETED


def test_soft_delete_preserves_identity_and_principal() -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    identity_id = identity.id
    identity.soft_delete()
    assert identity.deleted
    assert identity.id == identity_id
    assert identity.principal_id == principal.id


def test_double_soft_delete_rejected() -> None:
    identity = make_identity()
    identity.soft_delete()
    with pytest.raises(DomainInvariantError):
        identity.soft_delete()


def test_extension_defaults_are_independent() -> None:
    first = make_identity()
    second = make_identity()
    first.extension["claims"] = {"color": "blue"}
    assert second.extension == {}


def test_identity_has_no_federation_type_fields() -> None:
    # Local/federated Identity representation is UNRESOLVED (IdP design
    # territory); no provider or type fields may be invented here.
    identity = make_identity()
    assert not hasattr(identity, "identity_type")
    assert not hasattr(identity, "provider")
    assert not hasattr(identity, "federated")
