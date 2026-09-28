"""Unit tests for the global Principal entity (U02, U03, U05-U09, U12)."""

import pytest
from helpers import make_id, make_principal

from mtmf_core import DeletionStatus, DomainInvariantError, ImmutabilityError


def test_principal_has_no_owning_tenant() -> None:
    principal = make_principal()
    # A global Principal is never tenant-owned and exposes no tenant_id.
    assert not hasattr(principal, "tenant_id")
    assert not hasattr(principal, "tenant_ids")


def test_principal_has_no_organization_or_group_ownership() -> None:
    principal = make_principal()
    assert not hasattr(principal, "organizations")
    assert not hasattr(principal, "groups")
    assert not hasattr(principal, "role_assignments")


def test_distinct_principals_may_share_a_name() -> None:
    first = make_principal("robot")
    second = make_principal("robot")
    assert first.id != second.id
    assert first.name == second.name


def test_principal_id_cannot_be_replaced() -> None:
    principal = make_principal()
    with pytest.raises(ImmutabilityError):
        principal.id = make_id()  # type: ignore[misc]


def test_principal_name_is_mutable() -> None:
    principal = make_principal("old")
    principal.name = "new"
    assert principal.name == "new"


def test_new_principal_is_not_deleted() -> None:
    assert make_principal().deletion_status is DeletionStatus.NOT_DELETED


def test_soft_delete_preserves_identity() -> None:
    principal = make_principal()
    identity = principal.id
    principal.soft_delete()
    assert principal.deleted
    assert principal.id == identity


def test_double_soft_delete_rejected() -> None:
    principal = make_principal()
    principal.soft_delete()
    with pytest.raises(DomainInvariantError):
        principal.soft_delete()


def test_extension_defaults_are_independent_and_mutable() -> None:
    first = make_principal()
    second = make_principal()
    first.extension["customers"] = [1, 2]
    assert second.extension == {}
    assert first.extension == {"customers": [1, 2]}


def test_no_principal_kind_field() -> None:
    # Principal kinds (human/service/agent) remain UNRESOLVED.
    assert not hasattr(make_principal(), "kind")


def test_principal_does_not_model_identity_provider_fields() -> None:
    principal = make_principal()
    assert not hasattr(principal, "idp")
    assert not hasattr(principal, "provider")
