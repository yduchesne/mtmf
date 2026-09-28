"""Unit tests for the tenant-bound Group entity (U02-U09, U15, U16)."""

import pytest
from helpers import make_group, make_id, make_tenant

from mtmf_core import DeletionStatus, DomainInvariantError, ImmutabilityError, SecurityScope


def test_group_is_tenant_bound() -> None:
    tenant = make_tenant("A")
    group = make_group(tenant_id=tenant.id)
    assert group.tenant_id == tenant.id
    assert not hasattr(group, "tenant_ids")


def test_group_has_tenant_security_scope() -> None:
    assert make_group().scope is SecurityScope.TENANT


def test_group_does_not_embed_members() -> None:
    # Members are explicit IdentityGroupMembership relationships only.
    assert not hasattr(make_group(), "members")
    assert not hasattr(make_group(), "identity_ids")


def test_group_has_no_nested_group_support() -> None:
    group = make_group()
    assert not hasattr(group, "parent_group_id")
    assert not hasattr(group, "child_groups")


def test_group_does_not_contain_principals() -> None:
    assert not hasattr(make_group(), "principal_ids")


def test_distinct_groups_may_share_a_name() -> None:
    tenant = make_tenant("A")
    first = make_group(name="operators", tenant_id=tenant.id)
    second = make_group(name="operators", tenant_id=tenant.id)
    assert first.id != second.id
    assert first.name == second.name


def test_group_id_and_tenant_cannot_be_replaced() -> None:
    group = make_group()
    with pytest.raises(ImmutabilityError):
        group.id = make_id()  # type: ignore[misc]
    with pytest.raises(ImmutabilityError):
        group.tenant_id = make_id()  # type: ignore[misc]


def test_group_name_is_mutable() -> None:
    group = make_group("old")
    group.name = "new"
    assert group.name == "new"
    assert group.tenant_id is not None


def test_new_group_is_not_deleted() -> None:
    assert make_group().deletion_status is DeletionStatus.NOT_DELETED


def test_soft_delete_preserves_identity_and_tenant() -> None:
    group = make_group()
    group_id = group.id
    tenant_id = group.tenant_id
    group.soft_delete()
    assert group.deleted
    assert group.id == group_id
    assert group.tenant_id == tenant_id


def test_double_soft_delete_rejected() -> None:
    group = make_group()
    group.soft_delete()
    with pytest.raises(DomainInvariantError):
        group.soft_delete()


def test_extension_defaults_are_independent() -> None:
    first = make_group()
    second = make_group()
    first.extension["tags"] = ["a", "b"]
    assert second.extension == {}
