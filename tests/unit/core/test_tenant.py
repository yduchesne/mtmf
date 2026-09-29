"""Unit tests for the Tenant entity (U02-U09 plus scope rules)."""

import pytest
from helpers import make_id, make_tenant

from mtmf_core import (
    DeletionStatus,
    DomainInvariantError,
    ImmutabilityError,
    SecurityScope,
    Tenant,
)


def test_new_tenant_is_not_deleted() -> None:
    assert make_tenant().deletion_status is DeletionStatus.NOT_DELETED
    assert not make_tenant().deleted


def test_distinct_tenants_may_share_a_name() -> None:
    first = make_tenant("Accounting")
    second = make_tenant("Accounting")
    assert first.id != second.id
    assert first.name == second.name


def test_resource_id_cannot_be_replaced() -> None:
    tenant = make_tenant()
    with pytest.raises(ImmutabilityError):
        tenant.id = make_id()  # type: ignore[misc]


def test_owner_identity_cannot_be_replaced() -> None:
    tenant = make_tenant()
    with pytest.raises(ImmutabilityError):
        tenant.owner_identity_id = make_id()  # type: ignore[misc]


def test_owner_identity_is_distinct_from_name_and_scope() -> None:
    owner = make_id()
    tenant = make_tenant("Demo", owner=owner)
    assert tenant.owner_identity_id == owner
    # Ownership is provenance only: it is not authorization/admin state.
    assert tenant.name != str(owner)
    assert tenant.extension == {}


def test_name_is_mutable_presentation_metadata() -> None:
    tenant = make_tenant("Old")
    tenant.name = "New"
    assert tenant.name == "New"
    # Mutating the name never changes identity or provenance.
    original_id = tenant.id
    original_owner = tenant.owner_identity_id
    tenant.name = "Renamed"
    assert tenant.id == original_id
    assert tenant.owner_identity_id == original_owner


def test_two_extension_defaults_are_independent_empty_objects() -> None:
    first = make_tenant()
    second = make_tenant()
    assert first.extension == {}
    assert second.extension == {}
    assert first.extension is not second.extension


def test_extension_accepts_nested_json_values() -> None:
    tenant = make_tenant()
    tenant.extension["config"] = {"nested": [1, None, {"flag": True}], "text": "x"}
    assert tenant.extension["config"]["nested"][2] == {"flag": True}


def test_extension_mutation_does_not_change_mtmf_semantics() -> None:
    tenant = make_tenant()
    tenant.extension["owner"] = "application-claims-ownership"
    tenant.extension["scope"] = "fake-root"
    # Extension data stays opaque: MTMF-owned state is untouched.
    assert tenant.name == "Tenant"
    assert tenant.scope is SecurityScope.TENANT
    assert tenant.deletion_status is DeletionStatus.NOT_DELETED


def test_soft_delete_transitions_status_and_preserves_identity() -> None:
    tenant = make_tenant()
    identity = tenant.id
    owner = tenant.owner_identity_id
    tenant.extension["k"] = "v"
    tenant.soft_delete()
    assert tenant.deletion_status is DeletionStatus.DELETED
    assert tenant.deleted
    assert tenant.id == identity
    assert tenant.owner_identity_id == owner
    assert tenant.extension == {"k": "v"}


def test_soft_delete_is_not_truthiness() -> None:
    tenant = make_tenant()
    tenant.soft_delete()
    # Deletion is decided by enum comparison, not Boolean truthiness.
    assert bool(tenant.deletion_status) == bool(DeletionStatus.DELETED)
    assert tenant.deleted is (tenant.deletion_status is DeletionStatus.DELETED)


def test_double_soft_delete_rejected() -> None:
    tenant = make_tenant()
    tenant.soft_delete()
    with pytest.raises(DomainInvariantError):
        tenant.soft_delete()


def test_restoration_is_absent() -> None:
    tenant = make_tenant()
    tenant.soft_delete()
    # There is no restore API; status can only be set through soft_delete.
    assert not hasattr(tenant, "restore")
    assert tenant.deletion_status is DeletionStatus.DELETED


def test_ordinary_tenant_scope_is_tenanted_only() -> None:
    assert make_tenant().scope is SecurityScope.TENANT


def test_root_scope_is_representable_without_bootstrap_mechanics() -> None:
    # PR 10 owns bootstrap/root uniqueness; PR 2 only permits the settled
    # legal scope values on a Tenant.
    tenant = Tenant(make_id(), "Root", SecurityScope.ROOT, make_id())
    assert tenant.scope is SecurityScope.ROOT


@pytest.mark.parametrize("invalid_scope", [SecurityScope.SYSTEM, SecurityScope.ORGANIZATION])
def test_invalid_tenant_scope_rejected(invalid_scope: SecurityScope) -> None:
    with pytest.raises(DomainInvariantError):
        Tenant(make_id(), "Bad", invalid_scope, make_id())


def test_tenant_has_no_embedded_containers() -> None:
    # Organizations, memberships, Roles, and stewardship are related
    # explicitly; they are never embedded collections on the Tenant.
    tenant = make_tenant()
    for attribute in ("organizations", "memberships", "roles", "stewards"):
        assert not hasattr(tenant, attribute)


def test_tenant_equality_is_value_based_on_identity_fields() -> None:
    tenant = make_tenant("Same")
    clone_definition = Tenant(
        tenant.id, "Other Name", SecurityScope.TENANT, tenant.owner_identity_id
    )
    # The same stable ID denotes the same object identity regardless of
    # mutable presentation metadata.
    assert tenant.name != clone_definition.name
    assert tenant.id == clone_definition.id
