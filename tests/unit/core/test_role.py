"""Role domain object tests: definition namespace, ownership, mutation, scope limits."""

import pytest
from helpers import make_permission_set, make_role, make_role_urn

from mtmf_core import (
    DefinitionNamespace,
    DomainId,
    DomainInvariantError,
    ImmutabilityError,
    PermissionEffect,
    Role,
)


def test_system_role_consistency_valid() -> None:
    role = make_role(urn=make_role_urn(role_name="tenant-admin"))
    assert role.definition_namespace is DefinitionNamespace.SYSTEM
    assert role.defining_tenant_id is None
    assert role.urn.definition_namespace is DefinitionNamespace.SYSTEM


def test_tenant_role_consistency_valid() -> None:
    tenant = DomainId.generate()
    role = make_role(urn=make_role_urn(tenant_id=tenant), tenant_id=tenant)
    assert role.definition_namespace is DefinitionNamespace.TENANT
    assert role.defining_tenant_id == tenant
    assert role.urn.encoded_tenant_id == tenant


def test_system_role_with_structural_tenant_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        Role(
            make_role_urn(role_name="tenant-admin"),
            "Tenant Admin",
            defining_tenant_id=DomainId.generate(),
            permission_sets=(
                make_permission_set(role_urn=make_role_urn(role_name="tenant-admin")),
            ),
        )


def test_tenant_role_without_structural_tenant_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        Role(
            make_role_urn(tenant_id=DomainId.generate()),
            "Security Analyst",
            permission_sets=(
                make_permission_set(role_urn=make_role_urn(tenant_id=DomainId.generate())),
            ),
        )


def test_tenant_role_encoded_structural_mismatch_rejected() -> None:
    structural = DomainId.generate()
    other = DomainId.generate()
    with pytest.raises(DomainInvariantError):
        Role(
            make_role_urn(tenant_id=other),
            "Security Analyst",
            defining_tenant_id=structural,
            permission_sets=(make_permission_set(role_urn=make_role_urn(tenant_id=other)),),
        )


def test_role_has_no_security_scope() -> None:
    role = make_role()
    assert not hasattr(role, "scope")
    assert "scope" not in Role.__dataclass_fields__
    assert "security_scope" not in Role.__dataclass_fields__


def test_ordered_permission_sets_preserved() -> None:
    role_urn = make_role_urn(role_name="composite")
    first = make_permission_set(role_urn=role_urn, effect=PermissionEffect.ALLOW)
    second = make_permission_set(role_urn=role_urn, effect=PermissionEffect.DENY)
    role = make_role(urn=role_urn, permission_sets=(first, second))
    assert role.permission_sets == (first, second)


def test_permission_set_owner_matches_role_is_valid() -> None:
    role_urn = make_role_urn(role_name="owner")
    permission_set = make_permission_set(role_urn=role_urn)
    role = make_role(urn=role_urn, permission_sets=(permission_set,))
    assert role.permission_sets[0] is permission_set


def test_permission_set_owner_mismatch_rejected() -> None:
    role_urn = make_role_urn(role_name="owner")
    foreign = make_permission_set(role_urn=make_role_urn(role_name="other"))
    with pytest.raises(DomainInvariantError):
        make_role(urn=role_urn, permission_sets=(foreign,))


def test_empty_role_policy_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        Role(make_role_urn(), "Empty", permission_sets=())


def test_role_name_mutation_allowed() -> None:
    role = make_role(name="Before")
    role.name = "After"
    assert role.name == "After"


def test_role_description_mutation_allowed() -> None:
    role = make_role()
    role.description = "new description"
    assert role.description == "new description"


def test_role_urn_mutation_rejected() -> None:
    role = make_role()
    with pytest.raises(ImmutabilityError):
        role.urn = make_role_urn(role_name="other")  # type: ignore[misc]


def test_role_structural_tenant_mutation_rejected() -> None:
    tenant = DomainId.generate()
    role = make_role(urn=make_role_urn(tenant_id=tenant), tenant_id=tenant)
    with pytest.raises(ImmutabilityError):
        role.defining_tenant_id = DomainId.generate()  # type: ignore[misc]


def test_role_extension_defaults_are_independent() -> None:
    first = make_role()
    second = make_role()
    assert first.extension == {}
    assert second.extension == {}
    first.extension["tenant"] = "custom"  # type: ignore[index]
    assert second.extension == {}
    assert first.extension["tenant"] == "custom"  # type: ignore[index]


def test_role_extension_is_opaque() -> None:
    role = make_role()
    role.extension["favorite"] = "value"  # type: ignore[index]
    assert role.extension["favorite"] == "value"  # type: ignore[index]


def test_role_has_no_assignment_state() -> None:
    role = make_role()
    for absent in ("assignments", "identity_ids", "group_ids", "roles"):
        assert not hasattr(role, absent)
        assert absent not in Role.__dataclass_fields__
