"""Typed IAM URN parsing/validation tests (Role, Action, Permission)."""

from dataclasses import FrozenInstanceError

import pytest
from helpers import make_role_urn

from mtmf_core import (
    ActionUrn,
    DefinitionNamespace,
    DomainId,
    DomainInvariantError,
    PermissionUrn,
    RoleUrn,
)

SYSTEM_ROLE = "urn:mtmf:iam:roles:system:tenant-admin"
TENANT_ROLE_TAIL = "roles:tenant:{tenant}:security-analyst"


def _tenant_role(tenant: DomainId) -> str:
    return f"urn:mtmf:iam:{TENANT_ROLE_TAIL.format(tenant=tenant)}"


# --- Role URNs (U07-U11) -------------------------------------------------------


def test_system_role_urn_valid() -> None:
    role_urn = RoleUrn(SYSTEM_ROLE)
    assert str(role_urn) == SYSTEM_ROLE
    assert role_urn.definition_namespace is DefinitionNamespace.SYSTEM
    assert role_urn.encoded_tenant_id is None
    assert role_urn.role_name == "tenant-admin"


def test_tenant_role_urn_valid() -> None:
    tenant = DomainId.generate()
    role_urn = RoleUrn(_tenant_role(tenant))
    assert role_urn.definition_namespace is DefinitionNamespace.TENANT
    assert role_urn.encoded_tenant_id == tenant
    assert role_urn.role_name == "security-analyst"


def test_tenant_role_urn_missing_tenant_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:iam:roles:tenant:security-analyst")


def test_malformed_tenant_id_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:iam:roles:tenant:not-a-uuid:security-analyst")


def test_wildcard_role_urn_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:iam:roles:system:admin-*")
    with pytest.raises(DomainInvariantError):
        RoleUrn(f"urn:mtmf:iam:roles:tenant:{DomainId.generate()}:admin-*")
    with pytest.raises(DomainInvariantError):
        RoleUrn(f"urn:mtmf:iam:roles:tenant:{DomainId.generate()}:*admin")


def test_wrong_kind_prefix_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:iam:role:system:admin")
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:other:roles:system:admin")


def test_unknown_role_namespace_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:iam:roles:global:admin")


def test_empty_role_name_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:iam:roles:system:")


def test_whitespace_components_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:iam:roles:system:admin name")
    with pytest.raises(DomainInvariantError):
        RoleUrn(f"urn:mtmf:iam:roles:tenant:{DomainId.generate()}:a b")


def test_unexpected_role_components_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn("urn:mtmf:iam:roles:system:admin:extra")
    with pytest.raises(DomainInvariantError):
        RoleUrn(f"urn:mtmf:iam:roles:tenant:{DomainId.generate()}:name:extra")


def test_empty_component_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        RoleUrn(f"urn:mtmf:iam:roles:tenant::{DomainId.generate()}:name")


def test_role_urn_equality_and_hash() -> None:
    assert RoleUrn(SYSTEM_ROLE) == RoleUrn(SYSTEM_ROLE)
    assert hash(RoleUrn(SYSTEM_ROLE)) == hash(RoleUrn(SYSTEM_ROLE))
    assert RoleUrn(SYSTEM_ROLE) != RoleUrn("urn:mtmf:iam:roles:system:reader")


def test_role_urn_immutable() -> None:
    role_urn = RoleUrn(SYSTEM_ROLE)
    with pytest.raises(FrozenInstanceError):
        role_urn.value = "urn:mtmf:iam:roles:system:reader"  # type: ignore[misc]


def test_role_urn_helper_round_trip() -> None:
    tenant = DomainId.generate()
    system = make_role_urn(role_name="example-admin")
    tenant_role = make_role_urn(tenant_id=tenant, role_name="example-admin")
    assert system.definition_namespace is DefinitionNamespace.SYSTEM
    assert tenant_role.encoded_tenant_id == tenant


# --- Action URNs (U12-U16) -------------------------------------------------------


def test_exact_action_urn_valid() -> None:
    action_urn = ActionUrn("urn:mtmf:iam:actions:system:principal:set-active")
    assert action_urn.definition_namespace is DefinitionNamespace.SYSTEM
    assert action_urn.resource == "principal"
    assert action_urn.verb == "set"
    assert action_urn.qualifier == "active"
    assert action_urn.operation == "set-active"
    assert str(action_urn) == "urn:mtmf:iam:actions:system:principal:set-active"


def test_action_qualifier_wildcard_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal:set-*")


def test_action_wildcard_resource_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:*:set-alias")


def test_action_wildcard_verb_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal:*-alias")


def test_action_partial_wildcard_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal:set-a*")


def test_action_missing_qualifier_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal:set-")


def test_action_missing_verb_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal:-alias")


def test_action_unsupported_tenant_namespace_rejected() -> None:
    # Tenant-defined Action layout is unspecified; it must fail closed.
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:tenant:principal:set-alias")


def test_action_unknown_namespace_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:global:principal:set-alias")


def test_action_urn_wrong_component_count_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal")
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal:set-active:extra")


def test_action_urn_immutable() -> None:
    action_urn = ActionUrn("urn:mtmf:iam:actions:system:principal:set-active")
    with pytest.raises(FrozenInstanceError):
        action_urn.value = "urn:mtmf:iam:actions:system:principal:set-alias"  # type: ignore[misc]


def test_permission_urn_cannot_pass_as_action() -> None:
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:permissions:system:principal:set-alias")


# --- Permission URNs (U17-U22) ---------------------------------------------------


def test_exact_permission_urn_valid() -> None:
    permission_urn = PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-alias")
    assert permission_urn.definition_namespace is DefinitionNamespace.SYSTEM
    assert permission_urn.resource == "principal"
    assert permission_urn.verb == "set"
    assert permission_urn.qualifier == "alias"
    assert not permission_urn.is_wildcard


def test_wildcard_qualifier_permission_urn_valid() -> None:
    permission_urn = PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-*")
    assert permission_urn.verb == "set"
    assert permission_urn.qualifier == "*"
    assert permission_urn.is_wildcard


def test_wildcard_verb_permission_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:principal:*-alias")


def test_wildcard_resource_permission_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:*:set-alias")


def test_partial_qualifier_wildcard_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-a*")
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-*-name")


def test_missing_permission_qualifier_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-")


def test_missing_permission_verb_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:principal:-alias")


def test_permission_unsupported_tenant_namespace_rejected() -> None:
    # Tenant-defined Permission namespace semantics are unspecified.
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:tenant:principal:set-alias")


def test_permission_urn_immutable() -> None:
    permission_urn = PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-*")
    with pytest.raises(FrozenInstanceError):
        permission_urn.value = "urn:mtmf:iam:permissions:system:principal:delete-*"  # type: ignore[misc]


def test_permission_urn_operation_and_str() -> None:
    permission_urn = PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-*")
    assert permission_urn.operation == "set-*"
    assert str(permission_urn) == "urn:mtmf:iam:permissions:system:principal:set-*"


def test_permission_urn_wrong_component_count_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:principal")
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-alias:extra")


def test_action_urn_cannot_pass_as_permission() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:actions:system:principal:set-alias")
