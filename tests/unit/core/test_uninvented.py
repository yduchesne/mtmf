"""Tests that explicitly unresolved features are NOT invented (U31, U32, U39-U41).

These are import-boundary and field-absence checks: they guard the PR 2
scope boundary without depending on brittle introspection.
"""

import importlib

import pytest
from helpers import (
    make_group,
    make_identity,
    make_organization,
    make_principal,
    make_tenant,
)
from helpers import (
    make_role as _make_role,
)

import mtmf_core
from mtmf_core import Group, Identity, Organization, Principal, Role, Tenant

DOMAIN = importlib.import_module("mtmf_core.domain")


# U31 --- no PrincipalOrgMembership -------------------------------------------------


def test_principal_organization_membership_is_absent() -> None:
    assert not hasattr(DOMAIN, "PrincipalOrgMembership")
    memberships = importlib.import_module("mtmf_core.domain.memberships")
    assert not hasattr(memberships, "PrincipalOrgMembership")
    assert not hasattr(memberships, "PrincipalGroupMembership")


# U32 --- no nested Groups -----------------------------------------------------------


def test_nested_groups_are_absent() -> None:
    assert not hasattr(DOMAIN, "NestedGroup")
    group = make_group()
    assert not hasattr(group, "parent_group_id")
    assert not hasattr(group, "members")


# U39 --- ActiveStatus applicability is not invented ---------------------------------


@pytest.mark.parametrize(
    "entity",
    [
        make_tenant(),
        make_organization(),
        make_principal(),
        make_identity(),
        make_group(),
    ],
)
def test_entities_have_no_active_status_field(entity) -> None:
    assert not hasattr(entity, "active_status")


def test_entity_field_sets_contain_no_active_status() -> None:
    for entity_type in (Tenant, Organization, Principal, Identity, Group):
        assert "active_status" not in entity_type.__dataclass_fields__


# U40 --- local/federated Identity representation is not invented --------------------


def test_identity_type_enum_is_absent() -> None:
    assert not hasattr(DOMAIN, "IdentityType")
    identity = make_identity()
    assert not hasattr(identity, "identity_type")
    assert "identity_type" not in Identity.__dataclass_fields__


# U41 --- Principal kind enum is not invented ----------------------------------------


def test_principal_kind_enum_is_absent() -> None:
    assert not hasattr(DOMAIN, "PrincipalKind")
    principal = make_principal()
    assert not hasattr(principal, "kind")
    assert "kind" not in Principal.__dataclass_fields__


# --- PR 3 scope boundaries (U60-U63) ---
# These guard the PR 3/PR 4 seam: policy definitions and matcher facts
# exist, but no assignment, Authorizer, decision engine, or built-in
# Role policy mapping may leak into PR 3.


def test_role_assignments_are_absent() -> None:
    assert not hasattr(DOMAIN, "RoleAssignment")
    assert not hasattr(mtmf_core, "RoleAssignment")
    role = _make_role()
    assert not hasattr(role, "assignments")
    assert "assignments" not in Role.__dataclass_fields__


def test_authorizer_is_absent() -> None:
    assert not hasattr(mtmf_core, "Authorizer")
    assert not hasattr(mtmf_core.domain, "Authorizer")
    assert "Authorizer" not in mtmf_core.__all__


def test_default_deny_decision_engine_is_absent() -> None:
    for name in ("Authorizer", "Decision", "AuthorizationDecision", "PermissionEvaluator"):
        assert not hasattr(mtmf_core, name)
        assert not hasattr(mtmf_core.domain, name)
    role = _make_role()
    assert not hasattr(role, "decide")
    assert not hasattr(role, "authorize")


def test_builtin_role_policy_mapping_is_absent() -> None:
    assert not hasattr(mtmf_core, "BUILTIN_ROLE_POLICY")
    assert not hasattr(mtmf_core, "RolePolicy")
    policy = importlib.import_module("mtmf_core.domain.policy")
    assert not hasattr(policy, "BUILTIN_ROLE_POLICY")
    assert "mapping" not in Role.__dataclass_fields__
