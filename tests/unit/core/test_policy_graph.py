"""Canonical policy vertical slice: Role -> PermissionSet -> Permission.

Builds the documented SYSTEM and TENANT policy graphs and asserts only
matcher facts, explicitly avoiding any aggregate "which effect wins"
claim: aggregate resolution belongs to a later PR.
"""

import pytest
from helpers import make_permission_set, make_role_urn

from mtmf_core import (
    Action,
    ActionUrn,
    DefinitionNamespace,
    DomainId,
    DomainInvariantError,
    MatchSpecificity,
    Permission,
    PermissionEffect,
    PermissionSet,
    PermissionUrn,
    Role,
    SecurityScope,
    match_permission,
)


def _action(text: str) -> Action:
    return Action(ActionUrn(text))


def test_canonical_system_role_policy_slice() -> None:
    role_urn = make_role_urn(role_name="example-security-admin")
    allow_set_id = DomainId.generate()
    deny_set_id = DomainId.generate()

    allow_set = PermissionSet(
        allow_set_id,
        role_urn,
        PermissionEffect.ALLOW,
        (
            Permission(
                DomainId.generate(),
                allow_set_id,
                PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-*"),
            ),
        ),
    )
    deny_set = PermissionSet(
        deny_set_id,
        role_urn,
        PermissionEffect.DENY,
        (
            Permission(
                DomainId.generate(),
                deny_set_id,
                PermissionUrn("urn:mtmf:iam:permissions:system:principal:set-alias"),
            ),
        ),
    )
    role = Role(role_urn, "Example Security Administrator", "", None, (allow_set, deny_set))

    assert role.definition_namespace is DefinitionNamespace.SYSTEM

    set_active = _action("urn:mtmf:iam:actions:system:principal:set-active")
    set_alias = _action("urn:mtmf:iam:actions:system:principal:set-alias")
    delete_object = _action("urn:mtmf:iam:actions:system:principal:delete-object")

    wildcard = allow_set.permissions[0]
    exact = deny_set.permissions[0]

    # Only matcher facts are asserted here; no aggregate resolution.
    assert match_permission(wildcard, set_active).specificity is MatchSpecificity.QUALIFIER_WILDCARD
    assert match_permission(wildcard, set_alias).specificity is MatchSpecificity.QUALIFIER_WILDCARD
    assert not match_permission(wildcard, delete_object).matched
    assert match_permission(exact, set_alias).specificity is MatchSpecificity.EXACT
    assert MatchSpecificity.EXACT.is_more_specific_than(MatchSpecificity.QUALIFIER_WILDCARD)
    # Effects stay attached to their PermissionSets; no matcher fact
    # decides which effect wins.
    assert allow_set.effect is PermissionEffect.ALLOW
    assert deny_set.effect is PermissionEffect.DENY


def test_canonical_tenant_role_structural_tenant_agrees_with_urn() -> None:
    tenant = DomainId.generate()
    role_urn = make_role_urn(tenant_id=tenant, role_name="security-analyst")
    permission_set = make_permission_set(role_urn=role_urn)
    role = Role(
        role_urn,
        "Security Analyst",
        "",
        tenant,
        (permission_set,),
    )
    assert role.urn.encoded_tenant_id == tenant
    assert role.defining_tenant_id == tenant
    assert role.definition_namespace is DefinitionNamespace.TENANT


def test_tenant_role_structural_tenant_mismatch_rejected() -> None:
    tenant = DomainId.generate()
    other = DomainId.generate()
    role_urn = make_role_urn(tenant_id=tenant, role_name="security-analyst")
    permission_set = make_permission_set(role_urn=role_urn)
    with pytest.raises(DomainInvariantError):
        Role(
            role_urn,
            "Security Analyst",
            "",
            other,
            (permission_set,),
        )


def test_definition_namespace_is_distinct_from_security_scope() -> None:
    assert DefinitionNamespace.SYSTEM is not SecurityScope.SYSTEM
    assert DefinitionNamespace.TENANT is not SecurityScope.TENANT
    assert not isinstance(DefinitionNamespace.SYSTEM, int)
    assert isinstance(SecurityScope.SYSTEM, int)
    assert DefinitionNamespace.SYSTEM != SecurityScope.SYSTEM
    assert DefinitionNamespace.TENANT != SecurityScope.TENANT
    assert DefinitionNamespace.SYSTEM != 1


def test_namespace_values_are_the_urn_text() -> None:
    assert DefinitionNamespace.SYSTEM.value == "system"
    assert DefinitionNamespace.TENANT.value == "tenant"
