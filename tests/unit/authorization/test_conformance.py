"""Canonical authorization vertical slices (PR 4 Part 11).

Each slice exercises the Authorizer foundation end-to-end over the
settled security constitution: default deny, wildcard/exact specificity,
equal-specificity DENY, Tenant isolation, and strict dominance.
"""

from __future__ import annotations

from authz_helpers import (
    build_authorization_request,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)
from helpers import make_id

from mtmf_core import (
    Authorizer,
    DenyReason,
    DominanceRequirement,
    PermissionEffect,
    SecurityScope,
)


def test_slice_1_basic_default_deny() -> None:
    # Session Tenant A, valid memberships, matching-Action-shaped request
    # with no applicable Roles: DENY.
    request = build_authorization_request(action=make_action(verb="set", qualifier="active"))
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


def _actor_role() -> object:
    urn = make_role_urn(role_name="actor")
    return make_role_from_sets(
        role_urn=urn,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),),
    )


def test_slice_2_wildcard_allow() -> None:
    request = build_authorization_request(
        roles=(_actor_role(),), action=make_action(verb="set", qualifier="active")
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed


def test_slice_3_specific_deny() -> None:
    # ALLOW principal:set-* + DENY principal:set-alias; action set-alias.
    urn = make_role_urn(role_name="actor")
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        ),
    )
    request = build_authorization_request(
        roles=(role,), action=make_action(verb="set", qualifier="alias")
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_slice_4_specific_allow() -> None:
    # DENY principal:set-* + ALLOW principal:set-alias; action set-alias.
    urn = make_role_urn(role_name="actor")
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
            ),
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
        ),
    )
    request = build_authorization_request(
        roles=(role,), action=make_action(verb="set", qualifier="alias")
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed


def test_slice_5_equal_specificity_deny_across_roles() -> None:
    # Role A: ALLOW set-alias; Role B: DENY set-alias. Resolution crosses
    # Role boundaries and ignores Role order.
    allow_role = make_role_from_sets(
        role_urn=make_role_urn(role_name="a"),
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=make_role_urn(role_name="a"), rules=(("set", "alias"),)
            ),
        ),
    )
    deny_urn = make_role_urn(role_name="b")
    deny_role = make_role_from_sets(
        role_urn=deny_urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=deny_urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        ),
    )
    action = make_action(verb="set", qualifier="alias")
    authorizer = Authorizer()
    forward = authorizer.authorize(
        build_authorization_request(roles=(allow_role, deny_role), action=action)
    )
    reversed_role_order = authorizer.authorize(
        build_authorization_request(roles=(deny_role, allow_role), action=action)
    )
    assert forward == reversed_role_order
    assert not forward.allowed
    assert forward.reason is DenyReason.MATCHED_DENY


def test_slice_6_tenant_isolation() -> None:
    # Session Tenant A, target Tenant B, policy otherwise ALLOW: DENY.
    # The Role's definition namespace is never used as assignment proof.
    request = build_authorization_request(
        roles=(_actor_role(),),
        action=make_action(verb="set", qualifier="active"),
        target_tenant_id=make_id(),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MANAGEMENT_SCOPE


def test_slice_7_strict_dominance_allow() -> None:
    request = build_authorization_request(
        roles=(_actor_role(),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.SYSTEM,
        target_scope=SecurityScope.TENANT,
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed


def test_slice_7_strict_dominance_same_scope_deny() -> None:
    request = build_authorization_request(
        roles=(_actor_role(),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.TENANT,
        target_scope=SecurityScope.TENANT,
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INSUFFICIENT_DOMINANCE
