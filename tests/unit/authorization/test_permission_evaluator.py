"""PermissionEvaluator conformance and behavior tests.

Covers the PR 4 Part 4 canonical cases (A-I), the Part 10 evaluator
matrix (P01-P18), and the design boundaries (P19, P20).
"""

from __future__ import annotations

import importlib
import inspect
import typing
from collections.abc import Iterable

import pytest
from authz_helpers import (
    corrupt_role,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)
from helpers import make_id, make_permission

from mtmf_core import (
    Action,
    AuthorizationDecision,
    DenyReason,
    MatchSpecificity,
    PermissionEffect,
    PermissionEvaluationError,
    PermissionEvaluator,
    PermissionSet,
    Role,
    RoleUrn,
)


def _evaluate(role: Role, action: Action) -> AuthorizationDecision:
    """Evaluate one role against one action (conformance shorthand)."""
    return PermissionEvaluator().evaluate(action, (role,))


def _system_role(
    *,
    rules: tuple[tuple[str, str], ...] = (("set", "*"),),
    effect: PermissionEffect = PermissionEffect.ALLOW,
    role_urn: RoleUrn | None = None,
    role_name: str = "actor",
) -> Role:
    """Build a SYSTEM Role whose permission sets express ``rules``."""
    resolved_urn = role_urn if role_urn is not None else make_role_urn(role_name=role_name)
    return make_role_from_sets(
        role_urn=resolved_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=resolved_urn, effect=effect, rules=rules),
        ),
    )


# --- Part 4 canonical cases A-I ------------------------------------------------


def test_case_a_no_match_defaults_to_deny() -> None:
    role = _system_role(rules=(("set", "*"),))
    decision = _evaluate(role, make_action(verb="delete", qualifier="object"))
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


def test_case_b_wildcard_allow_only() -> None:
    role = _system_role(rules=(("set", "*"),))
    decision = _evaluate(role, make_action(verb="set", qualifier="active"))
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD


def test_case_c_wildcard_deny_only() -> None:
    role = _system_role(rules=(("set", "*"),), effect=PermissionEffect.DENY)
    decision = _evaluate(role, make_action(verb="set", qualifier="active"))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD


def test_case_d_exact_deny_beats_wildcard_allow() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        )
    )
    decision = _evaluate(role, make_action(verb="set", qualifier="alias"))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.EXACT
    # The lower-specificity wildcard ALLOW is discarded: no ALLOW at the
    # winning specificity.
    assert not decision.matched_allow
    assert decision.matched_deny


def test_case_e_exact_allow_beats_wildcard_deny() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
            ),
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
        )
    )
    decision = _evaluate(role, make_action(verb="set", qualifier="alias"))
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_allow
    assert not decision.matched_deny


def test_case_f_equal_exact_conflict_is_deny() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        )
    )
    decision = _evaluate(role, make_action(verb="set", qualifier="alias"))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_allow
    assert decision.matched_deny


def test_case_g_equal_wildcard_conflict_is_deny() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
            ),
        )
    )
    decision = _evaluate(role, make_action(verb="set", qualifier="active"))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD


def test_case_h_multiple_roles_create_no_role_precedence() -> None:
    # Role boundaries create no precedence: a matching ALLOW in one Role
    # and a matching DENY in another Role produce DENY in either order.
    allow_urn = make_role_urn(role_name="a")
    allow_role = make_role_from_sets(
        role_urn=allow_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "alias"),)),
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
    evaluator = PermissionEvaluator()
    forward = evaluator.evaluate(action, (allow_role, deny_role))
    reversed_ = evaluator.evaluate(action, (deny_role, allow_role))
    assert not forward.allowed
    assert forward == reversed_
    assert forward.reason is DenyReason.MATCHED_DENY


def test_case_i_irrelevant_rules_do_not_alter_result() -> None:
    urn = make_role_urn()
    noisy = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=urn,
                rules=(("create", "object"), ("delete", "object"), ("get", "object")),
            ),
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
        )
    )
    quiet = make_role_from_sets(
        permission_sets=(make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),)
    )
    action = make_action(verb="set", qualifier="active")
    evaluator = PermissionEvaluator()
    assert evaluator.evaluate(action, (noisy,)).allowed
    assert evaluator.evaluate(action, (noisy,)) == evaluator.evaluate(action, (quiet,))


# --- Part 10 evaluator matrix P01-P18 ------------------------------------------


def test_p01_no_roles_is_deny() -> None:
    decision = PermissionEvaluator().evaluate(make_action(), ())
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


def test_p02_role_but_no_matching_permission_is_deny() -> None:
    role = _system_role(rules=(("get", "object"),))
    decision = _evaluate(role, make_action(verb="set", qualifier="active"))
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


def test_p03_wildcard_allow_is_allow() -> None:
    decision = _evaluate(
        _system_role(rules=(("set", "*"),)), make_action(verb="set", qualifier="active")
    )
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD
    assert decision.matched_allow
    assert not decision.matched_deny
    assert decision.reason is None


def test_p04_wildcard_deny_is_deny() -> None:
    role = _system_role(rules=(("set", "*"),), effect=PermissionEffect.DENY)
    decision = _evaluate(role, make_action(verb="set", qualifier="active"))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_p05_exact_allow_is_allow() -> None:
    decision = _evaluate(
        _system_role(rules=(("set", "alias"),)), make_action(verb="set", qualifier="alias")
    )
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT


def test_p06_exact_deny_is_deny() -> None:
    role = _system_role(rules=(("set", "alias"),), effect=PermissionEffect.DENY)
    decision = _evaluate(role, make_action(verb="set", qualifier="alias"))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.EXACT


def test_p07_wildcard_allow_plus_exact_deny_is_deny() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        )
    )
    decision = _evaluate(role, make_action(verb="set", qualifier="alias"))
    assert not decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT


def test_p08_wildcard_deny_plus_exact_allow_is_allow() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
            ),
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
        )
    )
    decision = _evaluate(role, make_action(verb="set", qualifier="alias"))
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT


def test_p09_exact_allow_plus_exact_deny_is_deny() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        )
    )
    decision = _evaluate(role, make_action(verb="set", qualifier="alias"))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_p10_wildcard_allow_plus_wildcard_deny_is_deny() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
            ),
        )
    )
    decision = _evaluate(role, make_action(verb="set", qualifier="active"))
    assert not decision.allowed
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD


def test_p11_duplicate_same_effect_rules_are_stable() -> None:
    # Duplicate matching rules (across sets and across Roles) must not
    # create greater authority: the decision stays a stable ALLOW.
    urn = make_role_urn()
    role = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
        )
    )
    duplicated = make_role_from_sets(
        permission_sets=(make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),)
    )
    action = make_action(verb="set", qualifier="alias")
    evaluator = PermissionEvaluator()
    assert evaluator.evaluate(action, (role,)) == evaluator.evaluate(action, (duplicated,))


def test_p12_role_order_reversed_gives_same_decision() -> None:
    allow_urn = make_role_urn(role_name="a")
    allow_role = make_role_from_sets(
        role_urn=allow_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "alias"),)),
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
    evaluator = PermissionEvaluator()
    assert evaluator.evaluate(action, (allow_role, deny_role)) == evaluator.evaluate(
        action, (deny_role, allow_role)
    )


def test_p13_permission_set_order_reversed_gives_same_decision() -> None:
    urn = make_role_urn()
    allow_set = make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),))
    deny_set = make_permission_set_with_rules(
        role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
    )
    forward = make_role_from_sets(permission_sets=(allow_set, deny_set))
    reversed_ = make_role_from_sets(permission_sets=(deny_set, allow_set))
    action = make_action(verb="set", qualifier="alias")
    evaluator = PermissionEvaluator()
    assert evaluator.evaluate(action, (forward,)) == evaluator.evaluate(action, (reversed_,))


def test_p14_permission_order_reversed_gives_same_decision() -> None:
    urn = make_role_urn()
    first_set_id = make_id()
    forward_set = PermissionSet(
        first_set_id,
        urn,
        PermissionEffect.ALLOW,
        (
            make_permission(permission_set_id=first_set_id, verb="set", qualifier="alias"),
            make_permission(permission_set_id=first_set_id, verb="set", qualifier="*"),
        ),
    )
    second_set_id = make_id()
    reversed_set = PermissionSet(
        second_set_id,
        urn,
        PermissionEffect.ALLOW,
        (
            make_permission(permission_set_id=second_set_id, verb="set", qualifier="*"),
            make_permission(permission_set_id=second_set_id, verb="set", qualifier="alias"),
        ),
    )
    action = make_action(verb="set", qualifier="alias")
    evaluator = PermissionEvaluator()
    forward_role = make_role_from_sets(permission_sets=(forward_set,))
    reversed_role = make_role_from_sets(permission_sets=(reversed_set,))
    assert evaluator.evaluate(action, (forward_role,)) == evaluator.evaluate(
        action, (reversed_role,)
    )


def test_p15_multiple_roles_conflicting_exact_is_deny() -> None:
    allow_urn = make_role_urn(role_name="a")
    allow_role = make_role_from_sets(
        role_urn=allow_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "alias"),)),
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
    decision = PermissionEvaluator().evaluate(
        make_action(verb="set", qualifier="alias"), (allow_role, deny_role)
    )
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_p16_lower_specificity_deny_plus_higher_specificity_allow() -> None:
    # A lower-specificity DENY must NOT beat a higher-specificity ALLOW.
    deny_urn = make_role_urn(role_name="a")
    deny_role = make_role_from_sets(
        role_urn=deny_urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=deny_urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
            ),
        ),
    )
    allow_urn = make_role_urn(role_name="b")
    allow_role = make_role_from_sets(
        role_urn=allow_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "alias"),)),
        ),
    )
    decision = PermissionEvaluator().evaluate(
        make_action(verb="set", qualifier="alias"), (deny_role, allow_role)
    )
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert not decision.matched_deny


def test_p17_lower_specificity_allow_plus_higher_specificity_deny() -> None:
    allow_urn = make_role_urn(role_name="a")
    allow_role = make_role_from_sets(
        role_urn=allow_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "*"),)),
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
    decision = PermissionEvaluator().evaluate(
        make_action(verb="set", qualifier="alias"), (allow_role, deny_role)
    )
    assert not decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT


def test_p18_irrelevant_permission_noise_is_unchanged() -> None:
    urn = make_role_urn()
    noisy = make_role_from_sets(
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=urn,
                rules=(("create", "object"), ("delete", "object"), ("get", "object")),
            ),
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
        )
    )
    quiet = make_role_from_sets(
        permission_sets=(make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),)
    )
    action = make_action(verb="set", qualifier="active")
    evaluator = PermissionEvaluator()
    assert evaluator.evaluate(action, (noisy,)) == evaluator.evaluate(action, (quiet,))


# --- Design boundaries P19/P20 -------------------------------------------------


def test_p19_evaluator_api_takes_only_action_and_roles() -> None:
    hints = typing.get_type_hints(PermissionEvaluator.evaluate)
    assert hints["action"] is Action
    assert hints["roles"] == Iterable[Role]
    signature = inspect.signature(PermissionEvaluator.evaluate)
    assert list(signature.parameters) == ["self", "action", "roles"]


def test_p19_evaluator_module_has_no_context_retrieval_imports() -> None:
    module = importlib.import_module("mtmf_core.authorization.permission_evaluator")
    for name in (
        "SessionContext",
        "validate_session_context",
        "PrincipalTenantMembership",
        "IdentityTenantMembership",
        "Tenant",
        "Principal",
        "Identity",
        "repository",
        "uow",
    ):
        assert name not in module.__dict__


def test_p20_decision_contains_no_assignment_inference() -> None:
    decision = PermissionEvaluator().evaluate(make_action(), ())
    for name in ("role_urn", "role", "assignment", "identity_id", "tenant_id"):
        assert name not in AuthorizationDecision.__dataclass_fields__
        assert not hasattr(decision, name)


def test_evaluator_is_stateless_and_repeatable() -> None:
    action = make_action(verb="set", qualifier="active")
    role = _system_role(rules=(("set", "*"),))
    evaluator = PermissionEvaluator()
    first = evaluator.evaluate(action, (role,))
    second = evaluator.evaluate(action, (role,))
    assert first == second
    # Evaluation never mutates the supplied policy objects.
    assert role.permission_sets[0].permissions


def test_corrupted_policy_raises_instead_of_allow() -> None:
    role_urn = make_role_urn(role_name="owner")
    foreign_set = make_permission_set_with_rules(
        role_urn=make_role_urn(role_name="other"), rules=(("set", "*"),)
    )
    corrupt = corrupt_role(role_urn, (foreign_set,))
    with pytest.raises(PermissionEvaluationError):
        PermissionEvaluator().evaluate(make_action(verb="set", qualifier="active"), (corrupt,))
