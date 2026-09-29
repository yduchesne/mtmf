"""Pure-Python CompiledPolicy control tests (PR 8G amendment).

Focused behavioral coverage of ``benchmarks/python_compiled_policy.py``
(``PythonCompiledPolicy``, the PC control):

- empty policy -> NO_MATCH;
- exact ALLOW / exact DENY;
- wildcard ALLOW / wildcard DENY;
- exact-over-wildcard (lower-specificity evidence never leaks);
- equal-specificity conflict;
- duplicate collapse (non-voting);
- unrelated policy -> NO_MATCH;
- deterministic repeated evaluation;
- input-order independence;
- ownership corruption rejected;
- structurally immutable compiled representation;
- no mutation across repeated evaluation;
- large compiled policy.

These tests are pure Python: they do NOT require the native module. The
four-way P == R == PC == RC parity lives in
``test_compiled_policy_differential.py`` (which does require the native
module). No PostgreSQL, Podman, network service, timing assertion, or
randomness is used.
"""

from __future__ import annotations

from types import MappingProxyType

import pytest
from authz_helpers import (
    corrupt_role,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)

from mtmf_core import (
    AuthorizationDecision,
    DenyReason,
    MatchSpecificity,
    PermissionEffect,
)
from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError
from python_compiled_policy import EffectAggregate, PythonCompiledPolicy


def _compile(roles: object) -> PythonCompiledPolicy:
    return PythonCompiledPolicy.compile(roles)


def _single_set_role(
    *,
    effect: PermissionEffect = PermissionEffect.ALLOW,
    rules: tuple[tuple[str, str], ...] = (("set", "active"),),
) -> object:
    urn = make_role_urn()
    return make_role_from_sets(
        role_urn=urn,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, effect=effect, rules=rules),),
    )


def _assert_decision(
    compiled: PythonCompiledPolicy,
    verb: str,
    qualifier: str,
    *,
    expected: AuthorizationDecision,
    resource: str = "principal",
) -> None:
    decision = compiled.evaluate(make_action(resource=resource, verb=verb, qualifier=qualifier))
    assert decision == expected, f"{verb}-{qualifier}: {decision!r} != {expected!r}"
    assert decision.allowed == expected.allowed
    assert decision.effect == expected.effect
    assert decision.reason == expected.reason
    assert decision.matched_specificity == expected.matched_specificity
    assert decision.matched_allow == expected.matched_allow
    assert decision.matched_deny == expected.matched_deny


EXACT_ALLOW = AuthorizationDecision.allow(
    matched_specificity=MatchSpecificity.EXACT, matched_allow=True, matched_deny=False
)
EXACT_DENY = AuthorizationDecision.deny(
    DenyReason.MATCHED_DENY,
    matched_specificity=MatchSpecificity.EXACT,
    matched_allow=False,
    matched_deny=True,
)
WILDCARD_ALLOW = AuthorizationDecision.allow(
    matched_specificity=MatchSpecificity.QUALIFIER_WILDCARD,
    matched_allow=True,
    matched_deny=False,
)
WILDCARD_DENY = AuthorizationDecision.deny(
    DenyReason.MATCHED_DENY,
    matched_specificity=MatchSpecificity.QUALIFIER_WILDCARD,
    matched_allow=False,
    matched_deny=True,
)
NO_MATCH = AuthorizationDecision.deny(DenyReason.NO_MATCH)


# --- 1. Empty policy ------------------------------------------------------------


def test_empty_policy_is_valid_default_deny() -> None:
    compiled = _compile(())
    assert compiled.exact_key_count == 0
    assert compiled.wildcard_key_count == 0
    _assert_decision(compiled, "set", "active", expected=NO_MATCH)


# --- 2/3. Exact ALLOW / DENY ------------------------------------------------------


def test_exact_allow() -> None:
    _assert_decision(
        _compile((_single_set_role(rules=(("set", "active"),)),)),
        "set",
        "active",
        expected=EXACT_ALLOW,
    )


def test_exact_deny() -> None:
    _assert_decision(
        _compile((_single_set_role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),)),
        "set",
        "active",
        expected=EXACT_DENY,
    )


# --- 4/5. Wildcard ALLOW / DENY ----------------------------------------------------


def test_wildcard_allow() -> None:
    _assert_decision(
        _compile((_single_set_role(rules=(("set", "*"),)),)),
        "set",
        "alias",
        expected=WILDCARD_ALLOW,
    )


def test_wildcard_deny() -> None:
    _assert_decision(
        _compile((_single_set_role(effect=PermissionEffect.DENY, rules=(("set", "*"),)),)),
        "set",
        "alias",
        expected=WILDCARD_DENY,
    )


# --- 6. Exact over wildcard ----------------------------------------------------------


def test_wildcard_deny_plus_exact_allow_is_exact_allow() -> None:
    # Exact ALLOW beats the wildcard DENY; the wildcard DENY evidence
    # must not leak into the exact decision.
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(
                        role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
                    ),
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),
                ),
            ),
        )
    )
    _assert_decision(compiled, "set", "active", expected=EXACT_ALLOW)


def test_wildcard_allow_plus_exact_deny_is_exact_deny() -> None:
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
                    make_permission_set_with_rules(
                        role_urn=urn,
                        effect=PermissionEffect.DENY,
                        rules=(("set", "active"),),
                    ),
                ),
            ),
        )
    )
    _assert_decision(compiled, "set", "active", expected=EXACT_DENY)


def test_exact_allow_beats_wildcard_allow() -> None:
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),
                ),
            ),
        )
    )
    _assert_decision(compiled, "set", "active", expected=EXACT_ALLOW)


def test_exact_deny_beats_wildcard_deny() -> None:
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(
                        role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
                    ),
                    make_permission_set_with_rules(
                        role_urn=urn,
                        effect=PermissionEffect.DENY,
                        rules=(("set", "active"),),
                    ),
                ),
            ),
        )
    )
    _assert_decision(compiled, "set", "active", expected=EXACT_DENY)


# --- 7. Equal-specificity conflict ---------------------------------------------------


def test_equal_exact_conflict_is_matched_deny_with_both_flags() -> None:
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),
                    make_permission_set_with_rules(
                        role_urn=urn,
                        effect=PermissionEffect.DENY,
                        rules=(("set", "active"),),
                    ),
                ),
            ),
        )
    )
    _assert_decision(
        compiled,
        "set",
        "active",
        expected=AuthorizationDecision.deny(
            DenyReason.MATCHED_DENY,
            matched_specificity=MatchSpecificity.EXACT,
            matched_allow=True,
            matched_deny=True,
        ),
    )


def test_equal_wildcard_conflict_is_matched_deny_with_both_flags() -> None:
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
                    make_permission_set_with_rules(
                        role_urn=urn,
                        effect=PermissionEffect.DENY,
                        rules=(("set", "*"),),
                    ),
                ),
            ),
        )
    )
    _assert_decision(
        compiled,
        "set",
        "alias",
        expected=AuthorizationDecision.deny(
            DenyReason.MATCHED_DENY,
            matched_specificity=MatchSpecificity.QUALIFIER_WILDCARD,
            matched_allow=True,
            matched_deny=True,
        ),
    )


# --- 8. Duplicate collapse ------------------------------------------------------------


def test_duplicate_allow_collapses_to_one_allow() -> None:
    urn = make_role_urn()
    duplicated = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(
                        role_urn=urn, rules=(("set", "active"), ("set", "active"))
                    ),
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),
                ),
            ),
        )
    )
    assert duplicated.exact_key_count == 1
    _assert_decision(duplicated, "set", "active", expected=EXACT_ALLOW)


def test_duplicate_deny_collapses_to_one_deny() -> None:
    urn = make_role_urn()
    duplicated = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(
                        role_urn=urn,
                        effect=PermissionEffect.DENY,
                        rules=(("set", "active"),),
                    ),
                    make_permission_set_with_rules(
                        role_urn=urn,
                        effect=PermissionEffect.DENY,
                        rules=(("set", "active"),),
                    ),
                ),
            ),
        )
    )
    assert duplicated.exact_key_count == 1
    _assert_decision(duplicated, "set", "active", expected=EXACT_DENY)


def test_duplicate_allow_cannot_outweigh_equal_deny() -> None:
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),
                    make_permission_set_with_rules(
                        role_urn=urn,
                        effect=PermissionEffect.DENY,
                        rules=(("set", "active"),),
                    ),
                ),
            ),
        )
    )
    assert compiled.exact_key_count == 1
    _assert_decision(
        compiled,
        "set",
        "active",
        expected=AuthorizationDecision.deny(
            DenyReason.MATCHED_DENY,
            matched_specificity=MatchSpecificity.EXACT,
            matched_allow=True,
            matched_deny=True,
        ),
    )


# --- 9/10. Unrelated policy / NO_MATCH ------------------------------------------------


def test_unrelated_policy_is_no_match() -> None:
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(
                        role_urn=urn, rules=(("get", "object"), ("set", "alias"))
                    ),
                ),
            ),
        )
    )
    _assert_decision(compiled, "set", "active", expected=NO_MATCH)
    _assert_decision(compiled, "delete", "object", expected=NO_MATCH)
    # An exact key must not leak into a different qualifier.
    _assert_decision(compiled, "set", "alias", expected=EXACT_ALLOW)


# --- 11. Deterministic repeated evaluation ----------------------------------------------


def test_repeated_evaluation_is_identical() -> None:
    urn = make_role_urn()
    compiled = _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(
                        role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
                    ),
                    make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),
                ),
            ),
        )
    )
    action = make_action(verb="set", qualifier="active")
    first = compiled.evaluate(action)
    for _ in range(5):
        assert compiled.evaluate(action) == first


# --- 12. Input-order independence --------------------------------------------------------


def test_role_order_permutation_is_identical() -> None:
    allow_role = _single_set_role(rules=(("set", "active"),))
    deny_role = _single_set_role(effect=PermissionEffect.DENY, rules=(("set", "*"),))
    action = make_action(verb="set", qualifier="active")
    forward = _compile((allow_role, deny_role)).evaluate(action)
    reversed_roles = _compile((deny_role, allow_role)).evaluate(action)
    assert forward == reversed_roles
    assert forward == EXACT_ALLOW


def test_set_and_permission_order_permutation_is_identical() -> None:
    urn = make_role_urn()
    wildcard = make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),))
    exact_deny = make_permission_set_with_rules(
        role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "active"),)
    )
    action = make_action(verb="set", qualifier="active")
    forward = _compile(
        (make_role_from_sets(role_urn=urn, permission_sets=(wildcard, exact_deny)),)
    ).evaluate(action)
    reversed_roles = _compile(
        (make_role_from_sets(role_urn=urn, permission_sets=(exact_deny, wildcard)),)
    ).evaluate(action)
    assert forward == reversed_roles
    assert forward == EXACT_DENY


def test_semantically_equal_policies_build_equal_indexes() -> None:
    # Two semantically identical policies built from different object
    # orders produce equal indexes (indexes are set-like, not
    # sequence-like).
    urn_a = make_role_urn()
    urn_b = make_role_urn()
    a = _compile(
        (
            make_role_from_sets(
                role_urn=urn_a,
                permission_sets=(
                    make_permission_set_with_rules(role_urn=urn_a, rules=(("get", "object"),)),
                    make_permission_set_with_rules(role_urn=urn_a, rules=(("set", "active"),)),
                ),
            ),
        )
    )
    b = _compile(
        (
            make_role_from_sets(
                role_urn=urn_b,
                permission_sets=(
                    make_permission_set_with_rules(role_urn=urn_b, rules=(("set", "active"),)),
                    make_permission_set_with_rules(role_urn=urn_b, rules=(("get", "object"),)),
                ),
            ),
        )
    )
    assert set(a.exact) == set(b.exact)
    assert set(a.wildcard) == set(b.wildcard)
    assert a.exact_key_count == b.exact_key_count


# --- 13. Ownership corruption ------------------------------------------------------------


def test_ownership_corruption_rejected_before_indexing() -> None:
    owner_urn = make_role_urn(role_name="owner")
    set_ = make_permission_set_with_rules(role_urn=owner_urn, rules=(("set", "active"),))
    corrupt = corrupt_role(role_urn=make_role_urn(role_name="impostor"), permission_sets=(set_,))
    with pytest.raises(PermissionEvaluationError):
        _compile((corrupt,))


# --- 14. Immutable compiled representation ------------------------------------------------


def test_compiled_representation_is_structurally_immutable() -> None:
    compiled = _compile((_single_set_role(rules=(("set", "active"), ("get", "*"))),))
    # Frozen dataclass: attributes cannot be reassigned.
    with pytest.raises(AttributeError):
        compiled._exact = {}  # type: ignore[misc]
    # Private dicts are proxied read-only; mutation attempts fail.
    assert isinstance(compiled._exact, MappingProxyType)
    assert isinstance(compiled._wildcard, MappingProxyType)
    with pytest.raises(AttributeError):
        compiled._exact.clear()  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        compiled._wildcard.clear()  # type: ignore[attr-defined]


def test_effect_aggregates_are_frozen() -> None:
    aggregate = EffectAggregate(matched_allow=True, matched_deny=False)
    with pytest.raises(AttributeError):
        aggregate.matched_allow = False  # type: ignore[misc]
    assert aggregate.matched_allow is True


# --- 15/16. Large policy and no mutation across evaluation --------------------------------


def test_large_policy_compiles_and_evaluates() -> None:
    from mtmf_core import DomainId, Permission, PermissionSet, PermissionUrn, Role, RoleUrn

    role_urn = RoleUrn("urn:mtmf:iam:roles:system:bench-large")
    set_id = DomainId.generate()
    permissions = tuple(
        Permission(
            DomainId.generate(),
            set_id,
            PermissionUrn(f"urn:mtmf:iam:permissions:system:resource{i}:op-{i}"),
        )
        for i in range(5000)
    )
    role = Role(
        role_urn,
        "large",
        "",
        None,
        (PermissionSet(set_id, role_urn, PermissionEffect.ALLOW, permissions),),
    )
    compiled = _compile((role,))
    assert compiled.exact_key_count == 5000
    assert compiled.wildcard_key_count == 0
    hit = compiled.evaluate(make_action(resource="resource4999", verb="op", qualifier="4999"))
    assert hit == AuthorizationDecision.allow(
        matched_specificity=MatchSpecificity.EXACT, matched_allow=True, matched_deny=False
    )
    miss = compiled.evaluate(make_action(resource="resource4999", verb="op", qualifier="9999"))
    assert miss == NO_MATCH


def test_no_mutation_across_repeated_evaluation() -> None:
    compiled = _compile((_single_set_role(rules=(("set", "*"), ("get", "object"))),))
    exact_before = dict(compiled.exact)
    wildcard_before = dict(compiled.wildcard)
    for _ in range(10):
        _assert_decision(compiled, "set", "active", expected=WILDCARD_ALLOW)
        _assert_decision(compiled, "get", "object", expected=EXACT_ALLOW)
        _assert_decision(compiled, "delete", "object", expected=NO_MATCH)
    assert dict(compiled.exact) == exact_before
    assert dict(compiled.wildcard) == wildcard_before
    assert compiled.exact_key_count == len(exact_before)
    assert compiled.wildcard_key_count == len(wildcard_before)
