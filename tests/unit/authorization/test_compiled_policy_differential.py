"""Systematic P == R == C compiled-policy differential tests (PR 8G).

Complete-decision semantic equivalence is a first-class invariant for
the compiled-policy experiment:

```text
Python reference evaluator(input) == Rust evaluator(input) == Compiled(input)
```

The comparison covers the complete :class:`AuthorizationDecision`
policy evidence (effect, ``allowed``, deny reason, matched specificity,
``matched_allow``, ``matched_deny``), never only ``allowed``.

Coverage:

- MATRIX: a deterministic hand-authored parity matrix entered through
  the domain-facing evaluator implementations, reusing the exact
  scenarios of the PR 8E P/R differential (proving domain-to-primitive
  conversion plus compiled semantics);
- METAMORPHIC: Role order, PermissionSet order, Permission order, and
  duplicate invariance for all three implementations (the compiled
  policy is recompiled per permutation so compilation itself is proven
  order-independent);
- PROPERTIES: generated/property-based full-decision parity over
  syntactically valid SYSTEM policy (no arbitrary malformed garbage).

Every test requires the canonical ``./build.sh --rust`` native build
(including the PR 8G ``compile_policy`` capability) and the whole
module skips when the native module is absent. No PostgreSQL, Podman,
network service, timing assertion, or randomness outside Hypothesis is
used.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from authz_helpers import (
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)
from helpers import make_id
from hypothesis import given, settings
from hypothesis import strategies as st

from compiled_policy_evaluator import CompiledPolicyEvaluator
from mtmf_core import (
    Action,
    ActionUrn,
    AuthorizationDecision,
    DomainId,
    Permission,
    PermissionEffect,
    PermissionSet,
    PermissionUrn,
    Role,
    RoleUrn,
)
from mtmf_core.authorization.permission_evaluator import PermissionEvaluator
from mtmf_core.authorization.rust_permission_evaluator import RustPermissionEvaluator

NATIVE_MODULE = "_mtmf_permission_engine"

pytest.importorskip(NATIVE_MODULE)

_PYTHON = PermissionEvaluator()
_RUST = RustPermissionEvaluator()

SET_ACTIVE = "urn:mtmf:iam:permissions:system:principal:set-active"
SET_ALIAS = "urn:mtmf:iam:permissions:system:principal:set-alias"
SET_ANY = "urn:mtmf:iam:permissions:system:principal:set-*"
GET_OBJECT = "urn:mtmf:iam:permissions:system:principal:get-object"


def _compiled_decision(action: Action, roles: object) -> AuthorizationDecision:
    """Compile the Roles once and evaluate the Action against the result."""
    return CompiledPolicyEvaluator.compile(roles).evaluate(action)


def _assert_pairs_equal(
    left: AuthorizationDecision, right: AuthorizationDecision, *, label: str
) -> None:
    """Complete policy-evidence equality for one decision pair."""
    assert right == left, label
    assert right.allowed == left.allowed, label
    assert right.effect == left.effect, label
    assert right.reason == left.reason, label
    assert right.matched_specificity == left.matched_specificity, label
    assert right.matched_allow == left.matched_allow, label
    assert right.matched_deny == left.matched_deny, label


def _assert_full_parity(action: Action, roles: object, *, label: str = "") -> None:
    """Assert Python == Rust == Compiled over the complete decision."""
    python_decision = _PYTHON.evaluate(action, roles)
    rust_decision = _RUST.evaluate(action, roles)
    compiled_decision = _compiled_decision(action, roles)
    _assert_pairs_equal(rust_decision, python_decision, label=f"{label} (rust vs python)")
    _assert_pairs_equal(compiled_decision, python_decision, label=f"{label} (compiled vs python)")


def _single_set_role(
    *,
    effect: PermissionEffect = PermissionEffect.ALLOW,
    rules: tuple[tuple[str, str], ...] = (("set", "active"),),
    role_urn: RoleUrn | None = None,
) -> Role:
    urn = role_urn if role_urn is not None else make_role_urn()
    return make_role_from_sets(
        role_urn=urn,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, effect=effect, rules=rules),),
    )


def _multi_set_role(*sets: tuple[PermissionEffect, tuple[tuple[str, str], ...]]) -> Role:
    urn = make_role_urn()
    return make_role_from_sets(
        role_urn=urn,
        permission_sets=tuple(
            make_permission_set_with_rules(role_urn=urn, effect=effect, rules=rules)
            for effect, rules in sets
        ),
    )


def _case(
    label: str, builder: Callable[[], tuple[Action, object]]
) -> tuple[str, Callable[[], tuple[Action, object]]]:
    return label, builder


# --- Deterministic hand-authored parity matrix -------------------------------

_MATRIX_CASES: list[tuple[str, Callable[[], tuple[Action, object]]]] = [
    # 1. No Roles.
    _case(
        "no_roles",
        lambda: (make_action(verb="set", qualifier="active"), ()),
    ),
    # 2. One exact ALLOW.
    _case(
        "one_exact_allow",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (_single_set_role(rules=(("set", "active"),)),),
        ),
    ),
    # 3. One exact DENY.
    _case(
        "one_exact_deny",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (_single_set_role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),),
        ),
    ),
    # 4. One wildcard ALLOW.
    _case(
        "one_wildcard_allow",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (_single_set_role(rules=(("set", "*"),)),),
        ),
    ),
    # 5. One wildcard DENY.
    _case(
        "one_wildcard_deny",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (_single_set_role(effect=PermissionEffect.DENY, rules=(("set", "*"),)),),
        ),
    ),
    # 6. No matching Permission.
    _case(
        "no_matching_permission",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (_single_set_role(rules=(("get", "object"),)),),
        ),
    ),
    # 7. Wildcard ALLOW + exact DENY.
    _case(
        "wildcard_allow_plus_exact_deny",
        lambda: (
            make_action(verb="set", qualifier="alias"),
            (
                _multi_set_role(
                    (PermissionEffect.ALLOW, (("set", "*"),)),
                    (PermissionEffect.DENY, (("set", "alias"),)),
                ),
            ),
        ),
    ),
    # 8. Wildcard DENY + exact ALLOW.
    _case(
        "wildcard_deny_plus_exact_allow",
        lambda: (
            make_action(verb="set", qualifier="alias"),
            (
                _multi_set_role(
                    (PermissionEffect.DENY, (("set", "*"),)),
                    (PermissionEffect.ALLOW, (("set", "alias"),)),
                ),
            ),
        ),
    ),
    # 9. Exact ALLOW + exact DENY (equal specificity).
    _case(
        "exact_allow_plus_exact_deny",
        lambda: (
            make_action(verb="set", qualifier="alias"),
            (
                _multi_set_role(
                    (PermissionEffect.ALLOW, (("set", "alias"),)),
                    (PermissionEffect.DENY, (("set", "alias"),)),
                ),
            ),
        ),
    ),
    # 10. Wildcard ALLOW + wildcard DENY (equal specificity).
    _case(
        "wildcard_allow_plus_wildcard_deny",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (
                _multi_set_role(
                    (PermissionEffect.ALLOW, (("set", "*"),)),
                    (PermissionEffect.DENY, (("set", "*"),)),
                ),
            ),
        ),
    ),
    # 11. Multiple Roles (equal-specificity DENY across Role boundaries).
    _case(
        "multiple_roles",
        lambda: (
            make_action(verb="set", qualifier="alias"),
            (
                _single_set_role(rules=(("set", "alias"),), role_urn=make_role_urn(role_name="a")),
                _single_set_role(
                    effect=PermissionEffect.DENY,
                    rules=(("set", "alias"),),
                    role_urn=make_role_urn(role_name="b"),
                ),
            ),
        ),
    ),
    # 12. Multiple PermissionSets in one Role.
    _case(
        "multiple_sets_in_one_role",
        lambda: (
            make_action(verb="set", qualifier="alias"),
            (
                _multi_set_role(
                    (PermissionEffect.ALLOW, (("get", "object"),)),
                    (PermissionEffect.ALLOW, (("set", "*"),)),
                    (PermissionEffect.DENY, (("set", "alias"),)),
                ),
            ),
        ),
    ),
    # 13. Multiple Permissions in one PermissionSet.
    _case(
        "multiple_permissions_in_one_set",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (_single_set_role(rules=(("set", "*"), ("set", "active"), ("get", "object"))),),
        ),
    ),
    # 14. Duplicate exact ALLOW.
    _case(
        "duplicate_exact_allow",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (
                _multi_set_role(
                    (PermissionEffect.ALLOW, (("set", "active"),)),
                    (PermissionEffect.ALLOW, (("set", "active"),)),
                ),
            ),
        ),
    ),
    # 15. Duplicate exact DENY.
    _case(
        "duplicate_exact_deny",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (
                _multi_set_role(
                    (PermissionEffect.DENY, (("set", "active"),)),
                    (PermissionEffect.DENY, (("set", "active"),)),
                ),
            ),
        ),
    ),
    # 16. Duplicate ALLOW plus equal-specificity DENY.
    _case(
        "duplicate_allow_plus_equal_deny",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (
                _multi_set_role(
                    (PermissionEffect.ALLOW, (("set", "active"),)),
                    (PermissionEffect.ALLOW, (("set", "active"),)),
                    (PermissionEffect.DENY, (("set", "active"),)),
                ),
            ),
        ),
    ),
    # 17. Duplicate equivalent matcher URNs across different sets and Roles.
    _case(
        "duplicate_matchers_across_sets_and_roles",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (
                _multi_set_role(
                    (PermissionEffect.ALLOW, (("set", "active"),)),
                    (PermissionEffect.ALLOW, (("set", "active"),)),
                ),
                _single_set_role(rules=(("set", "active"),), role_urn=make_role_urn(role_name="b")),
            ),
        ),
    ),
    # 18. Unrelated resources in a large-ish policy.
    _case(
        "unrelated_resources",
        lambda: (
            make_action(verb="set", qualifier="active"),
            (
                _multi_set_role(
                    (PermissionEffect.ALLOW, (("get", "object"), ("set", "alias"))),
                    (PermissionEffect.DENY, (("delete", "object"), ("get", "*"))),
                ),
            ),
        ),
    ),
    # 19. Empty PermissionSets are structurally impossible on the domain
    # side (PR 3 invariant), so the matrix stays within valid policy.
]


@pytest.mark.parametrize(
    ("label", "builder"),
    _MATRIX_CASES,
    ids=[label for label, _ in _MATRIX_CASES],
)
def test_hand_authored_parity(label: str, builder: Callable[[], tuple[Action, object]]) -> None:
    action, roles = builder()
    _assert_full_parity(action, roles, label=label)


# --- Permutation and determinism matrix cases --------------------------------


def test_permission_set_order_permutation_is_parity_and_invariant() -> None:
    urn = make_role_urn()
    original = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        ),
    )
    swapped = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
        ),
    )
    action = make_action(verb="set", qualifier="alias")
    _assert_full_parity(action, (original,), label="set-order original")
    _assert_full_parity(action, (swapped,), label="set-order swapped")
    assert _PYTHON.evaluate(action, (original,)) == _PYTHON.evaluate(action, (swapped,))
    assert _RUST.evaluate(action, (original,)) == _RUST.evaluate(action, (swapped,))
    assert _compiled_decision(action, (original,)) == _compiled_decision(action, (swapped,))


def test_role_order_permutation_is_parity_and_invariant() -> None:
    allow_role = _single_set_role(rules=(("set", "alias"),), role_urn=make_role_urn(role_name="a"))
    deny_role = _single_set_role(
        effect=PermissionEffect.DENY,
        rules=(("set", "alias"),),
        role_urn=make_role_urn(role_name="b"),
    )
    action = make_action(verb="set", qualifier="alias")
    _assert_full_parity(action, (allow_role, deny_role), label="roles forward")
    _assert_full_parity(action, (deny_role, allow_role), label="roles reversed")
    assert _PYTHON.evaluate(action, (allow_role, deny_role)) == _PYTHON.evaluate(
        action, (deny_role, allow_role)
    )
    assert _RUST.evaluate(action, (allow_role, deny_role)) == _RUST.evaluate(
        action, (deny_role, allow_role)
    )
    assert _compiled_decision(action, (allow_role, deny_role)) == _compiled_decision(
        action, (deny_role, allow_role)
    )


def test_permission_order_permutation_is_parity_and_invariant() -> None:
    urn = make_role_urn()
    set_id = make_id()

    def build(permissions: tuple[Permission, ...]) -> Role:
        return make_role_from_sets(
            role_urn=urn,
            permission_sets=(PermissionSet(set_id, urn, PermissionEffect.ALLOW, permissions),),
        )

    def perm(text: str) -> Permission:
        return Permission(make_id(), set_id, PermissionUrn(text))

    original = build((perm(GET_OBJECT), perm(SET_ACTIVE), perm(SET_ANY)))
    reversed_ = build((perm(SET_ANY), perm(SET_ACTIVE), perm(GET_OBJECT)))
    action = make_action(verb="set", qualifier="active")
    _assert_full_parity(action, (original,), label="perm-order original")
    _assert_full_parity(action, (reversed_,), label="perm-order reversed")
    assert _PYTHON.evaluate(action, (original,)) == _PYTHON.evaluate(action, (reversed_,))
    assert _RUST.evaluate(action, (original,)) == _RUST.evaluate(action, (reversed_,))
    assert _compiled_decision(action, (original,)) == _compiled_decision(action, (reversed_,))


def test_repeated_evaluation_is_deterministic_and_parity() -> None:
    role = _multi_set_role(
        (PermissionEffect.ALLOW, (("set", "*"),)),
        (PermissionEffect.DENY, (("set", "alias"),)),
    )
    action = make_action(verb="set", qualifier="alias")
    first_python = _PYTHON.evaluate(action, (role,))
    first_rust = _RUST.evaluate(action, (role,))
    compiled = CompiledPolicyEvaluator.compile((role,))
    first_compiled = compiled.evaluate(action)
    for _ in range(5):
        assert _PYTHON.evaluate(action, (role,)) == first_python
        assert _RUST.evaluate(action, (role,)) == first_rust
        assert compiled.evaluate(action) == first_compiled
    _assert_full_parity(action, (role,), label="determinism")


# --- Generated/property-based parity ------------------------------------------

_ROLE_NAMES = ("admin", "analyst", "auditor", "operator", "support")
_RESOURCES = ("principal", "role", "tenant", "organization", "group", "identity")
_VERBS = ("create", "get", "update", "delete", "set")
_QUALIFIERS = ("object", "active", "inactive", "alias", "description", "extension")

_ACTION = st.builds(
    lambda resource, verb, qualifier: Action(
        ActionUrn(f"urn:mtmf:iam:actions:system:{resource}:{verb}-{qualifier}")
    ),
    resource=st.sampled_from(_RESOURCES),
    verb=st.sampled_from(_VERBS),
    qualifier=st.sampled_from(_QUALIFIERS),
)


def _permission_texts() -> st.SearchStrategy[str]:
    return st.builds(
        lambda resource, verb, qualifier: (
            f"urn:mtmf:iam:permissions:system:{resource}:{verb}-{qualifier}"
        ),
        resource=st.sampled_from(_RESOURCES),
        verb=st.sampled_from(_VERBS),
        qualifier=st.sampled_from((*_QUALIFIERS, "*")),
    )


@st.composite
def _role(draw: st.DrawFn) -> Role:
    role_name = draw(st.sampled_from(_ROLE_NAMES))
    urn = RoleUrn(f"urn:mtmf:iam:roles:system:{role_name}")
    sets: list[PermissionSet] = []
    effects = draw(
        st.lists(
            st.sampled_from((PermissionEffect.ALLOW, PermissionEffect.DENY)),
            min_size=1,
            max_size=3,
        )
    )
    for effect in effects:
        set_id = DomainId.generate()
        permission_texts = draw(st.lists(_permission_texts(), min_size=1, max_size=3))
        permissions = tuple(
            Permission(DomainId.generate(), set_id, PermissionUrn(text))
            for text in permission_texts
        )
        sets.append(PermissionSet(set_id, urn, effect, permissions))
    return Role(urn, role_name, "", None, tuple(sets))


@st.composite
def _policy(draw: st.DrawFn) -> tuple[Action, tuple[Role, ...]]:
    action = draw(_ACTION)
    roles = draw(st.lists(_role(), min_size=0, max_size=3))
    return action, tuple(roles)


@settings(max_examples=60, deadline=1000)
@given(policy=_policy())
def test_generated_policies_have_full_decision_parity(
    policy: tuple[Action, tuple[Role, ...]],
) -> None:
    action, roles = policy
    _assert_full_parity(action, roles, label=f"generated {action.urn.value} {len(roles)} roles")


@settings(max_examples=40, deadline=1000)
@given(policy=_policy())
def test_role_order_permutation_is_invariant_across_all_three(
    policy: tuple[Action, tuple[Role, ...]],
) -> None:
    action, roles = policy
    if len(roles) < 2:
        return
    reversed_roles = tuple(reversed(roles))
    _assert_full_parity(action, roles, label="roles")
    _assert_full_parity(action, reversed_roles, label="reversed roles")
    assert _compiled_decision(action, roles) == _compiled_decision(action, reversed_roles)


@settings(max_examples=40, deadline=1000)
@given(policy=_policy())
def test_permission_set_order_permutation_is_invariant_across_all_three(
    policy: tuple[Action, tuple[Role, ...]],
) -> None:
    action, roles = policy
    for role in roles:
        if len(role.permission_sets) < 2:
            continue
        shuffled = Role(
            role.urn,
            role.name,
            role.description,
            role.defining_tenant_id,
            tuple(reversed(role.permission_sets)),
        )
        _assert_full_parity(action, (role,), label="sets")
        _assert_full_parity(action, (shuffled,), label="shuffled sets")
        assert _compiled_decision(action, (role,)) == _compiled_decision(action, (shuffled,))


@settings(max_examples=40, deadline=1000)
@given(policy=_policy())
def test_permission_order_permutation_is_invariant_across_all_three(
    policy: tuple[Action, tuple[Role, ...]],
) -> None:
    action, roles = policy
    for role in roles:
        if len(role.permission_sets) != 1 or len(role.permission_sets[0].permissions) < 2:
            continue
        original_set = role.permission_sets[0]
        reversed_set = PermissionSet(
            original_set.id,
            original_set.role_urn,
            original_set.effect,
            tuple(reversed(original_set.permissions)),
        )
        rebuilt = Role(
            role.urn, role.name, role.description, role.defining_tenant_id, (reversed_set,)
        )
        _assert_full_parity(action, (role,), label="permissions")
        _assert_full_parity(action, (rebuilt,), label="reversed permissions")
        assert _compiled_decision(action, (role,)) == _compiled_decision(action, (rebuilt,))
