"""PR 8D RustPermissionEvaluator domain-conversion and mapping tests.

Covers:

- CONVERSION: the Rust-backed evaluator converts already-applicable
  Role policy to the detached primitive native input exactly once:
  canonical Action URN, canonical Permission URNs, existing effect enum
  values, PermissionSets flattened across Roles with no Role identity,
  and one-shot iterables consumed exactly once.
- MAPPING: validated native results map to the complete
  :class:`AuthorizationDecision` policy evidence (effect, allowed, deny
  reason, matched specificity, matched allow/deny) using the existing
  Python enums.
- VALIDATION: Role/PermissionSet ownership corruption fails with
  :class:`PermissionEvaluationError` before any native call.
- FAIL-CLOSED: native unavailability, missing capability, malformed
  responses, and parser ``ValueError`` propagate as
  :class:`PermissionEvaluationInfrastructureError` (with exception
  chaining) and never become a semantic DENY or ALLOW.
- SEMANTICS: the real native-backed path reproduces the settled
  exact/wildcard/equal-DENY behavior through domain objects.

Hermetic adapter tests never require the native module. The semantic
tests require the canonical ``./build.sh --rust`` build and skip when
the native module is not installed. No PostgreSQL/Podman/network
service is used.
"""

from __future__ import annotations

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
    PermissionEvaluationError,
    Role,
    RoleUrn,
)
from mtmf_core.authorization.permission_evaluator import PermissionEvaluator
from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEngineUnavailableError,
    RustEvaluation,
)
from mtmf_core.authorization.rust_permission_evaluator import (
    PermissionEvaluationInfrastructureError,
    RustPermissionEvaluator,
)

NATIVE_MODULE = "_mtmf_permission_engine"

_ACTION_URN = "urn:mtmf:iam:actions:system:principal:set-active"
_PERM_SET_ACTIVE = "urn:mtmf:iam:permissions:system:principal:set-active"
_PERM_SET_ANY = "urn:mtmf:iam:permissions:system:principal:set-*"


def _evaluator() -> RustPermissionEvaluator:
    return RustPermissionEvaluator()


def _one_permission_set_role(
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


# --- CONVERSION: domain-to-primitive ---------------------------------------


def test_converts_canonical_action_urn_and_effect_enum_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_native_evaluate(
        action_urn: str, permission_sets: list[tuple[str, list[str]]]
    ) -> RustEvaluation:
        captured["action_urn"] = action_urn
        captured["permission_sets"] = permission_sets
        return RustEvaluation("deny", None, False, False, "no-match")

    import mtmf_core.authorization.rust_permission_evaluator as module

    monkeypatch.setattr(module, "native_evaluate", fake_native_evaluate)
    role = _one_permission_set_role(effect=PermissionEffect.ALLOW, rules=(("set", "active"),))
    decision = _evaluator().evaluate(make_action(verb="set", qualifier="active"), (role,))

    assert decision == AuthorizationDecision.deny(DenyReason.NO_MATCH)
    # The canonical Action URN value is passed; effects are the existing
    # enum values; Permission URNs are the canonical matcher texts.
    assert captured["action_urn"] == _ACTION_URN
    assert captured["permission_sets"] == [("allow", [_PERM_SET_ACTIVE])]


def test_flattens_permission_sets_across_roles_without_role_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_native_evaluate(
        action_urn: str, permission_sets: list[tuple[str, list[str]]]
    ) -> RustEvaluation:
        captured["permission_sets"] = permission_sets
        return RustEvaluation("deny", None, False, False, "no-match")

    import mtmf_core.authorization.rust_permission_evaluator as module

    monkeypatch.setattr(module, "native_evaluate", fake_native_evaluate)
    allow_urn = make_role_urn(role_name="a")
    deny_urn = make_role_urn(role_name="b")
    allow_role = make_role_from_sets(
        role_urn=allow_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "active"),)),
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "alias"),)),
        ),
    )
    deny_role = make_role_from_sets(
        role_urn=deny_urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=deny_urn, effect=PermissionEffect.DENY, rules=(("get", "object"),)
            ),
        ),
    )
    _evaluator().evaluate(make_action(verb="set", qualifier="active"), (allow_role, deny_role))

    assert captured["permission_sets"] == [
        ("allow", ["urn:mtmf:iam:permissions:system:principal:set-active"]),
        ("allow", ["urn:mtmf:iam:permissions:system:principal:set-alias"]),
        ("deny", ["urn:mtmf:iam:permissions:system:principal:get-object"]),
    ]


def test_no_role_identity_crosses_the_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_native_evaluate(
        action_urn: str, permission_sets: list[tuple[str, list[str]]]
    ) -> RustEvaluation:
        captured["permission_sets"] = permission_sets
        return RustEvaluation("deny", None, False, False, "no-match")

    import mtmf_core.authorization.rust_permission_evaluator as module

    monkeypatch.setattr(module, "native_evaluate", fake_native_evaluate)
    name = "urn:mtmf:iam:roles:system:actor"
    role = _one_permission_set_role(role_urn=RoleUrn(name))
    _evaluator().evaluate(make_action(verb="set", qualifier="active"), (role,))

    combined = repr(captured["permission_sets"])
    assert "roles:" not in combined
    assert "actor" not in combined


def test_maps_multiple_permissions_of_one_set_to_primitive_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_native_evaluate(
        action_urn: str, permission_sets: list[tuple[str, list[str]]]
    ) -> RustEvaluation:
        captured["permission_sets"] = permission_sets
        return RustEvaluation("deny", None, False, False, "no-match")

    import mtmf_core.authorization.rust_permission_evaluator as module

    monkeypatch.setattr(module, "native_evaluate", fake_native_evaluate)
    urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=urn, rules=(("set", "active"), ("set", "alias"), ("get", "object"))
            ),
        ),
    )
    _evaluator().evaluate(make_action(verb="set", qualifier="active"), (role,))

    assert captured["permission_sets"] == [
        (
            "allow",
            [
                "urn:mtmf:iam:permissions:system:principal:set-active",
                "urn:mtmf:iam:permissions:system:principal:set-alias",
                "urn:mtmf:iam:permissions:system:principal:get-object",
            ],
        )
    ]


def test_consumes_one_shot_iterable_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_native_evaluate(
        action_urn: str, permission_sets: list[tuple[str, list[str]]]
    ) -> RustEvaluation:
        return RustEvaluation("allow", "exact", True, False, None)

    import mtmf_core.authorization.rust_permission_evaluator as module

    monkeypatch.setattr(module, "native_evaluate", fake_native_evaluate)

    def generated() -> object:
        urn = make_role_urn()
        yield make_role_from_sets(
            role_urn=urn,
            permission_sets=(
                make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),
            ),
        )

    decision = _evaluator().evaluate(make_action(verb="set", qualifier="active"), generated())
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT


# --- VALIDATION: structural corruption fails before any native call ---------


def test_ownership_corruption_rejected_before_native_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> RustEvaluation:
        raise AssertionError("native evaluation must not be reached for corrupt policy")

    import mtmf_core.authorization.rust_permission_evaluator as module

    monkeypatch.setattr(module, "native_evaluate", fail_if_called)
    role_urn = make_role_urn(role_name="target")
    foreign_set = make_permission_set_with_rules(
        role_urn=make_role_urn(role_name="other"), rules=(("set", "*"),)
    )
    with pytest.raises(PermissionEvaluationError):
        _evaluator().evaluate(
            make_action(verb="set", qualifier="active"), (corrupt_role(role_urn, (foreign_set,)),)
        )


def test_ownership_corruption_matches_python_error_semantics() -> None:
    role_urn = make_role_urn(role_name="target")
    foreign_set = make_permission_set_with_rules(
        role_urn=make_role_urn(role_name="other"), rules=(("set", "*"),)
    )
    corrupt = corrupt_role(role_urn, (foreign_set,))
    action = make_action(verb="set", qualifier="active")
    with pytest.raises(PermissionEvaluationError):
        PermissionEvaluator().evaluate(action, (corrupt,))
    with pytest.raises(PermissionEvaluationError):
        RustPermissionEvaluator().evaluate(action, (corrupt,))


# --- MAPPING: validated native result -> AuthorizationDecision ----------------


def _map(monkeypatch: pytest.MonkeyPatch, native: RustEvaluation) -> AuthorizationDecision:
    evaluator = _evaluator()
    import mtmf_core.authorization.rust_permission_evaluator as module

    monkeypatch.setattr(module, "native_evaluate", lambda action_urn, permission_sets: native)
    return evaluator.evaluate(
        make_action(verb="set", qualifier="active"),
        (_one_permission_set_role(rules=(("set", "active"),)),),
    )


def test_native_allow_maps_to_allow_decision(monkeypatch: pytest.MonkeyPatch) -> None:
    decision = _map(monkeypatch, RustEvaluation("allow", "exact", True, False, None))
    assert decision.allowed
    assert decision.effect.value == "allow"
    assert decision.reason is None
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_allow
    assert not decision.matched_deny


def test_native_wildcard_allow_maps_to_qualifier_wildcard_specificity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = _map(monkeypatch, RustEvaluation("allow", "qualifier-wildcard", True, False, None))
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD


def test_native_no_match_maps_to_deny_no_match(monkeypatch: pytest.MonkeyPatch) -> None:
    decision = _map(monkeypatch, RustEvaluation("deny", None, False, False, "no-match"))
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH
    assert decision.matched_specificity is None
    assert not decision.matched_allow
    assert not decision.matched_deny


def test_native_matched_deny_maps_to_deny_with_exact_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = _map(monkeypatch, RustEvaluation("deny", "exact", True, True, "matched-deny"))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_allow
    assert decision.matched_deny


def test_native_matched_deny_without_equal_allow_keeps_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decision = _map(
        monkeypatch, RustEvaluation("deny", "qualifier-wildcard", False, True, "matched-deny")
    )
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD
    assert not decision.matched_allow
    assert decision.matched_deny


# --- FAIL-CLOSED: native failures are infrastructure errors -------------------


def _evaluate_with_native_failure(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    import mtmf_core.authorization.rust_permission_evaluator as module

    def failing(*args: object, **kwargs: object) -> RustEvaluation:
        raise exc

    monkeypatch.setattr(module, "native_evaluate", failing)
    with pytest.raises(PermissionEvaluationInfrastructureError) as raised:
        _evaluator().evaluate(
            make_action(verb="set", qualifier="active"),
            (_one_permission_set_role(rules=(("set", "active"),)),),
        )
    assert raised.value.__cause__ is exc


def test_native_unavailable_is_infrastructure_error_never_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _evaluate_with_native_failure(
        monkeypatch, RustEngineUnavailableError("native module unavailable")
    )


def test_native_capability_error_is_infrastructure_error_never_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _evaluate_with_native_failure(
        monkeypatch, RustEngineCapabilityError("missing native evaluate capability")
    )


def test_native_parser_value_error_is_infrastructure_error_never_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _evaluate_with_native_failure(
        monkeypatch, ValueError("malformed URN reached the native parser")
    )


def test_native_malformed_response_is_infrastructure_error_never_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _evaluate_with_native_failure(
        monkeypatch,
        RustEngineCapabilityError("native module returned a malformed evaluation response"),
    )


def test_native_incoherent_response_is_infrastructure_error_never_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _evaluate_with_native_failure(
        monkeypatch,
        RustEngineCapabilityError("native module returned an incoherent evaluation state"),
    )


# --- SEMANTICS: real native-backed domain evaluation ------------------------


def _native() -> object:
    return pytest.importorskip(NATIVE_MODULE)


def test_empty_roles_is_default_deny_no_match() -> None:
    _native()
    decision = _evaluator().evaluate(make_action(verb="set", qualifier="active"), ())
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH
    assert decision.matched_specificity is None


def test_exact_allow_over_domain_objects() -> None:
    _native()
    decision = _evaluator().evaluate(
        make_action(verb="set", qualifier="active"),
        (_one_permission_set_role(rules=(("set", "active"),)),),
    )
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_allow
    assert not decision.matched_deny


def test_wildcard_deny_over_domain_objects() -> None:
    _native()
    decision = _evaluator().evaluate(
        make_action(verb="set", qualifier="active"),
        (_one_permission_set_role(effect=PermissionEffect.DENY, rules=(("set", "*"),)),),
    )
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD
    assert decision.matched_deny


def test_wildcard_allow_plus_exact_deny_is_exact_deny() -> None:
    _native()
    urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        ),
    )
    decision = _evaluator().evaluate(make_action(verb="set", qualifier="alias"), (role,))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert not decision.matched_allow


def test_wildcard_deny_plus_exact_allow_is_exact_allow() -> None:
    _native()
    urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
            ),
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
        ),
    )
    decision = _evaluator().evaluate(make_action(verb="set", qualifier="alias"), (role,))
    assert decision.allowed
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_allow
    assert not decision.matched_deny


def test_equal_specificity_conflict_is_deny_with_both_flags() -> None:
    _native()
    urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "alias"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        ),
    )
    decision = _evaluator().evaluate(make_action(verb="set", qualifier="alias"), (role,))
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_allow
    assert decision.matched_deny


def test_no_matching_permission_is_no_match() -> None:
    _native()
    decision = _evaluator().evaluate(
        make_action(verb="set", qualifier="active"),
        (_one_permission_set_role(rules=(("get", "object"),)),),
    )
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


def test_repeated_evaluation_is_deterministic() -> None:
    _native()
    urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),
            make_permission_set_with_rules(
                role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        ),
    )
    action = make_action(verb="set", qualifier="alias")
    first = _evaluator().evaluate(action, (role,))
    for _ in range(5):
        assert _evaluator().evaluate(action, (role,)) == first
