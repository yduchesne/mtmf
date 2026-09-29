"""PR 8C Python/Rust evaluator tests.

The matrix mirrors the PR 8C plan (sections 21 and 22):

- DECISIONS: the private primitive evaluator bridge produces the
  documented aggregate result (decision, highest specificity,
  ALLOW/DENY presence at that specificity, coarse deny reason) for no
  sets, single exact/wildcard ALLOW/DENY, specificity dominance, and
  equal-specificity conflict.
- SEMANTICS: duplicates never create voting semantics and ordering
  never changes the result.
- INVALID: malformed Action/Permission URNs raise ``ValueError`` and
  are never a policy DENY or ``NO_MATCH``; unknown PermissionSet
  effects raise ``ValueError`` on the native side.
- PARITY: a few hand-authored comparisons with the authoritative
  Python ``PermissionEvaluator`` prove the native kernel mirrors the
  Python semantics for the settled cases.
- BOUNDARY: the adapter stays private (never exported by
  :mod:`mtmf_core.authorization`), module absence fails closed with
  :class:`RustEngineUnavailableError`, missing/malformed/incoherent
  native evaluators fail with :class:`RustEngineCapabilityError`, and
  the native evaluator is never reachable through active authorization.

Tests that genuinely require the built native module skip when it is
not installed (for example in plain ``./build.sh --qa`` on a machine
that has not run ``./build.sh --rust``). Hermetic adapter-behavior tests
always run. No test here starts PostgreSQL, Podman, or any external
service, and no test instantiates a Role merely to call Rust: the
native path is exercised with primitive data only.
"""

from __future__ import annotations

import subprocess
import sys
from types import ModuleType, SimpleNamespace

import pytest

from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEngineUnavailableError,
    RustEvaluation,
    native_evaluate,
)

NATIVE_MODULE = "_mtmf_permission_engine"

ACTION = "urn:mtmf:iam:actions:system:principal:set-active"
ACTION_ALIAS = "urn:mtmf:iam:actions:system:principal:set-alias"
EXACT = "urn:mtmf:iam:permissions:system:principal:set-active"
EXACT_ALIAS = "urn:mtmf:iam:permissions:system:principal:set-alias"
WILDCARD = "urn:mtmf:iam:permissions:system:principal:set-*"
NON_MATCH = "urn:mtmf:iam:permissions:system:principal:set-inactive"
WRONG_RESOURCE = "urn:mtmf:iam:permissions:system:tenant:set-active"


def _native() -> ModuleType:
    return pytest.importorskip(NATIVE_MODULE)


def _sets(*items: tuple[str, list[str]]) -> list[tuple[str, list[str]]]:
    return list(items)


# --- DECISIONS: the primitive result contract ------------------------------

# Documented primitive results for the settled cases.
# (sets, expected (decision, specificity, allow, deny, reason))
_DECISION_CASES = [
    # Default deny.
    ([], ("deny", None, False, False, "no-match")),
    ([("allow", [])], ("deny", None, False, False, "no-match")),
    (
        [("allow", [NON_MATCH]), ("deny", [WRONG_RESOURCE])],
        ("deny", None, False, False, "no-match"),
    ),
    # Single exact matches.
    ([("allow", [EXACT])], ("allow", "exact", True, False, None)),
    ([("deny", [EXACT])], ("deny", "exact", False, True, "matched-deny")),
    # Single wildcard matches.
    ([("allow", [WILDCARD])], ("allow", "qualifier-wildcard", True, False, None)),
    ([("deny", [WILDCARD])], ("deny", "qualifier-wildcard", False, True, "matched-deny")),
    # Specificity: lower specificity is discarded before effect resolution.
    ([("allow", [WILDCARD]), ("deny", [EXACT])], ("deny", "exact", False, True, "matched-deny")),
    ([("deny", [WILDCARD]), ("allow", [EXACT])], ("allow", "exact", True, False, None)),
    ([("allow", [WILDCARD]), ("allow", [EXACT])], ("allow", "exact", True, False, None)),
    ([("deny", [WILDCARD]), ("deny", [EXACT])], ("deny", "exact", False, True, "matched-deny")),
    # Equal specificity: any DENY wins.
    ([("allow", [EXACT]), ("deny", [EXACT])], ("deny", "exact", True, True, "matched-deny")),
    (
        [("allow", [WILDCARD]), ("deny", [WILDCARD])],
        ("deny", "qualifier-wildcard", True, True, "matched-deny"),
    ),
]


@pytest.mark.parametrize(
    ("permission_sets", "expected"),
    _DECISION_CASES,
    ids=[f"case{i}" for i in range(len(_DECISION_CASES))],
)
def test_primitive_decision_matches_documented_result(
    permission_sets: list[tuple[str, list[str]]],
    expected: tuple[str | None, str | None, bool, bool, str | None],
) -> None:
    _native()
    result = native_evaluate(ACTION, permission_sets)
    assert (
        result.decision,
        result.matched_specificity,
        result.matched_allow,
        result.matched_deny,
        result.deny_reason,
    ) == expected


def test_no_sets_is_default_deny_no_match() -> None:
    _native()
    result = native_evaluate(ACTION, [])
    assert not result.allowed
    assert result.decision == "deny"
    assert result.matched_specificity is None
    assert result.matched_allow is False
    assert result.matched_deny is False
    assert result.deny_reason == "no-match"


def test_exact_allow_carries_clean_allow_evidence() -> None:
    _native()
    result = native_evaluate(ACTION, _sets(("allow", [EXACT])))
    assert result.allowed
    assert result.decision == "allow"
    assert result.matched_specificity == "exact"
    assert result.matched_allow is True
    assert result.matched_deny is False
    assert result.deny_reason is None


# --- SEMANTICS: duplicates and order ---------------------------------------


def test_duplicate_allow_does_not_outweigh_equal_deny() -> None:
    _native()
    duplicates = _sets(("allow", [EXACT]), ("allow", [EXACT]), ("deny", [EXACT]))
    result = native_evaluate(ACTION, duplicates)
    assert result.decision == "deny"
    assert result.matched_specificity == "exact"
    assert result.matched_allow is True
    assert result.matched_deny is True
    assert result.deny_reason == "matched-deny"


def test_duplicate_exact_allow_is_still_allow() -> None:
    _native()
    result = native_evaluate(ACTION, _sets(("allow", [EXACT]), ("allow", [EXACT])))
    assert result.allowed
    assert result.matched_specificity == "exact"


def test_permission_set_order_does_not_change_the_result() -> None:
    _native()
    forward = _sets(("allow", [WILDCARD]), ("deny", [EXACT]))
    backward = _sets(("deny", [EXACT]), ("allow", [WILDCARD]))
    assert native_evaluate(ACTION, forward) == native_evaluate(ACTION, backward)


def test_permission_order_inside_a_set_does_not_change_the_result() -> None:
    _native()
    one_order = _sets(("deny", [NON_MATCH, EXACT]))
    other_order = _sets(("deny", [EXACT, NON_MATCH]))
    assert native_evaluate(ACTION, one_order) == native_evaluate(ACTION, other_order)


def test_repeated_evaluation_is_deterministic() -> None:
    _native()
    sets = _sets(("deny", [WILDCARD]), ("allow", [EXACT]))
    first = native_evaluate(ACTION, sets)
    for _ in range(5):
        assert native_evaluate(ACTION, sets) == first


def test_aggregate_evidence_reports_both_effects_at_maximum_specificity() -> None:
    _native()
    result = native_evaluate(
        ACTION,
        _sets(("deny", [WILDCARD]), ("allow", [EXACT]), ("deny", [EXACT])),
    )
    assert result.decision == "deny"
    assert result.matched_specificity == "exact"
    assert result.matched_allow is True
    assert result.matched_deny is True
    assert result.deny_reason == "matched-deny"


# --- INVALID: malformed input and effects ----------------------------------

_INVALID_ACTIONS = [
    "urn:wrong:iam:actions:system:principal:set-active",
    "urn:mtmf:iam:actions:system:principal:set-*",  # wildcard Action
    "urn:mtmf:iam:actions:system:principal:setactive",  # missing hyphen
    "not-a-urn",
    "",
]

_INVALID_PERMISSIONS = [
    "urn:wrong:iam:permissions:system:principal:set-active",
    "urn:mtmf:iam:permissions:tenant:principal:set-active",  # unsupported namespace
    "urn:mtmf:iam:permissions:system:principal:set-act*ve",  # partial wildcard
    "not-a-urn",
    "",
]


@pytest.mark.parametrize("action_text", _INVALID_ACTIONS)
def test_malformed_action_raises_value_error(action_text: str) -> None:
    _native()
    with pytest.raises(ValueError):
        native_evaluate(action_text, _sets(("allow", [EXACT])))


@pytest.mark.parametrize("permission_text", _INVALID_PERMISSIONS)
def test_malformed_permission_raises_value_error(permission_text: str) -> None:
    _native()
    with pytest.raises(ValueError):
        native_evaluate(ACTION, _sets(("allow", [permission_text])))


def test_invalid_effect_raises_value_error_never_silent_deny() -> None:
    _native()
    # An unknown effect is malformed input, never a silent DENY/ALLOW.
    for bad_effect in ("ALLOW", "Deny", "allow-deny", "neutral", ""):
        with pytest.raises(ValueError):
            native_evaluate(ACTION, [(bad_effect, [EXACT])])


def test_malformed_action_fails_even_with_no_sets() -> None:
    _native()
    with pytest.raises(ValueError):
        native_evaluate("urn:mtmf:iam:actions:system:principal:set-", [])


# --- PARITY: a few hand-authored Python reference comparisons ---------------

_PARITY_CASES = [
    (("allow", [WILDCARD]), ("deny", [EXACT]), ("deny", "exact", False, True, "matched-deny")),
    (("deny", [WILDCARD]), ("allow", [EXACT]), ("allow", "exact", True, False, None)),
    (("allow", [EXACT]), ("deny", [EXACT]), ("deny", "exact", True, True, "matched-deny")),
]


def _python_primitive(permission_sets: list[tuple[str, list[str]]]) -> tuple[object, ...]:
    """Evaluate the settled semantics through the authoritative Python evaluator."""
    from mtmf_core import (
        Action,
        ActionUrn,
        DomainId,
        Permission,
        PermissionEffect,
        PermissionSet,
        PermissionUrn,
        Role,
        RoleUrn,
    )
    from mtmf_core.authorization.permission_evaluator import PermissionEvaluator

    roles = []
    for index, (effect_text, permissions) in enumerate(permission_sets):
        role_urn_text = f"urn:mtmf:iam:roles:system:parity-{index}"
        role_urn = RoleUrn(role_urn_text)
        owned = []
        for permission_text in permissions:
            set_id = DomainId.generate()
            owned.append(
                PermissionSet(
                    id=set_id,
                    role_urn=role_urn,
                    effect=PermissionEffect.ALLOW
                    if effect_text == "allow"
                    else PermissionEffect.DENY,
                    permissions=(
                        Permission(
                            id=DomainId.generate(),
                            permission_set_id=set_id,
                            urn=PermissionUrn(permission_text),
                        ),
                    ),
                )
            )
        roles.append(Role(urn=role_urn, name=f"parity-{index}", permission_sets=tuple(owned)))

    decision = PermissionEvaluator().evaluate(Action(ActionUrn(ACTION)), roles)
    specificity = None
    if decision.matched_specificity is not None:
        specificity = (
            "exact" if decision.matched_specificity.name == "EXACT" else "qualifier-wildcard"
        )
    return (
        "allow" if decision.allowed else "deny",
        specificity,
        decision.matched_allow,
        decision.matched_deny,
        None if decision.allowed else decision.reason.value,
    )


@pytest.mark.parametrize(
    ("first", "second", "expected"),
    _PARITY_CASES,
    ids=[f"parity{i}" for i in range(len(_PARITY_CASES))],
)
def test_native_agrees_with_python_reference(
    first: tuple[str, list[str]],
    second: tuple[str, list[str]],
    expected: tuple[str | None, str | None, bool, bool, str | None],
) -> None:
    _native()
    python_primitive = _python_primitive(_sets(first, second))
    native_result = native_evaluate(ACTION, _sets(first, second))
    native_primitive = (
        native_result.decision,
        native_result.matched_specificity,
        native_result.matched_allow,
        native_result.matched_deny,
        native_result.deny_reason,
    )
    assert python_primitive == expected == native_primitive


def test_native_evaluator_returns_typed_validated_result() -> None:
    _native()
    result = native_evaluate(ACTION, _sets(("allow", [WILDCARD])))
    assert isinstance(result, RustEvaluation)
    assert result.allowed


# --- BOUNDARY: privacy and fail-closed behavior -----------------------------


def test_native_evaluator_adapter_is_private_to_the_authorization_package() -> None:
    import mtmf_core.authorization as authorization

    assert "native_evaluate" not in authorization.__all__
    assert "RustEvaluation" not in authorization.__all__
    assert not hasattr(authorization, "native_evaluate")
    assert not hasattr(authorization, "RustEvaluation")


def test_adapter_fails_closed_when_native_module_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, NATIVE_MODULE, None)
    with pytest.raises(RustEngineUnavailableError):
        native_evaluate(ACTION, _sets(("allow", [EXACT])))


def test_adapter_rejects_missing_native_evaluator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(engine_version=lambda: "0.1.0"),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_evaluate(ACTION, _sets(("allow", [EXACT])))


def test_adapter_rejects_malformed_native_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Not a 5-tuple at all.
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(evaluate=lambda action_urn, sets: "allow"),  # type: ignore[return-value]
    )
    with pytest.raises(RustEngineCapabilityError):
        native_evaluate(ACTION, _sets(("allow", [EXACT])))


def test_adapter_rejects_unknown_native_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(  # type: ignore[return-value]
            evaluate=lambda action_urn, sets: ("ALLOW", "exact", True, False, None)
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_evaluate(ACTION, _sets(("allow", [EXACT])))


def test_adapter_rejects_unknown_native_deny_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(  # type: ignore[return-value]
            evaluate=lambda action_urn, sets: ("deny", "exact", False, True, "forbidden")
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_evaluate(ACTION, _sets(("deny", [EXACT])))


def test_adapter_rejects_incoherent_native_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ALLOW with a deny reason is an incoherent state: no native result
    # may look like this, and the adapter must never accept it.
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(  # type: ignore[return-value]
            evaluate=lambda action_urn, sets: ("allow", "exact", True, False, "matched-deny")
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_evaluate(ACTION, _sets(("allow", [EXACT])))


def test_adapter_rejects_no_match_carrying_a_specificity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(  # type: ignore[return-value]
            evaluate=lambda action_urn, sets: ("deny", "exact", False, False, "no-match")
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_evaluate(ACTION, _sets(("allow", [NON_MATCH])))


def test_adapter_accepts_documented_coherent_native_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(  # type: ignore[return-value]
            evaluate=lambda action_urn, sets: ("deny", "exact", True, True, "matched-deny")
        ),
    )
    result = native_evaluate(ACTION, _sets(("allow", [EXACT]), ("deny", [EXACT])))
    assert result == RustEvaluation("deny", "exact", True, True, "matched-deny")


def test_native_evaluator_not_reachable_through_active_authorization() -> None:
    code = (
        "import sys\n"
        "from mtmf_core import authorization, Authorizer, PermissionEvaluator\n"
        f"sys.exit(1 if {NATIVE_MODULE!r} in sys.modules else 0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
