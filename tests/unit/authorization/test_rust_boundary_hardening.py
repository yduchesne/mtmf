"""PR 8E boundary-hardening tests for the Rust permission-engine FFI.

Workstream A of PR 8E hardens the existing boundary without adding
authorization semantics:

- NATIVE-INPUT: malformed Action/Permission URN text (empty, truncated,
  non-URN, unsupported namespace, wildcard Action, partial wildcard,
  missing/extra structure, unusually long malformed strings), unknown
  PermissionSet effects, and wrong primitive/container types or shapes
  are rejected explicitly and are never a valid ``NO_MATCH``,
  ``MATCHED_DENY``, or ALLOW.
- SEAM-CLOSURE: adapter-side ``TypeError`` from the native layer is
  normalized into ``ValueError`` so every malformed/native boundary
  failure classifies as a fail-closed infrastructure/parsing failure
  and can never be misread as a policy outcome.
- NATIVE-OUTPUT: the adapter rejects every incoherent or unknown native
  aggregate state (ALLOW carrying a deny reason, ALLOW with
  ``matched_deny``, NO_MATCH carrying a specificity or match flags,
  MATCHED_DENY without evidence, unknown decision/specificity/deny
  reason, malformed result shapes) with
  :class:`RustEngineCapabilityError`.
- FAIL-CLOSED: malformed input or incoherent output at the evaluator
  seam becomes :class:`PermissionEvaluationInfrastructureError` (never
  an :class:`AuthorizationDecision`), and structural-corruption parity
  with the Python reference is retained (ownership check fails before
  any native call with the same :class:`PermissionEvaluationError`).

Tests that genuinely require the built native module skip when it is
not installed. Hermetic adapter tests (monkeypatched fake native module)
always run. No PostgreSQL/Podman/network service and no timing
assertion is used.
"""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest
from authz_helpers import (
    corrupt_role,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)

from mtmf_core import PermissionEvaluationError
from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEvaluation,
    native_evaluate,
    native_match_permission_urn,
)
from mtmf_core.authorization.rust_permission_evaluator import (
    PermissionEvaluationInfrastructureError,
    RustPermissionEvaluator,
)

NATIVE_MODULE = "_mtmf_permission_engine"

ACTION = "urn:mtmf:iam:actions:system:principal:set-active"
ACTION_ALIAS = "urn:mtmf:iam:actions:system:principal:set-alias"
EXACT = "urn:mtmf:iam:permissions:system:principal:set-active"
EXACT_ALIAS = "urn:mtmf:iam:permissions:system:principal:set-alias"
WILDCARD = "urn:mtmf:iam:permissions:system:principal:set-*"
NON_MATCH = "urn:mtmf:iam:permissions:system:principal:set-inactive"

# A finite but pathologically long malformed URN: it must fail parsing,
# never panic, never truncate into something parseable, and never
# degrade into a semantic decision.
LONG_MALFORMED = "urn:wrong:iam:" + ("a" * 100_000)

# A long malformed string with no URN structure at all.
LONG_GARBAGE = "not-a-urn" + "x" * 100_000


def _native() -> ModuleType:
    return pytest.importorskip(NATIVE_MODULE)


def _fake_native(*, evaluate=None, matcher=None) -> ModuleType:
    """Build a minimal fake native module for hermetic adapter tests."""
    return SimpleNamespace(
        engine_version=lambda: "0.1.0",
        match_permission=matcher
        if matcher is not None
        else (lambda action_urn, permission_urn: None),
        evaluate=evaluate if evaluate is not None else (lambda action_urn, permission_sets: None),
    )


def _monkeypatch_native(monkeypatch: pytest.MonkeyPatch, native: object) -> None:
    monkeypatch.setitem(sys.modules, NATIVE_MODULE, native)


# --- NATIVE-INPUT: malformed URN text raises, never a decision ---------------

_INVALID_ACTIONS = [
    "",
    ":",
    "urn:",
    "urn:mtmf:iam:actions:",
    "urn:mtmf:iam:actions:::",
    "urn:mtmf:iam:actions:system:principal:set-active:",  # trailing colon
    "urn:mtmf:iam:actions:system:principal:set-active:extra",  # extra structure
    "urn:mtmf:iam:actions:system:principal:setactive",  # missing hyphen
    "urn:mtmf:iam:actions:system:principal:-active",  # empty verb
    "urn:mtmf:iam:actions:system:principal:set-",  # empty qualifier
    "urn:mtmf:iam:actions::principal:set-active",  # missing namespace
    "urn:mtmf:iam:actions:system::set-active",  # empty resource
    "urn:mtmf:iam:actions:tenant:principal:set-active",  # unsupported namespace
    "urn:mtmf:iam:actions:vendor:principal:set-active",  # unknown namespace
    "urn:mtmf:iam:actions:system:principal:set-*",  # wildcard Action
    "urn:mtmf:iam:actions:system:principal:set-act*ve",  # partial wildcard
    "urn:mtmf:iam:actions:system:prin*cipal:set-active",  # wildcard resource
    "urn:mtmf:iam:actions:system:principal:s*t-active",  # wildcard verb
    "urn:mtmf:iam:actions:system:principal:set -active",  # whitespace
    "urn:mtmf:iam:permissions:system:principal:set-active",  # wrong kind
    "not-a-urn",
    LONG_MALFORMED,
    LONG_GARBAGE,
]

_INVALID_PERMISSIONS = [
    "",
    ":",
    "urn:",
    "urn:mtmf:iam:permissions:",
    "urn:mtmf:iam:permissions:::",
    "urn:mtmf:iam:permissions:system:principal:set-active:",  # trailing colon
    "urn:mtmf:iam:permissions:system:principal:set-active:extra",  # extra structure
    "urn:mtmf:iam:permissions:system:principal:setactive",  # missing hyphen
    "urn:mtmf:iam:permissions:system:principal:-active",  # empty verb
    "urn:mtmf:iam:permissions:system:principal:set-",  # empty qualifier
    "urn:mtmf:iam:permissions::principal:set-active",  # missing namespace
    "urn:mtmf:iam:permissions:system::set-*",  # empty resource
    "urn:mtmf:iam:permissions:tenant:principal:set-active",  # unsupported namespace
    "urn:mtmf:iam:permissions:vendor:principal:set-active",  # unknown namespace
    "urn:mtmf:iam:permissions:system:prin*cipal:set-*",  # wildcard resource
    "urn:mtmf:iam:permissions:system:principal:s*t-*",  # wildcard verb
    "urn:mtmf:iam:permissions:system:principal:set-act*ve",  # partial wildcard
    "urn:mtmf:iam:permissions:system:principal:set-al*",  # partial wildcard suffix
    "urn:mtmf:iam:permissions:system:principal:*",  # bare wildcard qualifier
    "urn:mtmf:iam:permissions:system:principal:*:set-active",  # wildcard verb position
    "urn:mtmf:iam:permissions:system:principal:set -active",  # whitespace
    "urn:mtmf:iam:actions:system:principal:set-active",  # wrong kind
    "not-a-urn",
    LONG_MALFORMED,
    LONG_GARBAGE,
]


@pytest.mark.parametrize(
    "action_text", _INVALID_ACTIONS, ids=[f"a{i}" for i in range(len(_INVALID_ACTIONS))]
)
def test_malformed_action_raises_and_never_becomes_a_decision(action_text: str) -> None:
    _native()
    with pytest.raises(ValueError):
        native_evaluate(action_text, [("allow", [EXACT])])
    with pytest.raises(ValueError):
        native_match_permission_urn(action_text, EXACT)


@pytest.mark.parametrize(
    "permission_text",
    _INVALID_PERMISSIONS,
    ids=[f"p{i}" for i in range(len(_INVALID_PERMISSIONS))],
)
def test_malformed_permission_raises_and_never_becomes_a_decision(permission_text: str) -> None:
    _native()
    with pytest.raises(ValueError):
        native_evaluate(ACTION, [("allow", [permission_text])])
    with pytest.raises(ValueError):
        native_match_permission_urn(ACTION, permission_text)


def test_valid_non_match_is_distinct_from_malformed_input() -> None:
    _native()
    # A valid non-matching URN is a None/``no-match`` fact; malformed
    # text is a parsing failure. The two must never blur.
    assert native_match_permission_urn(ACTION, NON_MATCH) is None
    result = native_evaluate(ACTION, [("allow", [NON_MATCH])])
    assert result.decision == "deny"
    assert result.deny_reason == "no-match"
    with pytest.raises(ValueError):
        native_match_permission_urn(ACTION, "not-a-urn")
    with pytest.raises(ValueError):
        native_evaluate(ACTION, [("allow", ["not-a-urn"])])


# --- NATIVE-INPUT: unknown/empty/wrong-case effects ---------------------------

_INVALID_EFFECTS = ["ALLOW", "Deny", "allow-deny", "neutral", "true", "", "None", "both"]


@pytest.mark.parametrize(
    "effect", _INVALID_EFFECTS, ids=[f"e{i}" for i in range(len(_INVALID_EFFECTS))]
)
def test_unknown_effect_raises_and_never_becomes_a_decision(effect: str) -> None:
    _native()
    with pytest.raises(ValueError):
        native_evaluate(ACTION, [(effect, [EXACT])])


def test_exact_canonical_effects_are_accepted() -> None:
    _native()
    assert native_evaluate(ACTION, [("allow", [EXACT])]).allowed
    assert not native_evaluate(ACTION, [("deny", [EXACT])]).allowed


# --- NATIVE-INPUT: wrong primitive/container types and shapes -----------------

# Values the domain construction normally prevents but the adapter is
# reachable with. The PyO3 `String`/`Vec` extraction rejects these with
# TypeError, which the adapter normalizes into the documented ValueError
# contract (never a decision).
_WRONG_SCALAR_TYPES: list[object] = [None, 123, 1.5, b"bytes", ["a"], {"urn": "x"}, True]


@pytest.mark.parametrize(
    "action_text", _WRONG_SCALAR_TYPES, ids=[f"t{i}" for i in range(len(_WRONG_SCALAR_TYPES))]
)
def test_wrong_action_type_raises_value_error(action_text: object) -> None:
    _native()
    with pytest.raises(ValueError):
        native_evaluate(action_text, [("allow", [EXACT])])  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "permission_text",
    _WRONG_SCALAR_TYPES,
    ids=[f"t{i}" for i in range(len(_WRONG_SCALAR_TYPES))],
)
def test_wrong_permission_type_raises_value_error(permission_text: object) -> None:
    _native()
    with pytest.raises(ValueError):
        native_evaluate(ACTION, [("allow", [permission_text])])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        native_match_permission_urn(ACTION, permission_text)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_sets",
    [
        None,
        42,
        "allow",  # a str is not a list of pairs
        [("allow",)],
        [(EXACT, [EXACT])],
        [(123, [EXACT])],
        [("allow", [EXACT]), "x"],
    ],
    ids=[f"s{i}" for i in range(7)],
)
def test_wrong_container_shape_raises(bad_sets: object) -> None:
    _native()
    with pytest.raises((ValueError, TypeError)):
        native_evaluate(ACTION, bad_sets)  # type: ignore[arg-type]


def test_wrong_permissions_sequence_type_raises_value_error() -> None:
    _native()
    # A non-iterable Permission collection cannot be flattened into
    # primitive texts; it fails explicitly, never as a decision.
    with pytest.raises(ValueError):
        native_evaluate(ACTION, [("allow", 5)])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        native_evaluate(ACTION, [("allow", [EXACT, 42])])  # type: ignore[list-item]


# --- SEAM-CLOSURE: adapter normalizes native TypeError to ValueError ----------


def test_adapter_normalizes_native_type_error_to_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(action_urn: object, permission_sets: object) -> object:
        raise TypeError("argument 'action_urn': 'int' object cannot be converted to 'PyString'")

    _monkeypatch_native(monkeypatch, _fake_native(evaluate=broken))
    with pytest.raises(ValueError) as raised:
        native_evaluate(123, [("allow", [EXACT])])  # type: ignore[arg-type]
    assert "native" in str(raised.value)


def test_matcher_adapter_normalizes_native_type_error_to_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(action_urn: object, permission_urn: object) -> object:
        raise TypeError("cannot convert to PyString")

    _monkeypatch_native(monkeypatch, _fake_native(matcher=broken))
    with pytest.raises(ValueError):
        native_match_permission_urn(123, EXACT)  # type: ignore[arg-type]


def test_adapter_rejects_missing_evaluator_before_any_type_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _monkeypatch_native(monkeypatch, SimpleNamespace(engine_version=lambda: "0.1.0"))
    with pytest.raises(RustEngineCapabilityError):
        native_evaluate(ACTION, [("allow", [EXACT])])


# --- NATIVE-OUTPUT: incoherent/unknown aggregate states are rejected ----------

# (response, native inputs) pairs: every response must be rejected as an
# incoherent or unknown native evaluation result.
_INCOHERENT_RESPONSES = [
    # ALLOW variants that can never be coherent.
    (("allow", "exact", True, False, "matched-deny"), "allow+deny_reason"),
    (("allow", "exact", True, True, None), "allow+matched_deny"),
    (("allow", None, True, False, None), "allow+no_specificity"),
    (("allow", "qualifier-wildcard", False, False, None), "allow+no_allow_flag"),
    # DENY/NO_MATCH variants that can never be coherent.
    (("deny", "exact", False, False, "no-match"), "no_match+specificity"),
    (("deny", None, True, False, "no-match"), "no_match+matched_allow"),
    (("deny", None, False, True, "no-match"), "no_match+matched_deny"),
    (("deny", None, True, True, "no-match"), "no_match+both_flags"),
    # DENY/MATCHED_DENY variants that can never be coherent.
    (("deny", None, False, True, "matched-deny"), "matched_deny+no_specificity"),
    (("deny", "exact", True, False, "matched-deny"), "matched_deny+deny_flag_false"),
    (("deny", "exact", False, False, "matched-deny"), "matched_deny+no_evidence"),
    # Unknown primitive values.
    (("ALLOW", "exact", True, False, None), "unknown_decision"),
    (("deny", "exact", True, True, "ALLOW"), "unknown_deny_reason"),
    (("deny", "super-exact", True, True, "matched-deny"), "unknown_specificity"),
    # Malformed result shapes.
    (("allow",), "short_tuple"),
    (("allow", "exact", True, False, None, "extra"), "long_tuple"),
    ("allow", "non_tuple"),
    (("allow", "exact", 1, 0, None), "non_bool_flags"),
]


@pytest.mark.parametrize(
    ("response", "label"),
    _INCOHERENT_RESPONSES,
    ids=[label for _, label in _INCOHERENT_RESPONSES],
)
def test_incoherent_native_response_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    response: object,
    label: str,
) -> None:
    _monkeypatch_native(
        monkeypatch,
        _fake_native(evaluate=lambda action_urn, permission_sets: response),
    )
    with pytest.raises(RustEngineCapabilityError) as raised:
        native_evaluate(ACTION, [("allow", [EXACT])])
    assert str(raised.value)  # an explanatory message exists


def test_documented_coherent_native_states_are_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coherent = [
        ("allow", "exact", True, False, None),
        ("allow", "qualifier-wildcard", True, False, None),
        ("deny", None, False, False, "no-match"),
        ("deny", "exact", False, True, "matched-deny"),
        ("deny", "exact", True, True, "matched-deny"),
    ]
    for response in coherent:
        _monkeypatch_native(
            monkeypatch,
            _fake_native(evaluate=lambda action_urn, permission_sets, r=response: r),
        )
        result = native_evaluate(ACTION, [("allow", [EXACT])])
        assert isinstance(result, RustEvaluation)


# --- FAIL-CLOSED: malformed/type errors become infrastructure errors ---------


def test_type_error_from_native_becomes_infrastructure_error_never_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mtmf_core.authorization.rust_permission_evaluator as module

    def broken(action_urn: object, permission_sets: object) -> object:
        raise TypeError("cannot convert to PyString")

    monkeypatch.setattr(module, "native_evaluate", broken)
    role_urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=role_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=role_urn, rules=(("set", "active"),)),
        ),
    )
    with pytest.raises(PermissionEvaluationInfrastructureError) as raised:
        RustPermissionEvaluator().evaluate(make_action(verb="set", qualifier="active"), (role,))
    assert isinstance(raised.value.__cause__, TypeError)


def test_infrastructure_failure_is_never_an_authorization_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mtmf_core.authorization.rust_permission_evaluator as module

    def broken(action_urn: object, permission_sets: object) -> object:
        raise ValueError("malformed URN reached the native parser")

    monkeypatch.setattr(module, "native_evaluate", broken)
    role_urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=role_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=role_urn, rules=(("set", "active"),)),
        ),
    )
    with pytest.raises(PermissionEvaluationInfrastructureError):
        RustPermissionEvaluator().evaluate(make_action(verb="set", qualifier="active"), (role,))


def test_malformed_input_never_produces_an_allow_or_semantic_deny() -> None:
    """The native boundary is exercised once for every rejected value class."""
    _native()
    # A malformed Permission alongside an otherwise matching policy must
    # fail the whole evaluation: no ALLOW, no MATCHED_DENY, no NO_MATCH.
    with pytest.raises(ValueError):
        native_evaluate(ACTION, [("allow", [WILDCARD]), ("allow", ["not-a-urn"])])
    # A malformed Action fails even with no PermissionSets.
    with pytest.raises(ValueError):
        native_evaluate("urn:mtmf:iam:actions:system:principal:set-", [])


# --- STRUCTURAL-CORRUPTION PARITY (PR 8D retained behavior) ------------------


def test_ownership_corruption_fails_before_native_with_python_error_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> object:
        raise AssertionError("native evaluation must not be reached for corrupt policy")

    import mtmf_core.authorization.rust_permission_evaluator as module

    monkeypatch.setattr(module, "native_evaluate", fail_if_called)
    role_urn = make_role_urn(role_name="target")
    foreign_set = make_permission_set_with_rules(
        role_urn=make_role_urn(role_name="other"), rules=(("set", "*"),)
    )
    corrupt = corrupt_role(role_urn, (foreign_set,))
    action = make_action(verb="set", qualifier="active")
    with pytest.raises(PermissionEvaluationError):
        RustPermissionEvaluator().evaluate(action, (corrupt,))
