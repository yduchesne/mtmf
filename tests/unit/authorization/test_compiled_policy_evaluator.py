"""Compiled-policy evaluator adapter tests (PR 8G experiment).

Behavioral coverage of :class:`CompiledPolicyEvaluator` (the
benchmark-side experimental adapter in ``benchmarks/``):

- Roles -> compile conversion (empty, single-set, multi-set, multi-role);
- PermissionSet ownership corruption rejected before any native call;
- the compiled policy is opaque and read-only from Python and is reused
  unchanged across evaluations;
- complete result mapping onto :class:`AuthorizationDecision` (never
  only ``allowed``);
- exact/wildcard/no-match/equal-conflict semantics;
- duplicate and permutation invariance at the adapter level;
- native compile failures map to
  :class:`PermissionEvaluationInfrastructureError` (fail closed, never
  a policy decision);
- malformed/incoherent native results fail closed where applicable;
- the experimental benchmark harness runs in smoke mode and writes
  valid JSON with the documented columns.

Every test requires the canonical ``./build.sh --rust`` native build
(including the PR 8G ``compile_policy`` capability) and the whole
module skips when the native module is absent or lacks the capability.
No PostgreSQL, Podman, network service, timing assertion, or randomness
is used.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from authz_helpers import (
    corrupt_role,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)

import compiled_policy_evaluator as compiled_policy_evaluator_module
from compiled_policy_evaluator import CompiledPolicyEvaluator
from mtmf_core import (
    AuthorizationDecision,
    AuthorizationEffect,
    DenyReason,
    MatchSpecificity,
    PermissionEffect,
)
from mtmf_core.authorization.permission_evaluator import (
    PermissionEvaluationError,
    PermissionEvaluator,
)
from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEngineUnavailableError,
)
from mtmf_core.authorization.rust_permission_evaluator import (
    PermissionEvaluationInfrastructureError,
)

NATIVE_MODULE = "_mtmf_permission_engine"

compiled_policy_evaluator = pytest.importorskip("compiled_policy_evaluator")
native = pytest.importorskip(NATIVE_MODULE)

REPO_ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_SCRIPT = REPO_ROOT / "benchmarks" / "compiled_policy_benchmark.py"


def _compile(roles: object) -> CompiledPolicyEvaluator:
    return CompiledPolicyEvaluator.compile(roles)


def _one_set_role(*rules: tuple[str, str]) -> object:
    urn = make_role_urn()
    return make_role_from_sets(
        role_urn=urn,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, rules=rules),),
    )


# --- Roles -> compile conversion and reuse -----------------------------------


def test_compile_empty_roles_is_valid_and_default_deny() -> None:
    compiled = _compile(())
    decision = compiled.evaluate(make_action(verb="set", qualifier="active"))
    assert decision.effect is AuthorizationEffect.DENY
    assert decision.allowed is False
    assert decision.reason is DenyReason.NO_MATCH
    assert decision.matched_specificity is None
    assert not decision.matched_allow
    assert not decision.matched_deny


def test_compile_single_role_and_opaque_object_reuse() -> None:
    urn = make_role_urn()
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"), ("get", "object"))),
        ),
    )
    compiled = _compile((role,))
    opaque = compiled.compiled
    assert callable(getattr(opaque, "evaluate", None))
    # The same opaque object is reused unchanged across evaluations.
    assert compiled.compiled is opaque
    assert compiled.evaluate(make_action(verb="set", qualifier="active")).allowed is True
    assert compiled.evaluate(make_action(verb="set", qualifier="alias")).allowed is True
    assert compiled.compiled is opaque


def test_compile_multi_role_flattening_is_parity_with_python() -> None:
    python = PermissionEvaluator()
    allow_role = make_role_from_sets(
        role_urn=make_role_urn(role_name="allow"),
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=make_role_urn(role_name="allow"), rules=(("set", "active"),)
            ),
        ),
    )
    deny_role = make_role_from_sets(
        role_urn=make_role_urn(role_name="deny"),
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=make_role_urn(role_name="deny"),
                effect=PermissionEffect.DENY,
                rules=(("set", "*"),),
            ),
        ),
    )
    action = make_action(verb="set", qualifier="active")
    compiled_decision = _compile((allow_role, deny_role)).evaluate(action)
    python_decision = python.evaluate(action, (allow_role, deny_role))
    assert compiled_decision == python_decision
    # Exact ALLOW beats the wildcard DENY: complete evidence equality.
    assert compiled_decision.allowed is True
    assert compiled_decision.matched_specificity is MatchSpecificity.EXACT
    assert compiled_decision.matched_allow is True
    assert compiled_decision.matched_deny is False


def test_compiled_object_is_opaque_and_read_only() -> None:
    compiled = _compile((_one_set_role(("set", "*")),))
    opaque = compiled.compiled
    # No mutable map exposure: the opaque object has no instance
    # namespace to attach attributes to, and attributes cannot be set.
    assert not hasattr(opaque, "__dict__")
    with pytest.raises((AttributeError, TypeError)):
        opaque.some_field = 1  # type: ignore[attr-defined]
    # No map/field exposure through normal attribute access.
    with pytest.raises(AttributeError):
        _ = opaque.exact  # type: ignore[attr-defined]


# --- Ownership corruption fails closed before native -------------------------


def test_ownership_corruption_rejected_before_native_call(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(*args: object, **kwargs: object) -> object:
        raise AssertionError("native compile must not be reached for corrupt policy")

    monkeypatch.setattr(compiled_policy_evaluator_module, "native_compile_policy", explode)
    owner_urn = make_role_urn(role_name="owner")
    set_ = make_permission_set_with_rules(role_urn=owner_urn, rules=(("set", "active"),))
    # The corrupt Role claims a different URN than its owned set.
    corrupt = corrupt_role(role_urn=make_role_urn(role_name="impostor"), permission_sets=(set_,))
    with pytest.raises(PermissionEvaluationError):
        _compile((corrupt,))


# --- Complete result mapping --------------------------------------------------


def _assert_decision_evidence(
    compiled: CompiledPolicyEvaluator,
    verb: str,
    qualifier: str,
    *,
    expected: AuthorizationDecision,
) -> None:
    decision = compiled.evaluate(make_action(verb=verb, qualifier=qualifier))
    assert decision == expected, f"{verb}-{qualifier}: {decision!r} != {expected!r}"
    assert decision.allowed == expected.allowed
    assert decision.effect == expected.effect
    assert decision.reason == expected.reason
    assert decision.matched_specificity == expected.matched_specificity
    assert decision.matched_allow == expected.matched_allow
    assert decision.matched_deny == expected.matched_deny


def _mixed_policy_compiled() -> CompiledPolicyEvaluator:
    urn = make_role_urn()
    return _compile(
        (
            make_role_from_sets(
                role_urn=urn,
                permission_sets=(
                    make_permission_set_with_rules(
                        role_urn=urn, rules=(("set", "active"), ("get", "*"))
                    ),
                    make_permission_set_with_rules(
                        role_urn=urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
                    ),
                ),
            ),
        )
    )


def test_complete_result_mapping_matrix() -> None:
    compiled = _mixed_policy_compiled()
    _assert_decision_evidence(
        compiled,
        "set",
        "active",
        # The exact ALLOW beats the wildcard DENY (mixed effects); the
        # wildcard DENY is discarded before effect resolution.
        expected=AuthorizationDecision.allow(
            matched_specificity=MatchSpecificity.EXACT,
            matched_allow=True,
            matched_deny=False,
        ),
    )
    _assert_decision_evidence(
        compiled,
        "get",
        "object",
        expected=AuthorizationDecision.allow(
            matched_specificity=MatchSpecificity.QUALIFIER_WILDCARD,
            matched_allow=True,
            matched_deny=False,
        ),
    )
    _assert_decision_evidence(
        compiled,
        "set",
        "alias",
        expected=AuthorizationDecision.deny(
            DenyReason.MATCHED_DENY,
            matched_specificity=MatchSpecificity.QUALIFIER_WILDCARD,
            matched_allow=False,
            matched_deny=True,
        ),
    )
    _assert_decision_evidence(
        compiled,
        "delete",
        "object",
        expected=AuthorizationDecision.deny(DenyReason.NO_MATCH),
    )


def test_equal_specificity_conflict_is_matched_deny_with_both_flags() -> None:
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
    _assert_decision_evidence(
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


# --- Duplicate and permutation invariance at the adapter level ----------------


def test_duplicate_permissions_and_sets_are_non_voting() -> None:
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
    _assert_decision_evidence(
        duplicated,
        "set",
        "active",
        expected=AuthorizationDecision.allow(
            matched_specificity=MatchSpecificity.EXACT,
            matched_allow=True,
            matched_deny=False,
        ),
    )


def test_permutation_invariance_across_roles() -> None:
    allow_urn = make_role_urn(role_name="allow")
    allow_role = make_role_from_sets(
        role_urn=allow_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "active"),)),
        ),
    )
    deny_urn = make_role_urn(role_name="deny")
    deny_role = make_role_from_sets(
        role_urn=deny_urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=deny_urn, effect=PermissionEffect.DENY, rules=(("set", "*"),)
            ),
        ),
    )
    action = make_action(verb="set", qualifier="active")
    forward = _compile((allow_role, deny_role)).evaluate(action)
    reversed_roles = _compile((deny_role, allow_role)).evaluate(action)
    assert forward == reversed_roles
    assert forward.allowed is True
    assert forward.matched_specificity is MatchSpecificity.EXACT


def test_set_order_permutation_is_invariant() -> None:
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
    # Exact DENY wins over the wildcard ALLOW in both orders.
    assert forward.allowed is False
    assert forward.matched_specificity is MatchSpecificity.EXACT
    assert forward.matched_deny is True


# --- Native failures fail closed ----------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param(ValueError("malformed URN"), id="value-error"),
        pytest.param(RustEngineUnavailableError("module absent"), id="module-absent"),
        pytest.param(RustEngineCapabilityError("capability missing"), id="capability-missing"),
    ],
)
def test_native_compile_failures_map_to_infrastructure_error(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    def failing(*args: object, **kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(compiled_policy_evaluator_module, "native_compile_policy", failing)
    with pytest.raises(PermissionEvaluationInfrastructureError):
        _compile((_one_set_role(("set", "*")),))


def test_malformed_native_result_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class MalformedOpaque:
        def evaluate(self, action_urn: str) -> tuple[object, ...]:
            return ("grant", "exact", True, False, None)

    monkeypatch.setattr(
        compiled_policy_evaluator_module, "native_compile_policy", lambda sets: MalformedOpaque()
    )
    compiled = _compile((_one_set_role(("set", "*")),))
    with pytest.raises(PermissionEvaluationInfrastructureError):
        compiled.evaluate(make_action(verb="set", qualifier="active"))


def test_incoherent_native_result_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class IncoherentOpaque:
        def evaluate(self, action_urn: str) -> tuple[object, ...]:
            # ALLOW with a deny reason is an impossible native state;
            # the adapter must fail closed instead of trusting it.
            return ("allow", "exact", True, False, "no-match")

    monkeypatch.setattr(
        compiled_policy_evaluator_module, "native_compile_policy", lambda sets: IncoherentOpaque()
    )
    compiled = _compile((_one_set_role(("set", "*")),))
    with pytest.raises(PermissionEvaluationInfrastructureError):
        compiled.evaluate(make_action(verb="set", qualifier="active"))


# --- Benchmark smoke + JSON output --------------------------------------------


def test_benchmark_smoke_and_json_output() -> None:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(REPO_ROOT / "benchmarks"), env.get("PYTHONPATH", "")])
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, prefix="mtmf-compiled-bench-"
    ) as handle:
        json_path = handle.name
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(BENCHMARK_SCRIPT),
                "--smoke",
                "--json",
                json_path,
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            env=env,
            timeout=600,
        )
        assert result.returncode == 0, result.stderr
        assert "smoke mode: JSON output validated" in result.stdout
        with open(json_path, encoding="utf-8") as handle:
            payload = json.load(handle)
    finally:
        os.unlink(json_path)

    assert set(payload) == {"environment", "scenarios"}, sorted(payload)
    assert len(payload["scenarios"]) >= 1
    required_columns = {
        "scenario",
        "permission_count",
        "permission_set_count",
        "python_eval_median_ns",
        "current_rust_eval_median_ns",
        "compiled_eval_median_ns",
        "compile_median_ns",
        "compile_plus_1_median_ns",
        "compile_plus_10_median_ns",
        "compile_plus_100_median_ns",
        "compile_plus_1000_median_ns",
        "compiled_vs_python_ratio",
        "compiled_vs_current_rust_ratio",
        "break_even_vs_python",
        "break_even_vs_current_rust",
    }
    for scenario in payload["scenarios"]:
        assert required_columns <= set(scenario), sorted(required_columns - set(scenario))
    assert payload["environment"]["rust_engine_version"]


def test_native_compiled_capability_present() -> None:
    # The native module exposes the experimental compiled-policy bridge
    # (guarded by importorskip above), and empty policy is valid.
    opaque = native.compile_policy([])
    result = opaque.evaluate("urn:mtmf:iam:actions:system:principal:set-active")
    assert result == ("deny", None, False, False, "no-match")
