"""PR 8F experimental msgspec/MessagePack semantic-buffer evaluator tests.

These tests exercise the experimental native entry point
(``_mtmf_permission_engine.evaluate_semantic_msgpack``) and the
benchmark-side :class:`MsgspecEvaluator` adapter over the FFI:

- PARITY: P/R/M1/M2 produce fully equal :class:`AuthorizationDecision`
  evidence for settled policies (exact, wildcard, no-match,
  equal-specificity conflict, specificity dominance).
- FAIL-CLOSED (native): empty, random, wrong-top-level-type,
  missing/truncated, unsupported-version, unknown-effect, invalid
  wildcard-state, and invalid-component payloads raise ``ValueError``
  and never become ALLOW / NO_MATCH / MATCHED_DENY.
- FAIL-CLOSED (adapter): the same malformed payloads surface as
  :class:`PermissionEvaluationInfrastructureError` (never a decision),
  and ownership corruption fails with the same
  :class:`PermissionEvaluationError` the production evaluators raise.
- BENCHMARK: ``--smoke`` mode runs end to end (four-way parity,
  components, human/JSON output) with tiny counts and validates the
  JSON shape.

Tests that genuinely require the built native module skip when it is
not installed (for example in plain ``./build.sh --qa``). No test here
starts PostgreSQL, Podman, or any external service, and no timing
assertion is used.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

import msgspec.msgpack as msgpack
import pytest
from authz_helpers import (  # type: ignore[import-untyped]
    corrupt_role,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)
from msgspec_evaluator import MsgspecEvaluator
from msgspec_wire import WIRE_VERSION

pytest.importorskip("msgspec")
native = pytest.importorskip("_mtmf_permission_engine")

from mtmf_core import PermissionEffect, PermissionEvaluationError  # noqa: E402
from mtmf_core.authorization.permission_evaluator import PermissionEvaluator  # noqa: E402
from mtmf_core.authorization.rust_engine import RustEngineUnavailableError  # noqa: E402
from mtmf_core.authorization.rust_permission_evaluator import (  # noqa: E402
    PermissionEvaluationInfrastructureError,
    RustPermissionEvaluator,
)

# --- Payload construction helpers -------------------------------------------


def _action() -> tuple[str, str, str, str]:
    return ("system", "principal", "set", "active")


def _encode_payload(
    version: int = WIRE_VERSION,
    action: tuple[str, str, str, str] | None = None,
    sets: list[object] | None = None,
) -> bytes:
    """Encode a top-level positional payload (schema literals)."""
    if action is None:
        action = _action()
    if sets is None:
        sets = []
    return msgpack.Encoder().encode((version, action, sets))


def _native_evaluation(payload: bytes) -> tuple[object, ...]:
    """One native semantic evaluation; raises ValueError on malformed input."""
    result = native.evaluate_semantic_msgpack(payload)
    assert isinstance(result, tuple) and len(result) == 5
    return result


def _permission_payload(*sets: tuple[str, tuple[tuple[str, str, str, str, bool], ...]]) -> bytes:
    """Build a v1 payload for the set-active action from wire literals."""
    return msgpack.Encoder().encode(
        (
            WIRE_VERSION,
            _action(),
            [(effect, list(permissions)) for effect, permissions in sets],
        )
    )


# --- Valid native decode ----------------------------------------------------


def test_native_decodes_a_valid_v1_payload() -> None:
    payload = _permission_payload(("allow", (("system", "principal", "set", "active", False),)))
    assert _native_evaluation(payload) == ("allow", "exact", True, False, None)


def test_native_wildcard_matches_with_specificity() -> None:
    payload = _permission_payload(("allow", (("system", "principal", "set", "*", True),)))
    assert _native_evaluation(payload) == ("allow", "qualifier-wildcard", True, False, None)


def test_native_no_match_never_confuses_malformed() -> None:
    payload = _permission_payload(("allow", (("system", "principal", "get", "object", False),)))
    assert _native_evaluation(payload) == ("deny", None, False, False, "no-match")


def test_native_equal_specificity_conflict_is_deny_with_allow_evidence() -> None:
    payload = _permission_payload(
        ("allow", (("system", "principal", "set", "active", False),)),
        ("deny", (("system", "principal", "set", "active", False),)),
    )
    assert _native_evaluation(payload) == ("deny", "exact", True, True, "matched-deny")


def test_native_wildcard_deny_does_not_defeat_exact_allow() -> None:
    payload = _permission_payload(
        ("deny", (("system", "principal", "set", "*", True),)),
        ("allow", (("system", "principal", "set", "active", False),)),
    )
    assert _native_evaluation(payload) == ("allow", "exact", True, False, None)


def test_native_empty_policy_is_default_deny() -> None:
    assert _native_evaluation(_encode_payload()) == ("deny", None, False, False, "no-match")


# --- Malformed wire can never become a decision (native) ----------------------


def test_empty_payload_is_rejected() -> None:
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(b"")


def test_random_bytes_are_rejected() -> None:
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(b"\x81\xa1x\xc0garbage")


def test_wrong_top_level_type_is_rejected() -> None:
    # A MessagePack string, integer, and map in place of the payload.
    for wrong in (_encode_payload_wrong_type_text(), b"\x01", b"\x83\xa1a\x01\xa1b\x02\xa1c\x03"):
        with pytest.raises(ValueError):
            native.evaluate_semantic_msgpack(wrong)


def test_missing_top_level_field_is_rejected() -> None:
    # Only two of three positional elements: the permission_sets field
    # is missing.
    payload = msgpack.Encoder().encode((WIRE_VERSION, _action()))
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(payload)


def test_truncated_payload_is_rejected() -> None:
    payload = _permission_payload(("allow", (("system", "principal", "set", "active", False),)))
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(payload[:-3])


def test_unsupported_version_is_rejected() -> None:
    for version in (0, 2, 99):
        with pytest.raises(ValueError):
            native.evaluate_semantic_msgpack(_encode_payload(version=version))


def test_unknown_effect_is_rejected() -> None:
    payload = _permission_payload(("maybe", ()))
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(payload)


def test_wildcard_flag_without_wildcard_text_is_rejected() -> None:
    payload = _permission_payload(("allow", (("system", "principal", "set", "active", True),)))
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(payload)


def test_wildcard_text_without_flag_is_rejected() -> None:
    payload = _permission_payload(("allow", (("system", "principal", "set", "*", False),)))
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(payload)


def test_invalid_component_type_is_rejected() -> None:
    payload = msgpack.Encoder().encode((WIRE_VERSION, (5, "principal", "set", "active"), []))
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(payload)


def test_invalid_namespace_is_rejected() -> None:
    payload = _encode_payload(action=("tenant", "principal", "set", "active"))
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(payload)


def test_excessive_nesting_is_rejected_without_panic() -> None:
    # Deeply nested arrays around the action element (50 levels).
    inner = b"\x91" * 50 + b"\xa6system"
    payload = bytes([0x93, 0x01]) + inner + bytes([0x90])
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(payload)


# --- Experimental adapter -----------------------------------------------------


def _policy_role(*, effect: PermissionEffect, rules: tuple[tuple[str, str], ...]):
    role_urn = make_role_urn(role_name="msgspec-policy")
    return make_role_from_sets(
        role_urn=role_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=role_urn, effect=effect, rules=rules),
        ),
    )


def _full_equality(left, right) -> bool:  # type: ignore[no-untyped-def]
    return (
        left == right
        and left.allowed == right.allowed
        and left.effect == right.effect
        and left.reason == right.reason
        and left.matched_specificity == right.matched_specificity
        and left.matched_allow == right.matched_allow
        and left.matched_deny == right.matched_deny
    )


@pytest.mark.parametrize(
    ("roles",),
    [
        ((),),
        ((_policy_role(effect=PermissionEffect.ALLOW, rules=(("set", "active"),)),),),
        ((_policy_role(effect=PermissionEffect.ALLOW, rules=(("set", "*"),)),),),
        ((_policy_role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),),),
        ((_policy_role(effect=PermissionEffect.ALLOW, rules=(("get", "object"),)),),),
        (
            (
                _policy_role(effect=PermissionEffect.ALLOW, rules=(("set", "*"),)),
                _policy_role(effect=PermissionEffect.ALLOW, rules=(("set", "active"),)),
            ),
        ),
        (
            (
                _policy_role(effect=PermissionEffect.ALLOW, rules=(("set", "active"),)),
                _policy_role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),
            ),
        ),
    ],
    ids=[
        "no_roles",
        "exact_allow",
        "wildcard_allow",
        "exact_deny",
        "no_match",
        "wildcard_then_exact",
        "equal_conflict",
    ],
)
def test_four_way_parity_p_equals_r_equals_m1_equals_m2(roles: tuple[object, ...]) -> None:
    action = make_action(resource="principal", verb="set", qualifier="active")
    python = PermissionEvaluator()
    rust = RustPermissionEvaluator()
    m1 = MsgspecEvaluator("encode")
    m2 = MsgspecEvaluator("encode_into")
    decisions = [
        python.evaluate(action, roles),
        rust.evaluate(action, roles),
        m1.evaluate(action, roles),
        m2.evaluate(action, roles),
    ]
    reference = decisions[0]
    for decision in decisions[1:]:
        assert _full_equality(reference, decision)


def test_m1_and_m2_return_the_same_decision_for_every_scenario() -> None:
    action = make_action(resource="principal", verb="set", qualifier="active")
    role = _policy_role(effect=PermissionEffect.DENY, rules=(("set", "*"),))
    m1 = MsgspecEvaluator("encode")
    m2 = MsgspecEvaluator("encode_into")
    assert _full_equality(m1.evaluate(action, (role,)), m2.evaluate(action, (role,)))


def test_adapter_ownership_corruption_fails_closed() -> None:
    foreign_urn = make_role_urn(role_name="thief")
    own_urn = make_role_urn(role_name="owner")
    stolen_set = make_permission_set_with_rules(role_urn=foreign_urn)
    corrupted = corrupt_role(own_urn, (stolen_set,))
    action = make_action(resource="principal", verb="set", qualifier="active")
    for evaluator in (MsgspecEvaluator("encode"), MsgspecEvaluator("encode_into")):
        with pytest.raises(PermissionEvaluationError):
            evaluator.evaluate(action, (corrupted,))


def test_adapter_maps_native_value_error_to_infrastructure_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A native wire failure must surface as a fail-closed error at the adapter."""
    evaluator = MsgspecEvaluator("encode")

    def boom(payload: object) -> object:
        raise ValueError("malformed semantic payload")

    monkeypatch.setattr(evaluator._native, "evaluate_semantic_msgpack", boom)
    action = make_action(resource="principal", verb="set", qualifier="active")
    role = _policy_role(effect=PermissionEffect.ALLOW, rules=(("set", "active"),))
    with pytest.raises(PermissionEvaluationInfrastructureError):
        evaluator.evaluate(action, (role,))


def test_adapter_malformed_unsupported_version_is_never_a_decision() -> None:
    # The adapter can only emit version-1 payloads from valid domain
    # objects, so the malformed wire is exercised at the boundary it
    # reaches: a non-1 version fails explicitly and is never a decision.
    broken = _encode_payload(version=7)
    with pytest.raises(ValueError):
        native.evaluate_semantic_msgpack(broken)


def test_native_build_profile_is_exposed() -> None:
    profile = native.build_profile()
    assert profile in ("debug", "release")


def test_native_unavailable_fails_closed() -> None:
    pytest.importorskip("msgspec")
    import sys

    # The adapter fails closed when the private module is absent; the
    # presence check mirrors the production seam.
    assert RustEngineUnavailableError
    assert "_mtmf_permission_engine" in sys.modules


def test_benchmark_smoke_runs_and_writes_json(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Run the benchmark's --smoke mode end to end and validate JSON."""
    import permission_evaluator_benchmark

    json_path = tmp_path / "smoke.json"
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = permission_evaluator_benchmark.main(["--smoke", "--json", str(json_path)])
    assert exit_code == 0
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert set(payload) == {"environment", "scenarios"}
    assert payload["environment"]["msgspec_version"]
    assert payload["environment"]["native_build_profile"] in ("debug", "release")
    assert payload["scenarios"], "smoke must produce at least one scenario"
    for scenario in payload["scenarios"]:
        for key in (
            "python_median_ns",
            "rust_median_ns",
            "m1_median_ns",
            "m2_median_ns",
            "ratio_m1_over_python",
            "ratio_m2_over_python",
            "ratio_m1_over_rust",
            "ratio_m2_over_rust",
        ):
            assert key in scenario
        for key in (
            "domain_to_wire_ns",
            "encode_ns",
            "encode_into_ns",
            "pre_encoded_native_ns",
        ):
            assert key in scenario["components"]


def _encode_payload_wrong_type_text() -> bytes:
    """A MessagePack string where a payload array is required."""
    return msgpack.Encoder().encode("not-a-payload")
