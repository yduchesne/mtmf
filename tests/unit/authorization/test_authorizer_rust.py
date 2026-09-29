"""PR 8D Authorizer cutover tests.

After PR 8D the normally constructed ``Authorizer()`` uses the
Rust-backed :class:`RustPermissionEvaluator` as the active/default
policy engine, while the Python reference
:class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
remains explicitly injectable.

Coverage:

- CUTOVER: the default evaluator is the Rust-backed implementation and
  the classification of policy ALLOW/DENY is unchanged.
- CONSTRAINTS: matching ALLOW still proceeds to later Authorizer
  constraints; Tenant/session/dominance behavior is unchanged.
- FAIL-CLOSED: a native unavailability/capability failure is not a
  semantic DENY, never becomes ALLOW, propagates as
  :class:`PermissionEvaluationInfrastructureError`, and has no Python
  fallback.

The actual native path requires the canonical ``./build.sh --rust``
build; the module skips when the native module is absent. Native
failures are exercised through the real evaluator seam (the internal
adapter), never by monkeypatching Authorizer internals. No
PostgreSQL/Podman/network service is used.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
from authz_helpers import (
    build_authorization_request,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)

from mtmf_core import (
    Authorizer,
    DenyReason,
    DominanceRequirement,
    PermissionEffect,
    PermissionEvaluator,
    SecurityScope,
)
from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError
from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEngineUnavailableError,
)
from mtmf_core.authorization.rust_permission_evaluator import (
    PermissionEvaluationInfrastructureError,
    RustPermissionEvaluator,
)

NATIVE_MODULE = "_mtmf_permission_engine"

pytest.importorskip(NATIVE_MODULE)

import mtmf_core.authorization.rust_permission_evaluator as evaluator_module  # noqa: E402


def _system_role(
    *,
    rules: tuple[tuple[str, str], ...] = (("set", "*"),),
    effect: PermissionEffect = PermissionEffect.ALLOW,
    role_urn: object | None = None,
) -> object:
    urn = role_urn if role_urn is not None else make_role_urn()
    return make_role_from_sets(
        role_urn=urn,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, effect=effect, rules=rules),),
    )


# --- CUTOVER: default evaluator is Rust-backed -------------------------------


def test_authorizer_defaults_to_the_rust_backed_evaluator() -> None:
    assert isinstance(Authorizer()._evaluator, RustPermissionEvaluator)


def test_authorizer_with_python_reference_injection_still_works() -> None:
    authorizer = Authorizer(evaluator=PermissionEvaluator())
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = authorizer.authorize(request)
    assert decision.allowed
    assert decision.reason is None


def test_authorizer_rust_path_matches_python_reference_input_for_allow() -> None:
    authorizer = Authorizer()
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = authorizer.authorize(request)
    assert decision.allowed
    assert decision.matched_specificity.name == "QUALIFIER_WILDCARD"


def test_authorizer_rust_path_semantic_deny_is_a_normal_decision() -> None:
    authorizer = Authorizer()
    request = build_authorization_request(
        roles=(_system_role(effect=PermissionEffect.DENY),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = authorizer.authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_authorizer_rust_path_no_match_is_normal_decision() -> None:
    authorizer = Authorizer()
    request = build_authorization_request(action=make_action(verb="set", qualifier="active"))
    decision = authorizer.authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


def test_authorizer_structural_corruption_still_fails_closed() -> None:
    authorizer = Authorizer()
    from authz_helpers import corrupt_role

    role_urn = make_role_urn(role_name="target")
    foreign_set = make_permission_set_with_rules(
        role_urn=make_role_urn(role_name="other"), rules=(("set", "*"),)
    )
    request = build_authorization_request(
        roles=(corrupt_role(role_urn, (foreign_set,)),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(PermissionEvaluationError):
        authorizer.authorize(request)


# --- CONSTRAINTS: later Authorizer logic unchanged ---------------------------


def test_matching_allow_still_proceeds_to_dominance_constraint() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.SYSTEM,
        target_scope=SecurityScope.TENANT,
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed


def test_matching_allow_insufficient_dominance_is_still_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.TENANT,
        target_scope=SecurityScope.TENANT,
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INSUFFICIENT_DOMINANCE


def test_tenant_isolation_is_unchanged_with_the_rust_default() -> None:
    from helpers import make_id

    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        target_tenant_id=make_id(),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.TENANT_MISMATCH


# --- FAIL-CLOSED: native failure is not policy DENY, no fallback --------------


def _force_native_failure(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    def failing(*args: object, **kwargs: object) -> object:
        raise exc

    monkeypatch.setattr(evaluator_module, "native_evaluate", failing)


def test_native_unavailable_propagates_and_is_not_semantic_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_native_failure(monkeypatch, RustEngineUnavailableError("native module unavailable"))
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(PermissionEvaluationInfrastructureError) as raised:
        Authorizer().authorize(request)
    assert isinstance(raised.value.__cause__, RustEngineUnavailableError)


def test_native_capability_failure_propagates_and_is_not_semantic_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_native_failure(monkeypatch, RustEngineCapabilityError("missing native evaluator"))
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(PermissionEvaluationInfrastructureError) as raised:
        Authorizer().authorize(request)
    assert isinstance(raised.value.__cause__, RustEngineCapabilityError)


def test_native_failure_never_becomes_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_native_failure(monkeypatch, RustEngineUnavailableError("native module unavailable"))
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(PermissionEvaluationInfrastructureError):
        Authorizer().authorize(request)


def test_malformed_native_response_propagates_and_never_becomes_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_native_failure(
        monkeypatch,
        RustEngineCapabilityError("native module returned a malformed evaluation response"),
    )
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    # A malformed native response is an evaluation failure, never a
    # semantic DENY (no NO_MATCH substitution) and never an ALLOW.
    with pytest.raises(PermissionEvaluationInfrastructureError):
        Authorizer().authorize(request)


def test_no_silent_python_fallback_on_native_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The Authorizer must not fall back to the Python reference: the
    # failure propagates and no ALLOW (or semantic DENY) decision exists.
    _force_native_failure(monkeypatch, RustEngineUnavailableError("native module unavailable"))
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(PermissionEvaluationInfrastructureError):
        Authorizer().authorize(request)


# --- PRIVACY: lazy native loading and adapter-only reachability -------------


def test_importing_rust_evaluator_does_not_eagerly_load_native_module() -> None:
    code = (
        "import sys\n"
        "from mtmf_core.authorization.rust_permission_evaluator import RustPermissionEvaluator\n"
        f"sys.exit(1 if {NATIVE_MODULE!r} in sys.modules else 0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_python_reference_evaluator_does_not_import_native_module() -> None:
    code = (
        "import sys\n"
        "from mtmf_core import PermissionEvaluator\n"
        "from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError\n"
        f"sys.exit(1 if {NATIVE_MODULE!r} in sys.modules else 0)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_rust_backed_evaluator_imports_adapter_not_extension_directly() -> None:
    import inspect

    import mtmf_core.authorization.rust_permission_evaluator as module

    source = inspect.getsource(module)
    assert "_mtmf_permission_engine" not in source
    assert "native_evaluate" in source
    assert "rust_engine" in source


def test_native_failure_message_does_not_claim_policy_deny(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _force_native_failure(monkeypatch, RustEngineUnavailableError("native module unavailable"))
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(PermissionEvaluationInfrastructureError) as raised:
        Authorizer().authorize(request)
    assert "DENY" not in str(raised.value)
