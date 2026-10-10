"""Rust evaluator status after the PR 8H default cutover.

PR 8H moves the default ``Authorizer()`` path to the pure-Python indexed
:class:`~mtmf_core.authorization.compiled_policy.CompiledPolicy`
resolved through
:class:`~mtmf_core.authorization.policy_resolver.DefaultAuthorizationPolicyResolver`
and wrapped in an
:class:`~mtmf_core.authorization.policy.EffectivePolicy`. The Rust-backed
:class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`
is retained for experimentation, differential testing, and Rust/Python
integration evidence; it is experimental, non-default, never a
fallback, and not required for normal production authorization.

This suite proves:

- the default Authorizer path never imports the native module;
- the default (Python compiled) decisions equal the Rust evaluator
  decisions for representative requests through the Authorizer;
- the linear Python oracle remains usable through the new resolver/policy
  seam for reference/comparison work;
- Rust kept behind an explicit test-only resolver adapter and its
  fail-closed native boundary propagate through the Authorizer as
  :class:`PermissionEvaluationInfrastructureError` and never become a
  semantic DENY or ALLOW, with no Python fallback;
- Authorizer constraint, Tenant, corruption, and lazy-loading behavior is
  unchanged.

The actual native path requires the canonical ``./build.sh --rust``
build; the module skips when the native module is absent. Native
failures are exercised through the real evaluator seam (the internal
adapter), never by monkeypatching Authorizer internals. No
PostgreSQL/Podman/network service is used.
"""

from __future__ import annotations

import importlib
import subprocess
import sys

import pytest
from authz_helpers import (
    build_authorization_request,
    corrupt_role,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)

from mtmf_core import (
    Action,
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationRequest,
    Authorizer,
    CompiledPolicy,
    DefaultAuthorizationPolicyResolver,
    DenyReason,
    DominanceRequirement,
    EffectivePolicy,
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


class _BoundPolicy:
    """Test-only AuthorizationPolicy adapter over an evaluator plus Roles.

    Binds a linear evaluator (Python reference or the experimental Rust
    evaluator) and the applicable Roles so it can be injected behind a
    stub resolver, keeping the PR 8H Authorizer seam
    (``resolver.resolve(context) -> policy.evaluate(action)``) while
    exercising the retained linear/reference path through the Authorizer.
    """

    def __init__(self, evaluator: object, roles: object) -> None:
        self._evaluator = evaluator
        self._roles = roles

    def evaluate(self, action: Action) -> AuthorizationDecision:
        return self._evaluator.evaluate(action, self._roles)  # type: ignore[attr-defined]

    def get_diagnostics(self) -> str:
        return f"{type(self._evaluator).__name__}Policy(experimental)"


class _BoundResolver:
    """Stub resolver returning a pre-bound policy for any context."""

    def __init__(self, policy: _BoundPolicy) -> None:
        self._policy = policy

    def resolve(self, context: AuthorizationContext) -> _BoundPolicy:
        return self._policy


def _rust_authorizer(request: AuthorizationRequest) -> Authorizer:
    """An Authorizer whose policy is backed by the experimental Rust evaluator."""
    return Authorizer(
        _BoundResolver(_BoundPolicy(RustPermissionEvaluator(), request.context.applicable_roles))
    )


def _python_authorizer(request: AuthorizationRequest) -> Authorizer:
    """An Authorizer whose policy is backed by the linear Python oracle."""
    return Authorizer(
        _BoundResolver(_BoundPolicy(PermissionEvaluator(), request.context.applicable_roles))
    )


# --- DEFAULT CUTOVER: the default path is Python CompiledPolicy -------------


def test_authorizer_defaults_to_the_default_python_policy_resolver() -> None:
    assert isinstance(Authorizer()._policy_resolver, DefaultAuthorizationPolicyResolver)
    context = build_authorization_request().context
    resolved = DefaultAuthorizationPolicyResolver().resolve(context)
    assert isinstance(resolved, EffectivePolicy)
    assert isinstance(resolved._policy, CompiledPolicy)
    assert not isinstance(resolved._policy, RustPermissionEvaluator)


def test_default_authorizer_path_never_imports_the_native_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    original_import_module = importlib.import_module

    def spy(name: str, *args: object, **kwargs: object) -> object:
        if name == NATIVE_MODULE:
            calls.append(name)
        return original_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", spy)
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed
    assert calls == []


def test_default_authorizer_decisions_equal_rust_evaluator_decisions() -> None:
    cases = (
        {
            "roles": (_system_role(),),
            "action": make_action(verb="set", qualifier="active"),
        },
        {
            "roles": (_system_role(effect=PermissionEffect.DENY),),
            "action": make_action(verb="set", qualifier="active"),
        },
        {"action": make_action(verb="set", qualifier="active")},
    )
    for kwargs in cases:
        request = build_authorization_request(**kwargs)
        default_decision = Authorizer().authorize(request)
        rust_decision = _rust_authorizer(request).authorize(request)
        assert rust_decision == default_decision, f"{kwargs!r}"
        assert rust_decision.allowed == default_decision.allowed
        assert rust_decision.reason == default_decision.reason
        assert rust_decision.matched_specificity == default_decision.matched_specificity
        assert rust_decision.matched_allow == default_decision.matched_allow
        assert rust_decision.matched_deny == default_decision.matched_deny


def test_authorizer_with_python_reference_policy_injection_still_works() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = _python_authorizer(request).authorize(request)
    assert decision.allowed
    assert decision.reason is None


def test_authorizer_structural_corruption_still_fails_closed() -> None:
    role_urn = make_role_urn(role_name="target")
    foreign_set = make_permission_set_with_rules(
        role_urn=make_role_urn(role_name="other"), rules=(("set", "*"),)
    )
    request = build_authorization_request(
        roles=(corrupt_role(role_urn, (foreign_set,)),),
        action=make_action(verb="set", qualifier="active"),
    )
    # Ownership corruption fails closed through the default (CompiledPolicy)
    # path and through the Rust-backed policy path alike.
    with pytest.raises(PermissionEvaluationError):
        Authorizer().authorize(request)
    with pytest.raises(PermissionEvaluationError):
        _rust_authorizer(request).authorize(request)


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


def test_tenant_isolation_is_unchanged_with_the_python_default() -> None:
    from helpers import make_id

    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        target_tenant_id=make_id(),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MANAGEMENT_SCOPE


# --- FAIL-CLOSED: native failure through the Rust path is not a policy DENY ---


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
        _rust_authorizer(request).authorize(request)
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
        _rust_authorizer(request).authorize(request)
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
        _rust_authorizer(request).authorize(request)


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
        _rust_authorizer(request).authorize(request)


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
        _rust_authorizer(request).authorize(request)


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
        _rust_authorizer(request).authorize(request)
    assert "DENY" not in str(raised.value)
