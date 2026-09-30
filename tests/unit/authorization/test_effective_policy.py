"""EffectivePolicy diagnostics-wrapper tests (PR 8H).

Prove that :class:`~mtmf_core.authorization.policy.EffectivePolicy`:

- satisfies the :class:`AuthorizationPolicy` protocol;
- delegates ``evaluate`` directly and unchanged to the nested policy;
- adds no authorization semantics (ALLOW/DENY returned unchanged);
- propagates nested exceptions;
- exposes context-aware diagnostics that include safe context identity
  and the nested diagnostics but never disclose policy internals;
- never lets diagnostics affect evaluation;
- exposes no retrieval/I/O surface.

All tests use stubs, never Rust and never the native module. No
PostgreSQL, Podman, network service, timing assertion, or randomness is
used.
"""

from __future__ import annotations

import pytest
from authz_helpers import build_authorization_request, make_action

from mtmf_core import (
    Action,
    AuthorizationDecision,
    AuthorizationPolicy,
    DenyReason,
    EffectivePolicy,
    MatchSpecificity,
)

EXACT_ALLOW = AuthorizationDecision.allow(
    matched_specificity=MatchSpecificity.EXACT, matched_allow=True, matched_deny=False
)
EXACT_DENY = AuthorizationDecision.deny(
    DenyReason.MATCHED_DENY,
    matched_specificity=MatchSpecificity.EXACT,
    matched_allow=False,
    matched_deny=True,
)


class _StubPolicy:
    """A stub nested policy recording evaluation and diagnostics calls."""

    def __init__(
        self,
        decision: AuthorizationDecision | None = None,
        *,
        raise_exc: Exception | None = None,
    ) -> None:
        self._decision = decision
        self._raise_exc = raise_exc
        self.evaluated: list[Action] = []
        self.diagnostics_calls = 0

    def evaluate(self, action: Action) -> AuthorizationDecision:
        self.evaluated.append(action)
        if self._raise_exc is not None:
            raise self._raise_exc
        if self._decision is not None:
            return self._decision
        return AuthorizationDecision.deny(DenyReason.NO_MATCH)

    def get_diagnostics(self) -> str:
        self.diagnostics_calls += 1
        return "NestedStub(keys=3)"


def _effective(
    decision: AuthorizationDecision | None = None,
) -> tuple[EffectivePolicy, _StubPolicy]:
    request = build_authorization_request(action=make_action(verb="set", qualifier="active"))
    policy = _StubPolicy(decision)
    return EffectivePolicy(policy, request.context), policy


# --- 1. Protocol compatibility -------------------------------------------------


def test_effective_policy_satisfies_the_authorization_policy_protocol() -> None:
    effective, _ = _effective()
    assert isinstance(effective, AuthorizationPolicy)
    assert callable(effective.evaluate)
    assert callable(effective.get_diagnostics)


# --- 2/3/4/5. Exact single delegation, decision unchanged ----------------------


def test_delegates_evaluation_exactly_once_to_nested_policy() -> None:
    effective, policy = _effective(EXACT_ALLOW)
    action = make_action(verb="set", qualifier="active")
    decision = effective.evaluate(action)
    assert decision == EXACT_ALLOW
    # The wrapper performs no extra evaluation work: the nested policy
    # saw exactly the one Action the caller supplied.
    assert policy.evaluated == [action]


def test_allow_is_returned_unchanged() -> None:
    effective, policy = _effective(EXACT_ALLOW)
    action = make_action(verb="set", qualifier="active")
    decision = effective.evaluate(action)
    assert decision == EXACT_ALLOW
    assert decision.allowed is True
    assert policy.evaluated == [action]


def test_deny_is_returned_unchanged() -> None:
    effective, _ = _effective(EXACT_DENY)
    decision = effective.evaluate(make_action(verb="set", qualifier="active"))
    assert decision == EXACT_DENY
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_deny is True


# --- 6. Nested exception propagation --------------------------------------------


def test_nested_exception_propagates() -> None:
    boom = RuntimeError("nested failure")
    request = build_authorization_request(action=make_action())
    effective = EffectivePolicy(_StubPolicy(raise_exc=boom), request.context)
    with pytest.raises(RuntimeError) as raised:
        effective.evaluate(make_action())
    assert raised.value is boom


# --- 7/8. Diagnostics -----------------------------------------------------------


def test_diagnostics_include_safe_context_identity() -> None:
    request = build_authorization_request(action=make_action(verb="set", qualifier="active"))
    effective = EffectivePolicy(_StubPolicy(), request.context)
    text = effective.get_diagnostics()
    assert str(request.context.tenant.id) in text
    assert str(request.context.principal.id) in text
    assert str(request.context.identity.id) in text
    assert "EffectivePolicy(" in text


def test_diagnostics_include_nested_policy_diagnostics() -> None:
    effective, policy = _effective()
    text = effective.get_diagnostics()
    assert policy.diagnostics_calls == 1
    assert "NestedStub(keys=3)" in text
    assert "NestedStub" in text


def test_diagnostics_do_not_disclose_policy_internals() -> None:
    from authz_helpers import make_permission_set_with_rules, make_role_from_sets, make_role_urn

    urn = make_role_urn(role_name="sensitive")
    role = make_role_from_sets(
        role_urn=urn,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, rules=(("set", "active"),)),),
    )
    request = build_authorization_request(roles=(role,))
    effective = EffectivePolicy(_StubPolicy(), request.context)
    text = effective.get_diagnostics()
    # Safe identity facts plus nested diagnostics only: never URNs,
    # Permission lists, extensions, credentials, or arbitrary reprs.
    assert "urn:mtmf" not in text
    assert "permission" not in text.lower()
    assert "secret" not in text.lower()
    assert "role_name" not in text


# --- 9. Diagnostics never affect evaluation -------------------------------------


def test_diagnostics_never_affect_evaluation() -> None:
    effective, policy = _effective(EXACT_ALLOW)
    action = make_action(verb="set", qualifier="active")
    before = policy.diagnostics_calls
    first = effective.evaluate(action)
    assert first == EXACT_ALLOW
    assert policy.diagnostics_calls == before
    text = effective.get_diagnostics()
    assert "NestedStub(keys=3)" in text
    assert policy.diagnostics_calls == before + 1
    second = effective.evaluate(action)
    assert second == EXACT_ALLOW
    assert policy.evaluated == [action, action]


# --- 10. No retrieval/I/O surface -----------------------------------------------


def test_no_retrieval_or_io_surface() -> None:
    effective, _ = _effective()
    for name in (
        "resolve",
        "repository",
        "spi",
        "session",
        "load",
        "refresh",
        "retrieve",
        "persist",
    ):
        assert not hasattr(effective, name)
    assert set(EffectivePolicy.__slots__) == {"_policy", "_context"}


def test_wrapping_does_not_mutate_the_context() -> None:
    request = build_authorization_request(action=make_action(verb="set", qualifier="active"))
    context = request.context
    effective = EffectivePolicy(_StubPolicy(EXACT_ALLOW), context)
    assert effective.get_diagnostics() == effective.get_diagnostics()
    assert effective.evaluate(make_action(verb="set", qualifier="active")) == EXACT_ALLOW
    assert request.context == context
