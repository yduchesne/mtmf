"""Native Rust batch authorization tests (PR 16, real installed wheel).

These tests require the canonical ``./build.sh --rust`` native build and
skip when the private ``_mtmf_permission_engine`` module (including the
PR 16 ``batch_evaluate`` capability) is absent. They provide positive
native-feature evidence:

- the real native ``batch_evaluate`` capability is installed and usable;
- a 100-Action eligible batch crosses the PyO3 boundary exactly once
  (instrumented through the real installed module, never a substituted
  mock engine);
- all pre-denied batches cross the native boundary zero times;
- a malformed middle Action fails the whole native batch;
- malformed native effects/URNs are errors, never DECY/NO_MATCH;
- full final-decision parity of the single :class:`Authorizer`, the
  Python :class:`BatchAuthorizer`, and the native
  :class:`RustBatchAuthorizer`;
- full policy-decision parity of the linear Python oracle, the indexed
  Python :class:`CompiledPolicy`, and the native compiled evaluator.

The native engine is never substituted for positive evidence; the
Python-level counter only wraps the real installed module's callable to
count PyO3 crossings.
"""

from __future__ import annotations

import importlib

import pytest
from authz_helpers import (
    build_request_from_context,
    make_action,
    make_authorization_context,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)

from compiled_policy_evaluator import CompiledPolicyEvaluator
from mtmf_core import (
    AuthorizationBatch,
    AuthorizationDecision,
    Authorizer,
    BatchAuthorizer,
    CompiledPolicy,
    DenyReason,
    DominanceRequirement,
    PermissionEffect,
    PermissionEvaluator,
    Role,
    RoleUrn,
    RustBatchAuthorizer,
    SecurityScope,
    UnsupportedConstraint,
)
from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError
from mtmf_core.authorization.rust_permission_evaluator import (
    PermissionEvaluationInfrastructureError,
    flatten_roles_to_primitive_sets,
)

NATIVE_MODULE = "_mtmf_permission_engine"

native = pytest.importorskip(NATIVE_MODULE)
compiled_policy_evaluator = pytest.importorskip("compiled_policy_evaluator")


class _CountingNativeModule:
    """Wrap the real installed native module to count PyO3 crossings.

    Every wrapped callable delegates to the real installed native
    function; only the invocation count is added. No mock engine is
    substituted.
    """

    def __init__(self, real: object) -> None:
        self._real = real
        self.batch_evaluate_calls = 0
        self.evaluate_calls = 0
        self.compile_policy_calls = 0

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)

    def batch_evaluate(self, *args: object, **kwargs: object) -> object:
        self.batch_evaluate_calls += 1
        return self._real.batch_evaluate(*args, **kwargs)  # type: ignore[attr-defined]

    def evaluate(self, *args: object, **kwargs: object) -> object:
        self.evaluate_calls += 1
        return self._real.evaluate(*args, **kwargs)  # type: ignore[attr-defined]

    def compile_policy(self, *args: object, **kwargs: object) -> object:
        self.compile_policy_calls += 1
        return self._real.compile_policy(*args, **kwargs)  # type: ignore[attr-defined]


def _install_counter(monkeypatch: pytest.MonkeyPatch) -> _CountingNativeModule:
    import mtmf_core.authorization.rust_engine as rust_engine

    real = importlib.import_module(NATIVE_MODULE)
    counting = _CountingNativeModule(real)
    monkeypatch.setattr(rust_engine, "_load_native_module", lambda: counting)
    return counting


def _role(
    *,
    effect: PermissionEffect = PermissionEffect.ALLOW,
    rules: tuple[tuple[str, str], ...] = (("set", "*"),),
    role_urn: RoleUrn | None = None,
) -> Role:
    urn = role_urn if role_urn is not None else make_role_urn()
    return make_role_from_sets(
        role_urn=urn,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, effect=effect, rules=rules),),
    )


# --- B28/B29: crossing counts on the real installed module -------------------


def test_b28_one_hundred_eligible_actions_cross_native_boundary_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counting = _install_counter(monkeypatch)
    context = make_authorization_context(roles=(_role(rules=(("set", "*"),)),))
    requests = tuple(
        build_request_from_context(context, action=make_action(verb="set", qualifier=f"q{index}"))
        for index in range(100)
    )
    result = RustBatchAuthorizer().authorize(AuthorizationBatch(requests))
    assert len(result.decisions) == 100
    # Exactly one native batch crossing; no per-Action native evaluation
    # and no separate native compilation crossing.
    assert counting.batch_evaluate_calls == 1
    assert counting.evaluate_calls == 0
    assert counting.compile_policy_calls == 0
    assert all(decision.allowed for decision in result.decisions)


def test_b29_all_pre_denied_crosses_native_boundary_zero_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    counting = _install_counter(monkeypatch)
    from helpers import make_tenant

    tenant = make_tenant("A")
    target = make_tenant("B")
    context = make_authorization_context(tenant=tenant, roles=(_role(rules=(("set", "*"),)),))
    requests = tuple(
        build_request_from_context(
            context, action=make_action(verb="set", qualifier="active"), target_tenant_id=target.id
        )
        for _ in range(10)
    )
    result = RustBatchAuthorizer().authorize(AuthorizationBatch(requests))
    assert counting.batch_evaluate_calls == 0
    assert counting.evaluate_calls == 0
    assert counting.compile_policy_calls == 0
    assert all(
        decision == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)
        for decision in result.decisions
    )


# --- B27/B34: malformed native input is an error, never a decision -----------


def test_b27_malformed_middle_action_fails_whole_native_call() -> None:
    primitive_sets = [("allow", ["urn:mtmf:iam:permissions:system:principal:set-*"])]
    actions = [
        "urn:mtmf:iam:actions:system:principal:set-active",
        "urn:mtmf:iam:actions:system:principal:set-alias",
        "not-a-urn",
        "urn:mtmf:iam:actions:system:principal:set-active",
    ]
    with pytest.raises(ValueError):
        native.batch_evaluate(primitive_sets, actions)


def test_b34_malformed_native_effects_and_urns_are_errors() -> None:
    with pytest.raises(ValueError):
        native.batch_evaluate(
            [("sometimes", [])], ["urn:mtmf:iam:actions:system:principal:set-active"]
        )
    with pytest.raises(ValueError):
        native.batch_evaluate(
            [("allow", ["not-a-urn"])],
            ["urn:mtmf:iam:actions:system:principal:set-active"],
        )
    # A wildcard in an Action URN is malformed native input, not a DENY.
    with pytest.raises(ValueError):
        native.batch_evaluate(
            [("allow", ["urn:mtmf:iam:permissions:system:principal:set-*"])],
            ["urn:mtmf:iam:actions:system:principal:set-*"],
        )
    # Out-of-range native input is rejected.
    with pytest.raises(ValueError):
        native.batch_evaluate([("allow", [])], [])
    with pytest.raises(ValueError):
        native.batch_evaluate(
            [("allow", [])],
            ["urn:mtmf:iam:actions:system:principal:set-active"] * 101,
        )


def test_compiled_object_batch_capability_is_present() -> None:
    compiled = native.compile_policy(
        [("allow", ["urn:mtmf:iam:permissions:system:principal:set-*"])]
    )
    results = compiled.evaluate_batch(
        [
            "urn:mtmf:iam:actions:system:principal:set-active",
            "urn:mtmf:iam:actions:system:principal:get-object",
        ]
    )
    assert results == [
        ("allow", "qualifier-wildcard", True, False, None),
        ("deny", None, False, False, "no-match"),
    ]


# --- B32: full final-decision parity -----------------------------------------


def _rich_requests() -> tuple[object, ...]:
    """Build a shared-context batch exercising every final-decision path."""
    allow_role = _role(rules=(("set", "*"), ("get", "object")))
    deny_role = _role(effect=PermissionEffect.DENY, rules=(("set", "active"),))
    other_role = _role(rules=(("delete", "object"),), role_urn=make_role_urn(role_name="deleter"))
    context = make_authorization_context(roles=(allow_role, deny_role, other_role))
    from helpers import make_tenant

    foreign = make_tenant("Foreign")
    return (
        # Wildcard ALLOW.
        build_request_from_context(context, action=make_action(verb="set", qualifier="alias")),
        # Exact DENY wins over wildcard ALLOW.
        build_request_from_context(context, action=make_action(verb="set", qualifier="active")),
        # Explicit exact ALLOW.
        build_request_from_context(context, action=make_action(verb="get", qualifier="object")),
        # No match.
        build_request_from_context(context, action=make_action(verb="set", qualifier="missing")),
        # Another role's ALLOW.
        build_request_from_context(context, action=make_action(verb="delete", qualifier="object")),
        # Duplicate occurrence.
        build_request_from_context(context, action=make_action(verb="set", qualifier="active")),
        # Cross-Tenant pre-denied (no management scope).
        build_request_from_context(
            context, action=make_action(verb="set", qualifier="alias"), target_tenant_id=foreign.id
        ),
        # Post-policy unsupported constraint.
        build_request_from_context(
            context,
            action=make_action(verb="set", qualifier="alias"),
            unsupported_constraints=(UnsupportedConstraint.ALTERNATE_DOMINANCE,),
        ),
        # Strict dominance retained ALLOW.
        build_request_from_context(
            context,
            action=make_action(verb="set", qualifier="alias"),
            dominance_requirement=DominanceRequirement.STRICT,
            subject_scope=SecurityScope.ROOT,
            target_scope=SecurityScope.TENANT,
        ),
        # Strict dominance insufficient.
        build_request_from_context(
            context,
            action=make_action(verb="set", qualifier="alias"),
            dominance_requirement=DominanceRequirement.STRICT,
            subject_scope=SecurityScope.ORGANIZATION,
            target_scope=SecurityScope.TENANT,
        ),
        # Post-constraint after a policy DENY keeps the original DENY.
        build_request_from_context(
            context,
            action=make_action(verb="set", qualifier="active"),
            unsupported_constraints=(UnsupportedConstraint.ALTERNATE_DOMINANCE,),
        ),
        build_request_from_context(context, action=make_action(verb="set", qualifier="alias")),
    )


def _management_role() -> Role:
    from helpers import make_id, make_permission

    urn = RoleUrn("urn:mtmf:iam:roles:system:tenant-management")
    set_id = make_id()
    permission = make_permission(
        permission_set_id=set_id, resource="tenant", verb="get", qualifier="object"
    )
    from mtmf_core import PermissionSet

    return Role(
        urn,
        "Tenant Management",
        "",
        None,
        (PermissionSet(set_id, urn, PermissionEffect.ALLOW, (permission,)),),
    )


def test_b10_native_eligible_management_parity() -> None:
    from helpers import make_id, make_tenant

    from mtmf_core import ManagementScopeCandidate, ManagementScopeResolution, TenantManagementScope

    manager = make_tenant("Manager")
    target = make_tenant("Target")
    role = _management_role()
    context = make_authorization_context(tenant=manager, roles=(role,))
    resolution = ManagementScopeResolution(
        candidate=ManagementScopeCandidate(
            management_group_id=make_id(),
            scope=TenantManagementScope.SYSTEM,
            management_role_urn=RoleUrn("urn:mtmf:iam:roles:system:tenant-management"),
        ),
        actor_eligible=True,
        blocked_reason=None,
    )
    request = build_request_from_context(
        context,
        action=make_action(resource="tenant", verb="get", qualifier="object"),
        target_tenant_id=target.id,
        management_scope=resolution,
    )
    batch = AuthorizationBatch((request,))
    python_result = BatchAuthorizer().authorize(batch).decisions[0]
    rust_result = RustBatchAuthorizer().authorize(batch).decisions[0]
    single = Authorizer().authorize(request)
    assert single.allowed
    assert python_result == single
    assert rust_result == single


def test_b32_single_authorizer_and_both_batches_full_parity() -> None:
    requests = _rich_requests()
    batch = AuthorizationBatch(requests)  # type: ignore[arg-type]
    python_result = BatchAuthorizer().authorize(batch)
    rust_result = RustBatchAuthorizer().authorize(batch)
    authorizer = Authorizer()
    expected = tuple(authorizer.authorize(request) for request in requests)  # type: ignore[arg-type]
    assert python_result.decisions == expected
    assert rust_result.decisions == expected
    assert len(rust_result.decisions) == len(requests)


# --- B31: policy-only parity (linear Python / indexed Python / native) --------


def test_b31_policy_only_parity_across_python_and_native() -> None:
    roles = (
        _role(rules=(("set", "*"),)),
        _role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),
        _role(rules=(("get", "object"), ("set", "active"))),
    )
    actions = (
        make_action(verb="set", qualifier="active"),
        make_action(verb="set", qualifier="alias"),
        make_action(verb="get", qualifier="object"),
        make_action(verb="set", qualifier="absent"),
    )
    linear = PermissionEvaluator()
    indexed_python = CompiledPolicy.compile(roles)
    indexed_native = CompiledPolicyEvaluator.compile(roles)
    for action in actions:
        expected = linear.evaluate(action, roles)
        assert indexed_python.evaluate(action) == expected
        assert indexed_native.evaluate(action) == expected


# --- corrupt ownership fails before native -----------------------------------


def test_corrupt_ownership_fails_before_native_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from authz_helpers import corrupt_role

    counting = _install_counter(monkeypatch)
    urn = make_role_urn()
    other_urn = make_role_urn(role_name="other")
    permission_set = make_permission_set_with_rules(role_urn=other_urn, rules=(("set", "*"),))
    corrupt = corrupt_role(urn, (permission_set,))
    context = make_authorization_context(roles=(corrupt,))
    request = build_request_from_context(context)
    with pytest.raises(PermissionEvaluationError):
        RustBatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert counting.batch_evaluate_calls == 0


def test_flatten_helper_rejects_corrupt_ownership() -> None:
    from authz_helpers import corrupt_role

    urn = make_role_urn()
    other_urn = make_role_urn(role_name="other")
    permission_set = make_permission_set_with_rules(role_urn=other_urn, rules=(("set", "*"),))
    corrupt = corrupt_role(urn, (permission_set,))
    with pytest.raises(PermissionEvaluationError):
        flatten_roles_to_primitive_sets((corrupt,))


def test_native_capability_error_propagates_as_infrastructure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mtmf_core.authorization.rust_engine as rust_engine

    class _IncapableModule:
        def __getattr__(self, name: str) -> object:
            raise AttributeError(name)

    monkeypatch.setattr(rust_engine, "_load_native_module", lambda: _IncapableModule())
    context = make_authorization_context(roles=(_role(rules=(("set", "*"),)),))
    request = build_request_from_context(
        context, action=make_action(verb="set", qualifier="active")
    )
    with pytest.raises(PermissionEvaluationInfrastructureError):
        RustBatchAuthorizer().authorize(AuthorizationBatch((request,)))
