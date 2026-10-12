"""Ordered batch authorization tests (PR 16, Python default path).

Covers the deterministic acceptance matrix items that do not require the
installed native wheel: batch shape/validation, one shared session check
and one policy resolution, per-item target/management guards, full
policy and final-decision parity against the single
:class:`Authorizer`, unsupported-constraint and strict-dominance guards,
fail-closed resolver/ownership failures, no cross-batch leakage, and no
native module load for the default import.

The native batch path (one PyO3 invocation, native parity, malformed
native input) is covered by ``test_rust_batch_authorizer.py``.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
from authz_helpers import (
    build_request_from_context,
    corrupt_role,
    make_action,
    make_authorization_context,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)
from helpers import make_id, make_identity, make_principal, make_tenant

from mtmf_core import (
    SYSTEM_MANAGEMENT_ROLE_URN,
    Action,
    AuthorizationBatch,
    AuthorizationContext,
    AuthorizationDecision,
    AuthorizationEffect,
    AuthorizationPolicy,
    AuthorizationRequest,
    Authorizer,
    BatchAuthorizer,
    DenyReason,
    DominanceRequirement,
    InvalidAuthorizationBatchError,
    ManagementScopeCandidate,
    ManagementScopeResolution,
    MatchSpecificity,
    PermissionEffect,
    PermissionEvaluationError,
    PermissionSet,
    Role,
    RoleUrn,
    RustBatchAuthorizer,
    SecurityScope,
    TenantManagementScope,
    UnsupportedConstraint,
)


class _StubPolicy:
    """A recording/injectable AuthorizationPolicy."""

    def __init__(self, decision: AuthorizationDecision) -> None:
        self._decision = decision
        self.evaluated: list[Action] = []

    def evaluate(self, action: Action) -> AuthorizationDecision:
        self.evaluated.append(action)
        return self._decision

    def get_diagnostics(self) -> str:
        return "StubPolicy()"


class _CountingResolver:
    """A resolver that records how many times (and for which contexts) it resolved."""

    def __init__(self, policy: AuthorizationPolicy) -> None:
        self._policy = policy
        self.resolve_calls = 0
        self.contexts: list[AuthorizationContext] = []

    def resolve(self, context: AuthorizationContext) -> AuthorizationPolicy:
        self.resolve_calls += 1
        self.contexts.append(context)
        return self._policy


class _RaisingResolver:
    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.resolve_calls = 0

    def resolve(self, context: AuthorizationContext) -> AuthorizationPolicy:
        self.resolve_calls += 1
        raise self._exc


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


def _management_role(
    *,
    resource: str = "tenant",
    verb: str = "get",
    qualifier: str = "object",
    effect: PermissionEffect = PermissionEffect.ALLOW,
) -> Role:
    urn = RoleUrn(SYSTEM_MANAGEMENT_ROLE_URN)
    set_id = make_id()
    from helpers import make_permission

    permission = make_permission(
        permission_set_id=set_id, resource=resource, verb=verb, qualifier=qualifier
    )
    return Role(
        urn, "Tenant Management", "", None, (PermissionSet(set_id, urn, effect, (permission,)),)
    )


def _eligible_resolution() -> ManagementScopeResolution:
    return ManagementScopeResolution(
        candidate=ManagementScopeCandidate(
            management_group_id=make_id(),
            scope=TenantManagementScope.SYSTEM,
            management_role_urn=RoleUrn(SYSTEM_MANAGEMENT_ROLE_URN),
        ),
        actor_eligible=True,
        blocked_reason=None,
    )


def _single(request: AuthorizationRequest) -> AuthorizationDecision:
    return Authorizer().authorize(request)


# --- B01/B02: basic batch size and parity ------------------------------------


def test_b01_batch_of_one_matches_single_authorizer() -> None:
    context = make_authorization_context(roles=(_role(rules=(("set", "*"),)),))
    request = build_request_from_context(
        context, action=make_action(verb="set", qualifier="active")
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert len(result.decisions) == 1
    assert result.decisions[0] == _single(request)
    assert result.decisions[0].allowed


def test_b02_batch_of_one_hundred_returns_exactly_one_hundred_ordered() -> None:
    role = _role(rules=(("set", "*"), ("get", "object")))
    context = make_authorization_context(roles=(role,))
    requests = tuple(
        build_request_from_context(
            context,
            action=make_action(
                verb="set" if index % 2 == 0 else "get",
                qualifier="active" if index % 2 == 0 else "object",
            ),
        )
        for index in range(100)
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch(requests))
    assert len(result.decisions) == 100
    for request, decision in zip(requests, result.decisions, strict=True):
        assert decision == _single(request)


# --- B03: batch validation before any resolver/native call -------------------


def test_b03_empty_batch_is_rejected() -> None:
    with pytest.raises(InvalidAuthorizationBatchError):
        AuthorizationBatch(())


def test_b03_oversized_batch_is_rejected() -> None:
    context = make_authorization_context()
    requests = tuple(build_request_from_context(context) for _ in range(101))
    with pytest.raises(InvalidAuthorizationBatchError):
        AuthorizationBatch(requests)


def test_b03_mutable_requests_are_rejected() -> None:
    context = make_authorization_context()
    request = build_request_from_context(context)
    with pytest.raises(InvalidAuthorizationBatchError):
        AuthorizationBatch([request])  # type: ignore[arg-type]


def test_b03_non_request_element_is_rejected() -> None:
    context = make_authorization_context()
    request = build_request_from_context(context)
    with pytest.raises(InvalidAuthorizationBatchError):
        AuthorizationBatch((request, "not-a-request"))  # type: ignore[arg-type]
    # The first element is validated separately.
    with pytest.raises(InvalidAuthorizationBatchError):
        AuthorizationBatch(("not-a-request",))  # type: ignore[arg-type]


def test_rust_batch_authorizer_takes_no_resolver_injection() -> None:
    with pytest.raises(TypeError):
        RustBatchAuthorizer(
            policy_resolver=_CountingResolver(_StubPolicy(AuthorizationDecision.allow()))
        )  # type: ignore[call-arg]


# --- B04/B05/B06: shared context, duplicates, one session/policy -------------


def test_b04_duplicate_action_occurrences_are_independent_and_ordered() -> None:
    role = _role(rules=(("set", "*"),))
    deny_role = _role(effect=PermissionEffect.DENY, rules=(("set", "active"),))
    context = make_authorization_context(roles=(role, deny_role))
    active = make_action(verb="set", qualifier="active")
    alias = make_action(verb="set", qualifier="alias")
    requests = (
        build_request_from_context(context, action=active),
        build_request_from_context(context, action=alias),
        build_request_from_context(context, action=active),
        build_request_from_context(context, action=alias),
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch(requests))
    assert result.decisions[0].reason is DenyReason.MATCHED_DENY
    assert result.decisions[1].allowed
    assert result.decisions[2].reason is DenyReason.MATCHED_DENY
    assert result.decisions[3].allowed
    for request, decision in zip(requests, result.decisions, strict=True):
        assert decision == _single(request)


def test_b05_distinct_but_equal_context_instances_are_rejected() -> None:
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    context_one = make_authorization_context(tenant=tenant, principal=principal, identity=identity)
    context_two = make_authorization_context(tenant=tenant, principal=principal, identity=identity)
    assert context_one == context_two
    assert context_one is not context_two
    requests = (
        build_request_from_context(context_one),
        build_request_from_context(context_two),
    )
    with pytest.raises(InvalidAuthorizationBatchError):
        AuthorizationBatch(requests)


def test_b06_shared_session_checked_once_and_policy_resolved_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mtmf_core.authorization.batch as batch_module

    session_calls = 0
    original = batch_module.validate_request_session

    def _counting_session(request: AuthorizationRequest) -> AuthorizationDecision | None:
        nonlocal session_calls
        session_calls += 1
        return original(request)

    monkeypatch.setattr(batch_module, "validate_request_session", _counting_session)

    role = _role(rules=(("set", "*"),))
    context = make_authorization_context(roles=(role,))
    resolver = _CountingResolver(_StubPolicy(AuthorizationDecision.allow()))
    requests = tuple(
        build_request_from_context(context, action=make_action(verb="set", qualifier=f"q{i}"))
        for i in range(5)
    )
    result = BatchAuthorizer(policy_resolver=resolver).authorize(AuthorizationBatch(requests))
    assert session_calls == 1
    assert resolver.resolve_calls == 1
    assert len(result.decisions) == 5
    assert all(decision.allowed for decision in result.decisions)


# --- B07/B08/B09: invalid session and target guards, no broadened ALLOW -------


def test_b07_invalid_session_denies_all_without_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    from mtmf_core import SessionContext

    context = make_authorization_context(
        principal=principal,
        identity=identity,
        session=SessionContext(make_id(), principal.id, identity.id),
        roles=(_role(),),
    )
    resolver = _CountingResolver(_StubPolicy(AuthorizationDecision.allow()))
    requests = tuple(build_request_from_context(context) for _ in range(3))
    result = BatchAuthorizer(policy_resolver=resolver).authorize(AuthorizationBatch(requests))
    assert resolver.resolve_calls == 0
    assert all(
        decision == AuthorizationDecision.deny(DenyReason.INVALID_CONTEXT)
        for decision in result.decisions
    )
    assert all(not decision.allowed for decision in result.decisions)


def test_b08_all_cross_tenant_denied_without_resolver() -> None:
    tenant = make_tenant("A")
    target = make_tenant("B")
    context = make_authorization_context(tenant=tenant, roles=(_role(),))
    resolver = _CountingResolver(_StubPolicy(AuthorizationDecision.allow()))
    requests = tuple(
        build_request_from_context(
            context, action=make_action(verb="set", qualifier=f"q{i}"), target_tenant_id=target.id
        )
        for i in range(4)
    )
    result = BatchAuthorizer(policy_resolver=resolver).authorize(AuthorizationBatch(requests))
    assert resolver.resolve_calls == 0
    assert all(
        decision == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)
        for decision in result.decisions
    )


def test_b09_mixed_valid_and_invalid_targets_keep_positions() -> None:
    tenant = make_tenant("A")
    target = make_tenant("B")
    context = make_authorization_context(tenant=tenant, roles=(_role(rules=(("set", "*"),)),))
    requests = (
        build_request_from_context(
            context, action=make_action(verb="set", qualifier="active"), target_tenant_id=tenant.id
        ),
        build_request_from_context(
            context, action=make_action(verb="set", qualifier="active"), target_tenant_id=target.id
        ),
        build_request_from_context(
            context, action=make_action(verb="set", qualifier="alias"), target_tenant_id=tenant.id
        ),
        build_request_from_context(
            context, action=make_action(verb="set", qualifier="alias"), target_tenant_id=target.id
        ),
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch(requests))
    assert result.decisions[0].allowed
    assert result.decisions[1] == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)
    assert result.decisions[2].allowed
    assert result.decisions[3] == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)
    for request, decision in zip(requests, result.decisions, strict=True):
        assert decision == _single(request)


# --- B10/B11/B12: management delegation --------------------------------------


def test_b10_eligible_management_parity_with_single_authorizer() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    role = _management_role()
    context = make_authorization_context(tenant=manager, roles=(role,))
    action = make_action(resource="tenant", verb="get", qualifier="object")
    request = build_request_from_context(
        context, action=action, target_tenant_id=target.id, management_scope=_eligible_resolution()
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert result.decisions[0].allowed
    assert result.decisions[0] == _single(request)


def test_b11_ineligible_management_is_denied() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    context = make_authorization_context(tenant=manager, roles=(_management_role(),))
    resolution = ManagementScopeResolution(
        candidate=_eligible_resolution().candidate,
        actor_eligible=False,
        blocked_reason="not eligible",
    )
    request = build_request_from_context(
        context,
        action=make_action(resource="tenant", verb="get", qualifier="object"),
        target_tenant_id=target.id,
        management_scope=resolution,
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert result.decisions[0] == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)


def test_b12_cross_tenant_extension_mutation_is_denied() -> None:
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    role = _management_role(verb="update", qualifier="extension")
    context = make_authorization_context(tenant=manager, roles=(role,))
    request = build_request_from_context(
        context,
        action=make_action(resource="tenant", verb="update", qualifier="extension"),
        target_tenant_id=target.id,
        management_scope=_eligible_resolution(),
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert result.decisions[0] == AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)


# --- B13-B18: policy semantics parity ----------------------------------------


@pytest.mark.parametrize(
    ("roles", "action"),
    [
        # B13 exact ALLOW vs wildcard DENY -> exact ALLOW.
        (
            (
                _role(effect=PermissionEffect.DENY, rules=(("set", "*"),)),
                _role(rules=(("set", "active"),)),
            ),
            make_action(verb="set", qualifier="active"),
        ),
        # B14 exact DENY vs wildcard ALLOW -> MATCHED_DENY.
        (
            (
                _role(rules=(("set", "*"),)),
                _role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),
            ),
            make_action(verb="set", qualifier="active"),
        ),
        # B15 equal-specificity ALLOW+DENY -> MATCHED_DENY, both flags.
        (
            (
                _role(rules=(("set", "active"),)),
                _role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),
            ),
            make_action(verb="set", qualifier="active"),
        ),
        # B16 wildcard-only ALLOW -> ALLOW at wildcard specificity.
        (
            (_role(rules=(("set", "*"),)),),
            make_action(verb="set", qualifier="active"),
        ),
        # B17 no matching permission -> NO_MATCH.
        (
            (_role(rules=(("set", "active"),)),),
            make_action(verb="get", qualifier="object"),
        ),
    ],
)
def test_b13_b17_policy_case_parity(roles: tuple[Role, ...], action: Action) -> None:
    context = make_authorization_context(roles=roles)
    request = build_request_from_context(context, action=action)
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert result.decisions[0] == _single(request)


def test_b15_equal_specificity_conflict_flags_both_true() -> None:
    context = make_authorization_context(
        roles=(
            _role(rules=(("set", "active"),)),
            _role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),
        )
    )
    request = build_request_from_context(
        context, action=make_action(verb="set", qualifier="active")
    )
    decision = BatchAuthorizer().authorize(AuthorizationBatch((request,))).decisions[0]
    assert decision.effect is AuthorizationEffect.DENY
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_deny
    assert decision.matched_allow


def test_b18_duplicates_and_permutations_do_not_change_decisions() -> None:
    action = make_action(verb="set", qualifier="active")
    base_roles = (
        _role(rules=(("set", "*"),)),
        _role(rules=(("set", "active"),)),
        _role(rules=(("set", "active"),), role_urn=make_role_urn(role_name="duplicate")),
    )
    permuted_roles = (base_roles[2], base_roles[0], base_roles[1])
    context_a = make_authorization_context(roles=base_roles)
    context_b = make_authorization_context(roles=permuted_roles)
    request_a = build_request_from_context(context_a, action=action)
    request_b = build_request_from_context(context_b, action=action)
    decision_a = BatchAuthorizer().authorize(AuthorizationBatch((request_a,))).decisions[0]
    decision_b = BatchAuthorizer().authorize(AuthorizationBatch((request_b,))).decisions[0]
    assert decision_a == _single(request_a)
    assert decision_b == _single(request_b)
    assert decision_a == decision_b


# --- B19-B22: post-policy guards ---------------------------------------------


def test_b19_unsupported_constraint_after_policy_allow_denies() -> None:
    context = make_authorization_context(roles=(_role(rules=(("set", "*"),)),))
    request = build_request_from_context(
        context,
        action=make_action(verb="set", qualifier="active"),
        unsupported_constraints=(UnsupportedConstraint.ALTERNATE_DOMINANCE,),
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert result.decisions[0] == AuthorizationDecision.deny(DenyReason.UNSUPPORTED_CONSTRAINT)
    assert result.decisions[0] == _single(request)


@pytest.mark.parametrize(
    ("subject_scope", "target_scope"),
    [
        (None, None),
        (SecurityScope.TENANT, SecurityScope.TENANT),
        (SecurityScope.ORGANIZATION, SecurityScope.TENANT),
    ],
)
def test_b20_missing_equal_or_insufficient_dominance_denies(
    subject_scope: SecurityScope | None, target_scope: SecurityScope | None
) -> None:
    context = make_authorization_context(roles=(_role(rules=(("set", "*"),)),))
    request = build_request_from_context(
        context,
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=subject_scope,
        target_scope=target_scope,
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert result.decisions[0] == AuthorizationDecision.deny(DenyReason.INSUFFICIENT_DOMINANCE)
    assert result.decisions[0] == _single(request)


def test_b21_sufficient_strict_dominance_retains_allow() -> None:
    context = make_authorization_context(roles=(_role(rules=(("set", "*"),)),))
    request = build_request_from_context(
        context,
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.ROOT,
        target_scope=SecurityScope.TENANT,
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert result.decisions[0].allowed
    assert result.decisions[0] == _single(request)


def test_b22_policy_deny_survives_post_constraints() -> None:
    context = make_authorization_context(
        roles=(_role(effect=PermissionEffect.DENY, rules=(("set", "active"),)),)
    )
    request = build_request_from_context(
        context,
        action=make_action(verb="set", qualifier="active"),
        unsupported_constraints=(UnsupportedConstraint.ALTERNATE_DOMINANCE,),
    )
    result = BatchAuthorizer().authorize(AuthorizationBatch((request,)))
    assert result.decisions[0].reason is DenyReason.MATCHED_DENY
    assert result.decisions[0] == _single(request)


# --- B23/B24: fail-closed ownership and resolver failures --------------------


def test_b23_corrupt_permission_set_ownership_fails_closed() -> None:
    urn = make_role_urn()
    other_urn = make_role_urn(role_name="other")
    permission_set = make_permission_set_with_rules(role_urn=other_urn, rules=(("set", "*"),))
    corrupt = corrupt_role(urn, (permission_set,))
    context = make_authorization_context(roles=(corrupt,))
    request = build_request_from_context(context)
    with pytest.raises(PermissionEvaluationError):
        BatchAuthorizer().authorize(AuthorizationBatch((request,)))


def test_b24_resolver_exception_fails_whole_batch_without_partial_result() -> None:
    tenant = make_tenant("A")
    target = make_tenant("B")
    context = make_authorization_context(tenant=tenant, roles=(_role(),))
    requests = (
        build_request_from_context(context, target_tenant_id=target.id),  # pre-denied
        build_request_from_context(context),  # surviving -> resolver called
    )
    resolver = _RaisingResolver(RuntimeError("resolver exploded"))
    with pytest.raises(RuntimeError, match="resolver exploded"):
        BatchAuthorizer(policy_resolver=resolver).authorize(AuthorizationBatch(requests))
    assert resolver.resolve_calls == 1


# --- B29/B33: native pre-denied and no cross-batch leakage -------------------


def test_b29_all_pre_denied_never_touches_resolver() -> None:
    tenant = make_tenant("A")
    target = make_tenant("B")
    context = make_authorization_context(tenant=tenant, roles=(_role(),))
    requests = tuple(
        build_request_from_context(context, target_tenant_id=target.id) for _ in range(5)
    )
    resolver = _CountingResolver(_StubPolicy(AuthorizationDecision.allow()))
    result = BatchAuthorizer(policy_resolver=resolver).authorize(AuthorizationBatch(requests))
    assert resolver.resolve_calls == 0
    assert len(result.decisions) == 5


def test_b33_sequential_batches_do_not_leak_authority() -> None:
    tenant_a = make_tenant("A")
    tenant_b = make_tenant("B")
    allow_role = _role(rules=(("set", "*"),))
    no_role: tuple[Role, ...] = ()
    context_a = make_authorization_context(tenant=tenant_a, roles=(allow_role,))
    context_b = make_authorization_context(tenant=tenant_b, roles=no_role)
    request_a = build_request_from_context(
        context_a, action=make_action(verb="set", qualifier="active")
    )
    request_b = build_request_from_context(
        context_b, action=make_action(verb="set", qualifier="active")
    )
    authorizer = BatchAuthorizer()
    first = authorizer.authorize(AuthorizationBatch((request_a,)))
    second = authorizer.authorize(AuthorizationBatch((request_b,)))
    assert first.decisions[0].allowed
    assert second.decisions[0].reason is DenyReason.NO_MATCH
    # Re-running the first batch still sees its own policy.
    third = authorizer.authorize(AuthorizationBatch((request_a,)))
    assert third.decisions[0].allowed


# --- B25: native unavailability fails closed (negative boundary only) --------


def test_b25_native_unavailable_fails_closed_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mtmf_core.authorization.rust_engine as rust_engine
    from mtmf_core.authorization.rust_permission_evaluator import (
        PermissionEvaluationInfrastructureError,
    )

    def _unavailable() -> object:
        raise rust_engine.RustEngineUnavailableError("native module absent")

    monkeypatch.setattr(rust_engine, "_load_native_module", _unavailable)
    context = make_authorization_context(roles=(_role(rules=(("set", "*"),)),))
    request = build_request_from_context(
        context, action=make_action(verb="set", qualifier="active")
    )
    with pytest.raises(PermissionEvaluationInfrastructureError):
        RustBatchAuthorizer().authorize(AuthorizationBatch((request,)))


# --- B30: default import/construct never loads the native module -------------


def test_b30_default_authorizer_import_never_loads_native_module() -> None:
    code = (
        "import sys\n"
        "import mtmf_core\n"
        "from mtmf_core import Authorizer, BatchAuthorizer\n"
        "Authorizer()\n"
        "BatchAuthorizer()\n"
        "assert '_mtmf_permission_engine' not in sys.modules, 'native module was loaded'\n"
        "print('no-native-load')\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "no-native-load" in completed.stdout
