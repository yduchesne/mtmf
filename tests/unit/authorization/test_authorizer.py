"""Authorizer foundation tests (matrix A01-A25)."""

from __future__ import annotations

import typing

import pytest
from authz_helpers import (
    build_authorization_request,
    corrupt_role,
    make_action,
    make_permission_set_with_rules,
    make_role_from_sets,
    make_role_urn,
)
from helpers import make_id, make_identity, make_principal, make_tenant

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
    IdentityTenantMembership,
    MatchSpecificity,
    PermissionEffect,
    PermissionEvaluationError,
    PermissionEvaluator,
    PrincipalTenantMembership,
    Role,
    RoleUrn,
    SecurityScope,
    SessionContext,
    UnsupportedConstraint,
)


class _StubPolicy:
    """A stub AuthorizationPolicy recording the Actions it evaluates."""

    def __init__(
        self,
        decision: AuthorizationDecision | None = None,
        *,
        raise_exc: Exception | None = None,
    ) -> None:
        self._decision = decision
        self._raise_exc = raise_exc
        self.evaluated: list[Action] = []

    def evaluate(self, action: Action) -> AuthorizationDecision:
        self.evaluated.append(action)
        if self._raise_exc is not None:
            raise self._raise_exc
        if self._decision is not None:
            return self._decision
        return AuthorizationDecision.deny(DenyReason.NO_MATCH)

    def get_diagnostics(self) -> str:
        return "StubPolicy()"


class _StubResolver:
    """A stub AuthorizationPolicyResolver recording the contexts it resolves."""

    def __init__(
        self,
        policy: _StubPolicy | None = None,
        *,
        raise_exc: Exception | None = None,
    ) -> None:
        self._policy = policy if policy is not None else _StubPolicy()
        self._raise_exc = raise_exc
        self.resolved: list[AuthorizationContext] = []

    def resolve(self, context: AuthorizationContext) -> _StubPolicy:
        self.resolved.append(context)
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._policy


def _system_role(
    *,
    rules: tuple[tuple[str, str], ...] = (("set", "*"),),
    effect: PermissionEffect = PermissionEffect.ALLOW,
    role_urn: RoleUrn | None = None,
    role_name: str = "actor",
) -> Role:
    resolved_urn = role_urn if role_urn is not None else make_role_urn(role_name=role_name)
    return make_role_from_sets(
        role_urn=resolved_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=resolved_urn, effect=effect, rules=rules),
        ),
    )


def test_a01_valid_session_same_tenant_policy_allow_no_dominance() -> None:
    request = build_authorization_request(
        roles=(_system_role(rules=(("set", "*"),)),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed
    assert decision.reason is None


def test_a02_policy_deny_is_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(rules=(("set", "*"),), effect=PermissionEffect.DENY),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_a03_no_applicable_roles_is_deny() -> None:
    request = build_authorization_request(action=make_action(verb="set", qualifier="active"))
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


def test_a04_session_tenant_differs_from_target_tenant_is_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        target_tenant_id=make_id(),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.TENANT_MISMATCH


def test_a05_session_tenant_differs_from_supplied_tenant_is_deny() -> None:
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    mismatched_session = SessionContext(make_id(), principal.id, identity.id)
    request = build_authorization_request(
        tenant=tenant,
        principal=principal,
        identity=identity,
        session=mismatched_session,
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INVALID_CONTEXT


def test_a06_identity_not_principals_identity_is_deny() -> None:
    principal_a = make_principal()
    principal_b = make_principal()
    identity = make_identity(principal_id=principal_b.id)
    tenant = make_tenant("A")
    request = build_authorization_request(
        tenant=tenant,
        principal=principal_a,
        identity=identity,
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INVALID_CONTEXT


def test_a07_missing_principal_tenant_membership_is_deny() -> None:
    request = build_authorization_request(
        principal_tenant_memberships=(),
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INVALID_CONTEXT


def test_a08_missing_identity_tenant_membership_is_deny() -> None:
    request = build_authorization_request(
        identity_tenant_memberships=(),
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INVALID_CONTEXT


def test_a09_another_tenants_memberships_only_is_deny() -> None:
    tenant = make_tenant("A")
    other_tenant = make_tenant("B")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    request = build_authorization_request(
        tenant=tenant,
        principal=principal,
        identity=identity,
        principal_tenant_memberships=(PrincipalTenantMembership(principal.id, other_tenant.id),),
        identity_tenant_memberships=(IdentityTenantMembership(identity.id, other_tenant.id),),
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INVALID_CONTEXT


def test_a10_policy_allow_strict_dominance_valid() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.SYSTEM,
        target_scope=SecurityScope.TENANT,
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed


def test_a11_strict_dominance_same_scope_is_deny() -> None:
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


def test_a12_inverse_dominance_is_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.TENANT,
        target_scope=SecurityScope.SYSTEM,
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INSUFFICIENT_DOMINANCE


def test_a13_missing_subject_scope_is_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=None,
        target_scope=SecurityScope.TENANT,
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INSUFFICIENT_DOMINANCE


def test_a14_missing_target_scope_is_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.SYSTEM,
        target_scope=None,
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INSUFFICIENT_DOMINANCE


def test_a15_policy_deny_with_valid_dominance_is_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(rules=(("set", "*"),), effect=PermissionEffect.DENY),),
        action=make_action(verb="set", qualifier="active"),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.ROOT,
        target_scope=SecurityScope.ORGANIZATION,
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY


def test_a16_strict_dominance_failure_has_no_alternate_dominance() -> None:
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


def test_a17_system_defined_role_is_not_rejected_in_tenant_context() -> None:
    request = build_authorization_request(
        roles=(_system_role(rules=(("set", "*"),)),),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed


def test_a18_tenant_defined_role_definition_is_not_assignment_context() -> None:
    # The Role's TENANT definition namespace (here for an unrelated
    # defining Tenant) is definition ownership, not assignment context:
    # the Authorizer must not reject it for namespace reasons.
    defining_tenant = make_id()
    urn = make_role_urn(tenant_id=defining_tenant, role_name="analyst")
    role = make_role_from_sets(
        role_urn=urn,
        tenant_id=defining_tenant,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, rules=(("set", "*"),)),),
    )
    request = build_authorization_request(
        roles=(role,), action=make_action(verb="set", qualifier="active")
    )
    decision = Authorizer().authorize(request)
    assert decision.allowed


def test_a19_cross_tenant_context_cannot_authorize() -> None:
    tenant_b = make_tenant("B")
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        target_tenant_id=tenant_b.id,
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.TENANT_MISMATCH


def test_a20_unsupported_security_constraint_is_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        unsupported_constraints=(UnsupportedConstraint.ALTERNATE_DOMINANCE,),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.UNSUPPORTED_CONSTRAINT


def test_a21_extension_mutation_requiring_unresolved_provenance_is_deny() -> None:
    request = build_authorization_request(
        roles=(_system_role(rules=(("update", "*"),)),),
        action=make_action(verb="update", qualifier="extension"),
        unsupported_constraints=(UnsupportedConstraint.EXTENSION_MUTATION_PROVENANCE,),
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.UNSUPPORTED_CONSTRAINT


def test_a22_callers_supply_exact_action_not_permission() -> None:
    request_hints = typing.get_type_hints(AuthorizationRequest)
    assert request_hints["action"] is Action
    evaluator_hints = typing.get_type_hints(PermissionEvaluator.evaluate)
    assert evaluator_hints["action"] is Action


def test_a23_permission_cannot_be_used_as_action_input() -> None:
    # The internal seam is typed at (action: Action): a Permission object
    # is never an acceptable input in place of an Action.
    request_hints = typing.get_type_hints(AuthorizationRequest)
    assert request_hints["action"] is Action
    assert "permission" not in AuthorizationRequest.__dataclass_fields__
    evaluator_hints = typing.get_type_hints(PermissionEvaluator.evaluate)
    assert evaluator_hints["action"] is Action


def test_a24_input_permutation_yields_same_decision() -> None:
    allow_urn = make_role_urn(role_name="a")
    allow_role = make_role_from_sets(
        role_urn=allow_urn,
        permission_sets=(
            make_permission_set_with_rules(role_urn=allow_urn, rules=(("set", "*"),)),
        ),
    )
    deny_urn = make_role_urn(role_name="b")
    deny_role = make_role_from_sets(
        role_urn=deny_urn,
        permission_sets=(
            make_permission_set_with_rules(
                role_urn=deny_urn, effect=PermissionEffect.DENY, rules=(("set", "alias"),)
            ),
        ),
    )
    action = make_action(verb="set", qualifier="alias")
    authorizer = Authorizer()
    forward = authorizer.authorize(
        build_authorization_request(roles=(allow_role, deny_role), action=action)
    )
    reversed_ = authorizer.authorize(
        build_authorization_request(roles=(deny_role, allow_role), action=action)
    )
    assert forward == reversed_
    assert not forward.allowed
    # Role definition is not assignment context here: the Role order does
    # not matter and the equal-specificity DENY wins in both orders.
    assert forward.reason is DenyReason.MATCHED_DENY


def test_a25_unexpected_evaluator_exception_propagates_never_allow() -> None:
    role_urn = make_role_urn(role_name="owner")
    foreign_set = make_permission_set_with_rules(
        role_urn=make_role_urn(role_name="other"), rules=(("set", "*"),)
    )
    request = build_authorization_request(
        roles=(corrupt_role(role_urn, (foreign_set,)),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(PermissionEvaluationError):
        Authorizer().authorize(request)


def test_authorizer_delegates_to_an_injected_resolver_and_policy() -> None:
    allow = AuthorizationDecision.allow(
        matched_specificity=MatchSpecificity.EXACT, matched_allow=True
    )
    policy = _StubPolicy(allow)
    resolver = _StubResolver(policy)
    authorizer = Authorizer(resolver)
    action = make_action(verb="set", qualifier="active")
    request = build_authorization_request(action=action)
    decision = authorizer.authorize(request)
    assert decision.allowed
    # Authorizer -> resolver.resolve(context) -> policy.evaluate(action).
    assert resolver.resolved == [request.context]
    assert policy.evaluated == [action]


def test_authorizer_default_policy_resolver_builds_effective_python_compiled_policy() -> None:
    assert isinstance(Authorizer()._policy_resolver, DefaultAuthorizationPolicyResolver)
    context = build_authorization_request(
        action=make_action(verb="set", qualifier="active")
    ).context
    resolved = DefaultAuthorizationPolicyResolver().resolve(context)
    assert isinstance(resolved, EffectivePolicy)
    assert isinstance(resolved._policy, CompiledPolicy)
    # The default resolver is non-caching but must return protocol-classified
    # policies; repeated resolve may return distinct objects (no caching
    # contract), and the default path never selects Rust.
    assert isinstance(Authorizer()._policy_resolver, DefaultAuthorizationPolicyResolver)


def test_resolver_is_not_called_for_invalid_session() -> None:
    policy = _StubPolicy()
    resolver = _StubResolver(policy)
    tenant = make_tenant("A")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    request = build_authorization_request(
        tenant=tenant,
        principal=principal,
        identity=identity,
        session=SessionContext(make_id(), principal.id, identity.id),
        action=make_action(verb="set", qualifier="active"),
    )
    decision = Authorizer(resolver).authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.INVALID_CONTEXT
    assert resolver.resolved == []
    assert policy.evaluated == []


def test_resolver_is_not_called_for_target_tenant_mismatch() -> None:
    policy = _StubPolicy()
    resolver = _StubResolver(policy)
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
        target_tenant_id=make_id(),
    )
    decision = Authorizer(resolver).authorize(request)
    assert not decision.allowed
    assert decision.reason is DenyReason.TENANT_MISMATCH
    assert resolver.resolved == []
    assert policy.evaluated == []


def test_resolver_exception_propagates_and_never_becomes_allow() -> None:
    boom = RuntimeError("resolver exploded")
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(RuntimeError) as raised:
        Authorizer(_StubResolver(raise_exc=boom)).authorize(request)
    assert raised.value is boom


def test_policy_evaluation_exception_propagates_and_never_becomes_allow() -> None:
    boom = RuntimeError("policy exploded")
    request = build_authorization_request(
        roles=(_system_role(),),
        action=make_action(verb="set", qualifier="active"),
    )
    with pytest.raises(RuntimeError) as raised:
        Authorizer(_StubResolver(_StubPolicy(raise_exc=boom))).authorize(request)
    assert raised.value is boom


def test_policy_deny_is_final_through_the_resolver_path() -> None:
    deny = AuthorizationDecision.deny(
        DenyReason.MATCHED_DENY,
        matched_specificity=MatchSpecificity.EXACT,
        matched_allow=False,
        matched_deny=True,
    )
    request = build_authorization_request(
        action=make_action(verb="set", qualifier="active"),
        unsupported_constraints=(UnsupportedConstraint.ALTERNATE_DOMINANCE,),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.ROOT,
        target_scope=SecurityScope.ORGANIZATION,
    )
    decision = Authorizer(_StubResolver(_StubPolicy(deny))).authorize(request)
    assert not decision.allowed
    # The policy DENY is reported as such; no later constraint rewrites it.
    assert decision.reason is DenyReason.MATCHED_DENY


def test_policy_deny_is_final_even_when_other_constraints_are_required() -> None:
    request = build_authorization_request(
        roles=(_system_role(rules=(("set", "*"),), effect=PermissionEffect.DENY),),
        action=make_action(verb="set", qualifier="active"),
        unsupported_constraints=(UnsupportedConstraint.ALTERNATE_DOMINANCE,),
        dominance_requirement=DominanceRequirement.STRICT,
        subject_scope=SecurityScope.ROOT,
        target_scope=SecurityScope.ORGANIZATION,
    )
    decision = Authorizer().authorize(request)
    assert not decision.allowed
    # The policy DENY is reported as such; no later constraint rewrites it
    # and no failure path ever produces ALLOW.
    assert decision.reason is DenyReason.MATCHED_DENY


def test_context_and_request_carry_only_narrow_supplied_facts() -> None:
    assert set(AuthorizationContext.__dataclass_fields__) == {
        "session",
        "tenant",
        "principal",
        "identity",
        "principal_tenant_memberships",
        "identity_tenant_memberships",
        "applicable_roles",
    }
    assert set(AuthorizationRequest.__dataclass_fields__) == {
        "context",
        "action",
        "target_tenant_id",
        "dominance_requirement",
        "subject_scope",
        "target_scope",
        "unsupported_constraints",
    }
