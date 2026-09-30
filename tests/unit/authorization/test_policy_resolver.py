"""DefaultAuthorizationPolicyResolver tests (PR 8H).

Prove the resolver contract and the default implementation:

- ``resolve`` returns an :class:`AuthorizationPolicy`;
- the returned object is an :class:`EffectivePolicy`;
- the nested actual policy is the production pure-Python
  :class:`CompiledPolicy`;
- applicable Roles compile correctly and no-Roles resolves to a valid
  empty policy that denies;
- ownership corruption propagates from ``resolve``;
- repeated ``resolve`` may return distinct objects (no caching
  contract);
- ``resolve`` needs no Action, performs no persistence/config,
  retrieves nothing, and never mutates the context or Roles.

Pure Python: no native module, no PostgreSQL, no Podman, no network
service, no timing assertion, no randomness.
"""

from __future__ import annotations

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
    AuthorizationPolicy,
    AuthorizationPolicyResolver,
    CompiledPolicy,
    DefaultAuthorizationPolicyResolver,
    DenyReason,
    EffectivePolicy,
    PermissionEffect,
    PermissionEvaluator,
)
from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError


def _role(
    *,
    rules: tuple[tuple[str, str], ...] = (("set", "active"),),
    effect: PermissionEffect = PermissionEffect.ALLOW,
) -> object:
    urn = make_role_urn()
    return make_role_from_sets(
        role_urn=urn,
        permission_sets=(make_permission_set_with_rules(role_urn=urn, effect=effect, rules=rules),),
    )


def _resolver() -> DefaultAuthorizationPolicyResolver:
    return DefaultAuthorizationPolicyResolver()


# --- 1/2/3. Resolver contract and default composition --------------------------


def test_resolver_conforms_to_the_resolver_protocol() -> None:
    resolver = _resolver()
    assert isinstance(resolver, AuthorizationPolicyResolver)
    assert callable(resolver.resolve)


def test_resolve_returns_an_authorization_policy() -> None:
    context = build_authorization_request(roles=(_role(),)).context
    policy = _resolver().resolve(context)
    assert isinstance(policy, AuthorizationPolicy)


def test_resolve_returns_effective_policy_wrapping_production_compiled_policy() -> None:
    context = build_authorization_request(roles=(_role(),)).context
    resolved = _resolver().resolve(context)
    assert isinstance(resolved, EffectivePolicy)
    assert isinstance(resolved._policy, CompiledPolicy)
    # Never Rust: the nested policy is the production pure-Python compiled
    # implementation.
    from mtmf_core.authorization.rust_permission_evaluator import RustPermissionEvaluator

    assert not isinstance(resolved._policy, RustPermissionEvaluator)


# --- 4/5. Applicable Roles compile; no Roles is a valid empty policy -----------


def test_applicable_roles_compile_correctly() -> None:
    context = build_authorization_request(
        roles=(_role(rules=(("set", "active"),), effect=PermissionEffect.ALLOW),)
    ).context
    policy = _resolver().resolve(context)
    decision = policy.evaluate(make_action(verb="set", qualifier="active"))
    assert decision.allowed
    assert decision.reason is None


def test_no_roles_resolves_to_a_valid_empty_policy_that_denies() -> None:
    context = build_authorization_request().context
    resolved = _resolver().resolve(context)
    assert isinstance(resolved, EffectivePolicy)
    assert resolved._policy.exact_key_count == 0
    assert resolved._policy.wildcard_key_count == 0
    decision = resolved.evaluate(make_action(verb="set", qualifier="active"))
    assert not decision.allowed
    assert decision.reason is DenyReason.NO_MATCH


# --- 6. Ownership corruption propagates from resolve ----------------------------


def test_ownership_corruption_propagates_from_resolve() -> None:
    owner_urn = make_role_urn(role_name="owner")
    foreign_set = make_permission_set_with_rules(
        role_urn=make_role_urn(role_name="other"), rules=(("set", "*"),)
    )
    role = corrupt_role(owner_urn, (foreign_set,))
    context = build_authorization_request(roles=(role,)).context
    with pytest.raises(PermissionEvaluationError):
        _resolver().resolve(context)


# --- 7. No caching contract ------------------------------------------------------


def test_repeated_resolve_may_return_distinct_objects() -> None:
    context = build_authorization_request(roles=(_role(),)).context
    resolver = _resolver()
    first = resolver.resolve(context)
    second = resolver.resolve(context)
    # No object-reuse contract: distinct objects are allowed, but they
    # must behave identically (deterministic compile of the same Roles).
    assert first is not second
    action = make_action(verb="set", qualifier="active")
    assert first.evaluate(action) == second.evaluate(action)
    assert first.get_diagnostics() == second.get_diagnostics()


# --- 8. No Action required --------------------------------------------------------


def test_resolve_requires_no_action() -> None:
    context = build_authorization_request(roles=(_role(),)).context
    resolved = _resolver().resolve(context)
    assert callable(resolved.evaluate)
    # Resolve never evaluated anything: the request Action is not an input.
    action = make_action(verb="set", qualifier="active")
    assert resolved.evaluate(action).allowed


# --- 9/10. No persistence/config, no mutation -------------------------------------


def test_resolver_has_no_persistence_or_configuration_surface() -> None:
    resolver = _resolver()
    for name in (
        "repository",
        "spi",
        "unit_of_work",
        "cache",
        "config",
        "redis",
        "db",
        "session",
        "load",
        "retrieve",
    ):
        assert not hasattr(resolver, name)


def test_resolve_does_not_mutate_context_or_roles() -> None:
    role = _role(rules=(("set", "active"), ("get", "*")))
    request = build_authorization_request(roles=(role,))
    context = request.context
    sets_before = tuple(role.permission_sets)
    permissions_before = tuple(
        permission for permission_set in sets_before for permission in permission_set.permissions
    )
    resolved = _resolver().resolve(context)
    assert context.applicable_roles == (role,)
    assert role.permission_sets == sets_before
    assert (
        tuple(
            permission
            for permission_set in role.permission_sets
            for permission in permission_set.permissions
        )
        == permissions_before
    )
    # Compiled decisions agree with the linear oracle on the same input.
    action = make_action(verb="set", qualifier="active")
    assert resolved.evaluate(action) == PermissionEvaluator().evaluate(action, (role,))
