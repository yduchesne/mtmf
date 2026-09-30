"""Production authorization policy resolution (PR 8H).

The :class:`AuthorizationPolicyResolver` protocol resolves an
:class:`~mtmf_core.authorization.policy.AuthorizationPolicy` for a
supplied
:class:`~mtmf_core.authorization.context.AuthorizationContext`. A
resolver does not authorize an Action and must not require an Action: it
produces the policy object that later evaluates Actions.

The initial production implementation is the non-caching
:class:`DefaultAuthorizationPolicyResolver`, which compiles the
caller-supplied ``context.applicable_roles`` into the production
pure-Python :class:`~mtmf_core.authorization.compiled_policy.CompiledPolicy`
and wraps it in an
:class:`~mtmf_core.authorization.policy.EffectivePolicy` for
context-aware diagnostics.

There is deliberately no repository, ``MtmfSpi``, UnitOfWork,
PostgreSQL, Redis, network, filesystem, global cache, local cache, or
policy fingerprinting here. ``AuthorizationContext.applicable_roles``
remains trusted, pre-filtered caller input (Role-assignment/effective-
Role loading is PR 9 work and is not invented here).

The resolver contract is designed so that later caching/decoration can
be composed around this implementation without changing the Authorizer
or the policy implementations, for example:

.. code-block:: python

    resolver = InMemoryCachingAuthorizationPolicyResolver(
        RedisCachingAuthorizationPolicyResolver(
            DefaultAuthorizationPolicyResolver()
        )
    )

No caching resolver, cache key, version, fingerprint, invalidation,
TTL, or cache configuration exists or is implemented in PR 8H.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mtmf_core.authorization.compiled_policy import CompiledPolicy
from mtmf_core.authorization.context import AuthorizationContext
from mtmf_core.authorization.policy import AuthorizationPolicy, EffectivePolicy


@runtime_checkable
class AuthorizationPolicyResolver(Protocol):
    """Resolves an already-applicable policy for a supplied context.

    ``resolve`` returns an :class:`AuthorizationPolicy` that can then
    evaluate any number of exact Actions. It performs no Action
    evaluation and no authorization: it only selects/builds the policy.
    Implementations must not retrieve authorization context; the
    supplied context is the complete input.
    """

    def resolve(self, context: AuthorizationContext) -> AuthorizationPolicy:
        """Resolve the applicable policy for the supplied context."""
        ...


class DefaultAuthorizationPolicyResolver:
    """Non-caching default resolver: compile applicable Roles, wrap for diagnostics.

    ``resolve(context)``:

    1. compiles ``context.applicable_roles`` into a production
       pure-Python :class:`~mtmf_core.authorization.compiled_policy.CompiledPolicy`;
    2. wraps it in an :class:`~mtmf_core.authorization.policy.EffectivePolicy`
       carrying ``context`` for diagnostics;
    3. returns the wrapper.

    The resolver performs no repository, ``MtmfSpi``, UnitOfWork,
    PostgreSQL, Redis, network, filesystem, cache, or fingerprinting
    behavior, and it never mutates the supplied context or Roles.

    :raises PermissionEvaluationError: for structurally corrupted
        domain policy in ``context.applicable_roles`` (ownership
        corruption), exactly like the linear Python oracle and the Rust
        evaluator/adapters.
    """

    __slots__ = ()

    def resolve(self, context: AuthorizationContext) -> AuthorizationPolicy:
        """Compile the applicable Roles and wrap the policy for the context."""
        compiled = CompiledPolicy.compile(context.applicable_roles)
        return EffectivePolicy(compiled, context)
