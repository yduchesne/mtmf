"""Production authorization policy abstraction (PR 8H).

The :class:`AuthorizationPolicy` protocol is the production policy
surface the :class:`~mtmf_core.authorization.authorizer.Authorizer`
depends on after PR 8H. Unlike the historical
:class:`~mtmf_core.authorization.evaluator.PermissionEvaluatorProtocol`
seam (which decided one Action against an iterable of
already-applicable Roles), an :class:`AuthorizationPolicy` is
*already resolved*: callers evaluate one exact Action against a policy
that was compiled/resolved up front and must not be handed Roles at
evaluation time.

Rules of the seam:

- callers evaluate an already-resolved policy;
- ``evaluate`` receives no Roles;
- internal representation is hidden;
- diagnostics never affect authorization;
- no persistence or context retrieval exists on the policy surface.

:class:`EffectivePolicy` is a pure diagnostic/delegation wrapper over
another :class:`AuthorizationPolicy` plus the
:class:`~mtmf_core.authorization.context.AuthorizationContext` it was
resolved for. It adds no authorization semantics, performs no
retrieval, and delegates ``evaluate`` unchanged; it only makes
context-aware diagnostics available.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mtmf_core.authorization.context import AuthorizationContext
from mtmf_core.authorization.decision import AuthorizationDecision
from mtmf_core.domain.action import Action


@runtime_checkable
class AuthorizationPolicy(Protocol):
    """An already-resolved, ready-to-evaluate authorization policy.

    Implementations own their internal policy representation (for
    example an immutable compiled index) and expose exactly two
    capabilities:

    - :meth:`evaluate`: decide one exact
      :class:`~mtmf_core.domain.action.Action`;
    - :meth:`get_diagnostics`: implementation-specific diagnostic text
      that never influences authorization.

    A policy never retrieves authorization context, never performs
    persistence/I/O, and never decides which Roles are applicable: the
    applicable policy was resolved before the policy object existed.
    """

    def evaluate(self, action: Action) -> AuthorizationDecision:
        """Decide one exact Action against this already-resolved policy."""
        ...

    def get_diagnostics(self) -> str:
        """Return implementation-specific diagnostic text.

        The text is not parsed by the Authorizer, is not decision
        input, is not a stable machine API, is not cache identity, is
        not serialization, and is not an audit record.
        """
        ...


class EffectivePolicy:
    """A diagnostics wrapper over an actual policy plus its context.

    Conceptually ``EffectivePolicy(actual_policy, authorization_context)``:

    - retains the context so safe high-level identity information can
      be correlated with the nested policy;
    - retains the nested :class:`AuthorizationPolicy` and delegates
      :meth:`evaluate` to it directly and unchanged;
    - adds no authorization semantics and performs no retrieval;
    - exposes context-aware diagnostics by combining safe high-level
      context identity with the nested policy's own diagnostics.

    The wrapped policy owns all evaluation behavior: this class is a
    diagnostics boundary, not another policy engine.
    """

    __slots__ = ("_context", "_policy")

    def __init__(
        self,
        policy: AuthorizationPolicy,
        context: AuthorizationContext,
    ) -> None:
        """Wrap ``policy`` for the supplied ``context`` (diagnostics only)."""
        self._policy = policy
        self._context = context

    def evaluate(self, action: Action) -> AuthorizationDecision:
        """Delegate to the wrapped policy directly and unchanged."""
        return self._policy.evaluate(action)

    def get_diagnostics(self) -> str:
        """Combine safe context identity with the wrapped policy diagnostics.

        Contains: the resolved Tenant/Principal/Identity IDs, the
        number of caller-supplied applicable Roles, and the nested
        policy implementation name plus its own diagnostics. It never
        dumps Permission lists, Role/PermissionSet/Permission URNs,
        extension payloads, credentials/secrets, or arbitrary domain
        reprs, and it never influences authorization.
        """
        context = self._context
        return (
            "EffectivePolicy("
            f"tenant={context.tenant.id}, principal={context.principal.id}, "
            f"identity={context.identity.id}, "
            f"applicable_roles={len(context.applicable_roles)}, "
            f"policy={type(self._policy).__name__}) "
            f"[{self._policy.get_diagnostics()}]"
        )
