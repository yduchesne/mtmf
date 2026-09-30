"""Internal policy-evaluation protocol (linear reference/experimental seam).

The :class:`PermissionEvaluatorProtocol` describes the linear
policy-evaluation capability shared by the pure-Python reference
:class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
and the experimental Rust-backed
:class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`:
decide one exact :class:`~mtmf_core.domain.action.Action` against an
iterable of already-applicable
:class:`~mtmf_core.domain.role.Role` objects and return an
:class:`AuthorizationDecision`.

After PR 8H this is no longer the Authorizer's primary seam: the
:class:`~mtmf_core.authorization.authorizer.Authorizer` depends on the
:class:`~mtmf_core.authorization.policy_resolver.AuthorizationPolicyResolver`
protocol and on :class:`~mtmf_core.authorization.policy.AuthorizationPolicy`,
and the production policy implementation is the pure-Python indexed
:class:`~mtmf_core.authorization.compiled_policy.CompiledPolicy`.
This protocol intentionally remains as the narrow seam for the linear
Python reference/oracle and for Rust integration/differential
experiments:

- no lifecycle, configuration, persistence, capability-probing,
  backend-selection, or context-retrieval methods exist here;
- it is not exported through ``mtmf-api`` and introduces no plugin or
  provider framework;
- both the Python reference
  :class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
  and the Rust-backed
  :class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`
  satisfy it, so evaluator injection remains available for tests and
  reference/comparison use while the Authorizer no longer depends on
  this seam for its default path.

Python (the Authorizer) remains authoritative for authorization
context, policy applicability, Tenant/session validation, scope and
dominance, stewardship/delegation, operation-specific constraints, and
fail-closed orchestration. Evaluation implementations only resolve
policy against already-applicable Roles.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from mtmf_core.authorization.decision import AuthorizationDecision
from mtmf_core.domain.action import Action
from mtmf_core.domain.role import Role


class PermissionEvaluatorProtocol(Protocol):
    """The narrow internal policy-evaluation capability.

    Implementations consume an exact Action and already-applicable Role
    objects and produce one explicit :class:`AuthorizationDecision`.
    They never retrieve authorization context and never decide which
    Roles are applicable.
    """

    def evaluate(
        self,
        action: Action,
        roles: Iterable[Role],
    ) -> AuthorizationDecision:
        """Decide one exact Action against the supplied applicable Roles."""
        ...
