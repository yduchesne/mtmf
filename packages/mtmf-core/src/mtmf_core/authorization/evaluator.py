"""Internal policy-evaluation protocol for the Authorizer seam.

The :class:`PermissionEvaluatorProtocol` describes exactly the
policy-evaluation capability the
:class:`~mtmf_core.authorization.authorizer.Authorizer` depends on:
decide one exact
:class:`~mtmf_core.domain.action.Action` against an iterable of
already-applicable
:class:`~mtmf_core.domain.role.Role` objects and return an
:class:`AuthorizationDecision`.
This protocol is intentionally narrow and internal:

- no lifecycle, configuration, persistence, capability-probing,
  backend-selection, or context-retrieval methods exist here;
- it is not exported through ``mtmf-api`` and introduces no plugin or
  provider framework;
- both the Python reference
  :class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
  and the Rust-backed
  :class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`
  satisfy it, so the evaluator remains injectable for tests and
  reference/comparison use while the Authorizer depends only on this
  seam.

Python (the Authorizer) remains authoritative for authorization
context, policy applicability, Tenant/session validation, scope and
dominance, stewardship/delegation, operation-specific constraints, and
fail-closed orchestration. The evaluator implementations only resolve
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
