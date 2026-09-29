"""Deterministic, side-effect-free Permission evaluation.

The :class:`PermissionEvaluator` consumes an exact
:class:`~mtmf_core.domain.action.Action` and an iterable of
already-applicable :class:`~mtmf_core.domain.role.Role` objects supplied
by the caller. It reuses PR 3 matching (never reimplements wildcard
grammar or specificity), selects the most-specific matching rules across
all supplied Roles, applies equal-specificity DENY precedence, and
defaults to DENY when nothing matches.

The evaluator performs no context retrieval of any kind: no repository,
membership, assignment, session, scope/dominance, stewardship,
delegation, logging, network, or database behavior exists here. It
consumes policy only.
"""

from __future__ import annotations

from collections.abc import Iterable

from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.authorization.evaluator import PermissionEvaluatorProtocol
from mtmf_core.domain.action import Action
from mtmf_core.domain.errors import DomainInvariantError
from mtmf_core.domain.permission_matching import MatchSpecificity, match_permission
from mtmf_core.domain.policy import PermissionEffect
from mtmf_core.domain.role import Role


class PermissionEvaluationError(DomainInvariantError):
    """Raised when structurally corrupted policy reaches the evaluator.

    Policy objects are expected to satisfy the PR 3 construction
    invariants (Role owns its PermissionSets; a PermissionSet owns its
    Permissions). If impossible state somehow reaches evaluation, the
    evaluator fails closed by raising a narrow internal error instead of
    guessing an ALLOW.
    """


class PermissionEvaluator(PermissionEvaluatorProtocol):
    """Pure Python policy-resolution engine (evaluate only; retrieve nothing).

    This implementation is the semantic reference/oracle for the whole
    policy-evaluation surface: every
    :class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`
    decision is differentially tested against this one. It consumes an
    exact Action and already-applicable Roles, reuses PR 3 matching,
    and never retrieves authorization context.
    """

    def evaluate(self, action: Action, roles: Iterable[Role]) -> AuthorizationDecision:
        """Decide one exact Action against caller-supplied applicable Roles.

        Selection order:

        1. every matching Permission in every PermissionSet of every
           supplied Role is considered;
        2. only the most-specific matches survive;
        3. among equally specific survivors, any DENY wins, else any
           ALLOW wins;
        4. no match means DENY.

        Role order, PermissionSet order, Permission order, and input
        order never affect the result, and duplicate matches never
        create additional authority.

        :raises PermissionEvaluationError: if structurally corrupted
            policy (impossible under PR 3 construction) is supplied.
        """
        highest: MatchSpecificity | None = None
        allow_at_highest = False
        deny_at_highest = False
        for role in roles:
            for permission_set in role.permission_sets:
                if permission_set.role_urn != role.urn:
                    raise PermissionEvaluationError(
                        f"PermissionSet {permission_set.id} is owned by "
                        f"{permission_set.role_urn}, not by supplied Role {role.urn}"
                    )
                for permission in permission_set.permissions:
                    match = match_permission(permission, action)
                    specificity = match.specificity
                    if specificity is None:
                        continue
                    if highest is None or specificity.is_more_specific_than(highest):
                        highest = specificity
                        allow_at_highest = permission_set.effect is PermissionEffect.ALLOW
                        deny_at_highest = permission_set.effect is PermissionEffect.DENY
                    elif specificity is highest:
                        if permission_set.effect is PermissionEffect.ALLOW:
                            allow_at_highest = True
                        else:
                            deny_at_highest = True
        if highest is None:
            return AuthorizationDecision.deny(DenyReason.NO_MATCH)
        if deny_at_highest:
            return AuthorizationDecision.deny(
                DenyReason.MATCHED_DENY,
                matched_specificity=highest,
                matched_allow=allow_at_highest,
                matched_deny=True,
            )
        if allow_at_highest:
            return AuthorizationDecision.allow(
                matched_specificity=highest,
                matched_allow=True,
                matched_deny=False,
            )
        raise PermissionEvaluationError(
            "matching PermissionSet carries neither ALLOW nor DENY; corrupt policy state"
        )
