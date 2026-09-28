"""Deterministic Permission-to-Action matching.

These primitives answer a single question: does one owned Permission
matcher match one exact Action, and with which specificity? They do not
authorize: no effect is returned, no aggregate selection happens, and no
list ordering is ever consulted. Aggregate resolution, equal-specificity
DENY precedence, and default-deny decisions belong to later PRs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from mtmf_core.domain.action import Action
from mtmf_core.domain.iam_urn import ActionUrn, PermissionUrn
from mtmf_core.domain.permission import Permission


class MatchSpecificity(Enum):
    """The two specificity classes defined by the model.

    :attr:`EXACT` is more specific than :attr:`QUALIFIER_WILDCARD`.
    There is no DENY precedence here.
    """

    QUALIFIER_WILDCARD = "qualifier-wildcard"
    EXACT = "exact"

    def is_more_specific_than(self, other: MatchSpecificity) -> bool:
        """Return whether this specificity is strictly more specific.

        The model defines exactly one documented ordering: EXACT is more
        specific than QUALIFIER_WILDCARD.
        """
        return self is MatchSpecificity.EXACT and other is MatchSpecificity.QUALIFIER_WILDCARD


@dataclass(frozen=True, slots=True)
class MatchResult:
    """The deterministic result of matching one Permission against one Action.

    :attr:`specificity` is set exactly when the matcher matches; a
    result with no specificity is a non-match. The result never carries
    an effect or an authorization decision.
    """

    specificity: MatchSpecificity | None = None

    @property
    def matched(self) -> bool:
        """True when the Permission matcher matched the Action."""
        return self.specificity is not None


NO_MATCH = MatchResult(specificity=None)


def match_permission_urn(permission_urn: PermissionUrn, action_urn: ActionUrn) -> MatchResult:
    """Match one Permission matcher URN against one exact Action URN.

    The comparison covers the security-relevant parsed fields: the
    definition namespace, resource, verb, and qualifier. Cross-namespace
    matching is never permitted. A wildcard Permission matches any exact
    qualifier of the same resource and verb; anything else must match
    exactly.

    The function is deterministic and side-effect-free.
    """
    if permission_urn.definition_namespace is not action_urn.definition_namespace:
        return NO_MATCH
    if permission_urn.resource != action_urn.resource:
        return NO_MATCH
    if permission_urn.verb != action_urn.verb:
        return NO_MATCH
    if permission_urn.is_wildcard:
        return MatchResult(specificity=MatchSpecificity.QUALIFIER_WILDCARD)
    if permission_urn.qualifier == action_urn.qualifier:
        return MatchResult(specificity=MatchSpecificity.EXACT)
    return NO_MATCH


def match_permission(permission: Permission, action: Action) -> MatchResult:
    """Match an owned Permission object against an Action object.

    Delegates to :func:`match_permission_urn` on the immutable parsed
    URNs; the owned objects contribute no decision state.
    """
    return match_permission_urn(permission.urn, action.urn)
