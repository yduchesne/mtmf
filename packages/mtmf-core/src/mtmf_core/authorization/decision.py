"""Minimal internal authorization decision representation.

The exact public decision/audit record remains unresolved by the
authoritative documents. This module defines only the smallest immutable
internal representation the evaluator and the Authorizer foundation
need: an explicit ALLOW or DENY effect, coarse denial reason categories,
and narrow policy-matching evidence.

It deliberately contains no public error payload, audit-record schema,
HTTP disclosure shape, or user-facing explanation. The representation
never has an implicit/unknown state that could be treated as ALLOW: only
an explicit :attr:`AuthorizationEffect.ALLOW` yields ``allowed == True``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from mtmf_core.domain.errors import DomainInvariantError
from mtmf_core.domain.permission_matching import MatchSpecificity


class AuthorizationEffect(Enum):
    """The explicit authorization effect.

    Exactly :attr:`ALLOW` and :attr:`DENY` exist. There is no
    implicit/unknown/abstain state that could ever be treated as ALLOW.
    """

    ALLOW = "allow"
    DENY = "deny"


class DenyReason(Enum):
    """Coarse internal categories explaining a DENY.

    Categories are intentionally coarse and internal: they are not a
    public security diagnostic contract and never expose Permission or
    Role internals. ``NO_MATCH`` and ``MATCHED_DENY`` stem from policy
    evaluation; the remaining categories stem from structurally invalid
    or unsupported authorization context.
    """

    NO_MATCH = "no-match"
    MATCHED_DENY = "matched-deny"
    INVALID_CONTEXT = "invalid-context"
    TENANT_MISMATCH = "tenant-mismatch"
    NO_MANAGEMENT_SCOPE = "no-management-scope"
    INSUFFICIENT_DOMINANCE = "insufficient-dominance"
    UNSUPPORTED_CONSTRAINT = "unsupported-constraint"


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """An immutable authorization decision.

    :attr:`allowed` is ``True`` exactly when the effect is an explicit
    ALLOW. The optional matching evidence (:attr:`matched_specificity`,
    :attr:`matched_allow`, :attr:`matched_deny`) reports the most
    specific policy match and whether ALLOW/DENY was present at that
    specificity; it carries no assignment or role-identity facts. A DENY
    always carries exactly one coarse :attr:`reason`; an ALLOW never
    carries one.
    """

    effect: AuthorizationEffect
    matched_specificity: MatchSpecificity | None = None
    matched_allow: bool = False
    matched_deny: bool = False
    reason: DenyReason | None = None

    def __post_init__(self) -> None:
        if self.effect is AuthorizationEffect.ALLOW and self.reason is not None:
            raise DomainInvariantError("an ALLOW decision must not carry a deny reason")
        if self.effect is AuthorizationEffect.DENY and self.reason is None:
            raise DomainInvariantError("a DENY decision requires a deny reason")

    @property
    def allowed(self) -> bool:
        """True only for an explicit ALLOW effect."""
        return self.effect is AuthorizationEffect.ALLOW

    @classmethod
    def allow(
        cls,
        *,
        matched_specificity: MatchSpecificity | None = None,
        matched_allow: bool = False,
        matched_deny: bool = False,
    ) -> AuthorizationDecision:
        """Build an explicit ALLOW decision with optional matching evidence."""
        return cls(
            AuthorizationEffect.ALLOW,
            matched_specificity,
            matched_allow,
            matched_deny,
            None,
        )

    @classmethod
    def deny(
        cls,
        reason: DenyReason,
        *,
        matched_specificity: MatchSpecificity | None = None,
        matched_allow: bool = False,
        matched_deny: bool = False,
    ) -> AuthorizationDecision:
        """Build a DENY decision carrying one coarse internal reason."""
        return cls(
            AuthorizationEffect.DENY,
            matched_specificity,
            matched_allow,
            matched_deny,
            reason,
        )
