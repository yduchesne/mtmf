"""Tests for the minimal internal authorization decision representation."""

from dataclasses import FrozenInstanceError

import pytest

from mtmf_core import (
    AuthorizationDecision,
    AuthorizationEffect,
    DenyReason,
    DomainInvariantError,
    MatchSpecificity,
)


def test_effect_enum_has_exactly_allow_and_deny() -> None:
    assert {member.name for member in AuthorizationEffect} == {"ALLOW", "DENY"}


def test_allowed_is_true_only_for_explicit_allow() -> None:
    allowed = AuthorizationDecision.allow()
    denied = AuthorizationDecision.deny(DenyReason.NO_MATCH)
    assert allowed.effect is AuthorizationEffect.ALLOW
    assert allowed.allowed
    assert denied.effect is AuthorizationEffect.DENY
    assert not denied.allowed


def test_decision_has_no_implicit_or_unknown_state() -> None:
    assert set(AuthorizationDecision.__dataclass_fields__) == {
        "effect",
        "matched_specificity",
        "matched_allow",
        "matched_deny",
        "reason",
    }


def test_decision_carries_no_assignment_or_role_facts() -> None:
    for name in ("role", "roles", "assignment", "assignments", "permission", "identity_id"):
        assert name not in AuthorizationDecision.__dataclass_fields__


def test_allow_decision_must_not_carry_a_deny_reason() -> None:
    with pytest.raises(DomainInvariantError):
        AuthorizationDecision(AuthorizationEffect.ALLOW, None, False, False, DenyReason.NO_MATCH)


def test_deny_decision_requires_a_reason() -> None:
    with pytest.raises(DomainInvariantError):
        AuthorizationDecision(AuthorizationEffect.DENY)


def test_deny_reason_categories_are_coarse_and_internal() -> None:
    assert {member.name for member in DenyReason} == {
        "NO_MATCH",
        "MATCHED_DENY",
        "INVALID_CONTEXT",
        "TENANT_MISMATCH",
        "NO_MANAGEMENT_SCOPE",
        "INSUFFICIENT_DOMINANCE",
        "UNSUPPORTED_CONSTRAINT",
    }


def test_allow_decision_keeps_matching_evidence_only() -> None:
    decision = AuthorizationDecision.allow(
        matched_specificity=MatchSpecificity.EXACT,
        matched_allow=True,
        matched_deny=False,
    )
    assert decision.matched_specificity is MatchSpecificity.EXACT
    assert decision.matched_allow
    assert not decision.matched_deny
    assert decision.reason is None
    assert decision.allowed


def test_matched_deny_decision_keeps_evidence_and_reason() -> None:
    decision = AuthorizationDecision.deny(
        DenyReason.MATCHED_DENY,
        matched_specificity=MatchSpecificity.QUALIFIER_WILDCARD,
        matched_allow=True,
        matched_deny=True,
    )
    assert not decision.allowed
    assert decision.reason is DenyReason.MATCHED_DENY
    assert decision.matched_specificity is MatchSpecificity.QUALIFIER_WILDCARD
    assert decision.matched_allow
    assert decision.matched_deny


def test_decision_is_immutable() -> None:
    decision = AuthorizationDecision.deny(DenyReason.NO_MATCH)
    with pytest.raises(FrozenInstanceError):
        decision.effect = AuthorizationEffect.ALLOW


def test_decisions_are_value_equal() -> None:
    first = AuthorizationDecision.allow(
        matched_specificity=MatchSpecificity.EXACT,
        matched_allow=True,
        matched_deny=False,
    )
    second = AuthorizationDecision.allow(
        matched_specificity=MatchSpecificity.EXACT,
        matched_allow=True,
        matched_deny=False,
    )
    assert first == second
    assert hash(first) == hash(second)
