"""Permission-to-Action matching and specificity tests."""

from helpers import make_action_urn, make_permission, make_permission_urn

from mtmf_core import (
    NO_MATCH,
    Action,
    MatchResult,
    MatchSpecificity,
    match_permission,
    match_permission_urn,
)


def test_exact_permission_match_is_exact() -> None:
    permission = make_permission_urn(verb="set", qualifier="alias")
    action = make_action_urn(verb="set", qualifier="alias")
    result = match_permission_urn(permission, action)
    assert result.matched
    assert result.specificity is MatchSpecificity.EXACT


def test_wildcard_permission_match_is_qualifier_wildcard() -> None:
    permission = make_permission_urn(verb="set", qualifier="*")
    action = make_action_urn(verb="set", qualifier="alias")
    result = match_permission_urn(permission, action)
    assert result.matched
    assert result.specificity is MatchSpecificity.QUALIFIER_WILDCARD


def test_wildcard_matches_any_qualifier_of_same_verb() -> None:
    wildcard = make_permission_urn(verb="set", qualifier="*")
    set_active = make_action_urn(verb="set", qualifier="active")
    set_alias = make_action_urn(verb="set", qualifier="alias")
    assert match_permission_urn(wildcard, set_active).matched
    assert match_permission_urn(wildcard, set_alias).matched


def test_wildcard_does_not_match_different_verb() -> None:
    wildcard = make_permission_urn(verb="set", qualifier="*")
    delete_object = make_action_urn(verb="delete", qualifier="object")
    result = match_permission_urn(wildcard, delete_object)
    assert not result.matched
    assert result == NO_MATCH


def test_wildcard_does_not_match_different_resource() -> None:
    wildcard = make_permission_urn(resource="principal", verb="set", qualifier="*")
    tenant_set = make_action_urn(resource="tenant", verb="set", qualifier="active")
    assert not match_permission_urn(wildcard, tenant_set).matched


def test_exact_does_not_match_different_qualifier() -> None:
    exact = make_permission_urn(verb="set", qualifier="alias")
    set_active = make_action_urn(verb="set", qualifier="active")
    assert not match_permission_urn(exact, set_active).matched


def test_exact_is_more_specific_than_wildcard() -> None:
    assert MatchSpecificity.EXACT.is_more_specific_than(MatchSpecificity.QUALIFIER_WILDCARD)
    assert not MatchSpecificity.QUALIFIER_WILDCARD.is_more_specific_than(MatchSpecificity.EXACT)
    assert not MatchSpecificity.EXACT.is_more_specific_than(MatchSpecificity.EXACT)
    assert not MatchSpecificity.QUALIFIER_WILDCARD.is_more_specific_than(
        MatchSpecificity.QUALIFIER_WILDCARD
    )


def test_specificity_classes_are_exactly_two() -> None:
    assert {member.name for member in MatchSpecificity} == {
        "QUALIFIER_WILDCARD",
        "EXACT",
    }


def test_matcher_result_contains_no_effect_or_decision() -> None:
    result = match_permission_urn(
        make_permission_urn(verb="set", qualifier="*"),
        make_action_urn(verb="set", qualifier="active"),
    )
    assert isinstance(result, MatchResult)
    for absent in ("effect", "allow", "deny", "decision", "role_urn"):
        assert not hasattr(result, absent)
        assert absent not in MatchResult.__dataclass_fields__


def test_match_is_deterministic_and_side_effect_free() -> None:
    permission = make_permission_urn(verb="set", qualifier="*")
    action = make_action_urn(verb="set", qualifier="active")
    first = match_permission_urn(permission, action)
    second = match_permission_urn(permission, action)
    assert first == second
    # NO_MATCH is the single non-match value.
    assert MatchResult(specificity=None) == NO_MATCH
    assert not NO_MATCH.matched


def test_match_never_returns_allow_or_deny() -> None:
    permission = make_permission_urn(verb="set", qualifier="*")
    action = make_action_urn(verb="set", qualifier="active")
    result = match_permission_urn(permission, action)
    assert not hasattr(result, "effect")
    assert result.specificity is MatchSpecificity.QUALIFIER_WILDCARD


def test_object_level_matcher_delegates() -> None:
    permission = make_permission(verb="set", qualifier="alias")
    action = Action(make_action_urn(verb="set", qualifier="alias"))
    result = match_permission(permission, action)
    assert result.matched
    assert result.specificity is MatchSpecificity.EXACT


def test_list_order_creates_no_precedence() -> None:
    # Matching is defined per single Permission against a single Action:
    # there is no list, no first-match, and no order-aware selection in
    # this PR. Two Permissions in any structural order still produce the
    # same individual matcher facts.
    wildcard = make_permission_urn(verb="set", qualifier="*")
    exact = make_permission_urn(verb="set", qualifier="alias")
    action = make_action_urn(verb="set", qualifier="alias")
    assert match_permission_urn(exact, action).specificity is MatchSpecificity.EXACT
    assert match_permission_urn(wildcard, action).specificity is MatchSpecificity.QUALIFIER_WILDCARD
    # Re-evaluating in either order changes nothing.
    assert match_permission_urn(wildcard, action) == match_permission_urn(wildcard, action)
    assert match_permission_urn(exact, action) == match_permission_urn(exact, action)
