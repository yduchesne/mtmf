"""Action domain object tests: exactness, typed boundary, and scope limits."""

import importlib

import pytest
from helpers import make_action_urn

from mtmf_core import (
    BASELINE_ACTIONS,
    Action,
    ActionUrn,
    DomainInvariantError,
    ImmutabilityError,
)


def test_action_wraps_exact_action_urn() -> None:
    action_urn = make_action_urn(resource="tenant", verb="set", qualifier="active")
    action = Action(action_urn)
    assert action.urn is action_urn


def test_action_wildcard_cannot_be_constructed() -> None:
    # The typed boundary is enforced at URN construction time.
    with pytest.raises(DomainInvariantError):
        ActionUrn("urn:mtmf:iam:actions:system:principal:set-*")


def test_action_urn_immutable() -> None:
    action = Action(make_action_urn())
    with pytest.raises(ImmutabilityError):
        action.urn = make_action_urn(verb="delete")  # type: ignore[misc]


def test_action_has_no_effect() -> None:
    action = Action(make_action_urn())
    assert not hasattr(action, "effect")
    assert "effect" not in Action.__dataclass_fields__


def test_action_has_no_scope_or_ownership_state() -> None:
    action = Action(make_action_urn())
    for absent in ("scope", "role_urn", "permission_set_id", "assignment"):
        assert not hasattr(action, absent)
        assert absent not in Action.__dataclass_fields__


def test_action_fields_are_only_urn() -> None:
    assert "urn" in Action.__dataclass_fields__
    assert set(Action.__dataclass_fields__) - {"urn", "_immutable_fields"} == set()


def test_baseline_actions_cover_documented_examples() -> None:
    assert len(BASELINE_ACTIONS) == 17
    assert BASELINE_ACTIONS[0] == ActionUrn("urn:mtmf:iam:actions:system:principal:create-object")
    assert BASELINE_ACTIONS[-1] == ActionUrn(
        "urn:mtmf:iam:actions:system:tenant:transfer-stewardship"
    )
    assert all(isinstance(urn, ActionUrn) for urn in BASELINE_ACTIONS)


def test_baseline_catalog_makes_no_completeness_claim() -> None:
    # The foundation is explicitly documented as non-exhaustive: the
    # complete Action catalog is unresolved.
    action_module = importlib.import_module("mtmf_core.domain.action")
    doc = (action_module.__doc__ or "").lower().replace("\n", " ")
    assert "not an exhaustive action catalog" in doc


def test_no_builtin_role_policy_mapping_exists() -> None:
    action_module = importlib.import_module("mtmf_core.domain.action")
    for name in ("BUILTIN_ROLE_POLICY", "ROLE_POLICY", "ROLE_PERMISSION_MAP"):
        assert not hasattr(action_module, name)
