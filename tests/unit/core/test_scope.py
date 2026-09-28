"""Unit tests for the exact SecurityScope enum (U01)."""

from mtmf_core.domain import SecurityScope


def test_exact_integer_values() -> None:
    assert SecurityScope.ROOT.value == 0
    assert SecurityScope.SYSTEM.value == 1
    assert SecurityScope.TENANT.value == 2
    assert SecurityScope.ORGANIZATION.value == 3


def test_int_mapping_round_trip() -> None:
    assert SecurityScope(0) is SecurityScope.ROOT
    assert SecurityScope(1) is SecurityScope.SYSTEM
    assert SecurityScope(2) is SecurityScope.TENANT
    assert SecurityScope(3) is SecurityScope.ORGANIZATION


def test_members_are_ordered_broad_to_narrow() -> None:
    assert (
        SecurityScope.ROOT
        < SecurityScope.SYSTEM
        < SecurityScope.TENANT
        < SecurityScope.ORGANIZATION
    )


def test_exactly_four_scope_members() -> None:
    assert set(SecurityScope) == {
        SecurityScope.ROOT,
        SecurityScope.SYSTEM,
        SecurityScope.TENANT,
        SecurityScope.ORGANIZATION,
    }


def test_enum_type_is_int_enum() -> None:
    # Numeric values MUST NOT imply authorization rules by themselves,
    # but they must remain comparable plain ints for later dominance logic.
    assert int(SecurityScope.TENANT) == 2
    assert SecurityScope.TENANT > 1
