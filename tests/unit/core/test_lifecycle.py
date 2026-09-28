"""Unit tests for the exact lifecycle enums."""

from mtmf_core.domain import ActiveStatus, DeletionStatus


def test_deleted_exact_integer_value() -> None:
    assert DeletionStatus.DELETED.value == 1
    assert int(DeletionStatus.DELETED) == 1


def test_not_deleted_exact_integer_value() -> None:
    assert DeletionStatus.NOT_DELETED.value == 2
    assert int(DeletionStatus.NOT_DELETED) == 2


def test_inactive_exact_integer_value() -> None:
    assert ActiveStatus.INACTIVE.value == 0
    assert int(ActiveStatus.INACTIVE) == 0


def test_active_exact_integer_value() -> None:
    assert ActiveStatus.ACTIVE.value == 1
    assert int(ActiveStatus.ACTIVE) == 1


def test_deletion_status_is_not_boolean_truthiness() -> None:
    # Application code must compare enum members; DELETED must not be
    # treated as falsy simply because it is a "negative" state.
    assert DeletionStatus.DELETED
    assert DeletionStatus.NOT_DELETED
    assert bool(DeletionStatus.DELETED) == bool(DeletionStatus.NOT_DELETED)


def test_int_enum_values_map_to_exact_members() -> None:
    assert DeletionStatus(1) is DeletionStatus.DELETED
    assert DeletionStatus(2) is DeletionStatus.NOT_DELETED
    assert ActiveStatus(0) is ActiveStatus.INACTIVE
    assert ActiveStatus(1) is ActiveStatus.ACTIVE
