"""PermissionSet domain object tests: effect, ownership, ordering, cardinality."""

import pytest
from helpers import make_permission, make_permission_set, make_role_urn

from mtmf_core import (
    DomainId,
    DomainInvariantError,
    ImmutabilityError,
    PermissionEffect,
    PermissionSet,
)


def test_allow_effect_permission_set_valid() -> None:
    permission_set = make_permission_set(effect=PermissionEffect.ALLOW)
    assert permission_set.effect is PermissionEffect.ALLOW
    assert len(permission_set.permissions) == 1


def test_deny_effect_permission_set_valid() -> None:
    permission_set = make_permission_set(effect=PermissionEffect.DENY)
    assert permission_set.effect is PermissionEffect.DENY


def test_effect_has_only_allow_and_deny() -> None:
    assert {member.name for member in PermissionEffect} == {"ALLOW", "DENY"}


def test_effect_is_not_numeric() -> None:
    # No numeric encoding exists from which precedence could be derived.
    assert not isinstance(PermissionEffect.ALLOW, int)
    assert not isinstance(PermissionEffect.DENY, int)
    assert PermissionEffect.ALLOW.value == "allow"
    assert PermissionEffect.DENY.value == "deny"


def test_permission_set_uuid_immutable() -> None:
    permission_set = make_permission_set()
    with pytest.raises(ImmutabilityError):
        permission_set.id = DomainId.generate()  # type: ignore[misc]


def test_permission_set_role_urn_immutable() -> None:
    permission_set = make_permission_set()
    with pytest.raises(ImmutabilityError):
        permission_set.role_urn = make_role_urn(role_name="other")  # type: ignore[misc]


def test_permission_set_effect_immutable() -> None:
    permission_set = make_permission_set()
    with pytest.raises(ImmutabilityError):
        permission_set.effect = PermissionEffect.DENY  # type: ignore[misc]


def test_effect_belongs_to_permission_set_not_permission() -> None:
    permission_set = make_permission_set(effect=PermissionEffect.ALLOW)
    for permission in permission_set.permissions:
        assert not hasattr(permission, "effect")
    assert permission_set.effect is PermissionEffect.ALLOW


def test_ordered_permissions_preserved() -> None:
    set_id = DomainId.generate()
    first = make_permission(permission_set_id=set_id, qualifier="alias")
    second = make_permission(permission_set_id=set_id, qualifier="active")
    third = make_permission(permission_set_id=set_id, qualifier="*")
    permission_set = PermissionSet(
        set_id,
        make_role_urn(),
        PermissionEffect.ALLOW,
        (first, second, third),
    )
    assert permission_set.permissions == (first, second, third)
    # structural order is preserved exactly as given
    assert [permission.urn.qualifier for permission in permission_set.permissions] == [
        "alias",
        "active",
        "*",
    ]


def test_permission_owner_matches_set_is_valid() -> None:
    set_id = DomainId.generate()
    permission = make_permission(permission_set_id=set_id)
    permission_set = PermissionSet(set_id, make_role_urn(), PermissionEffect.ALLOW, (permission,))
    assert permission_set.permissions[0] is permission


def test_permission_owner_mismatch_rejected() -> None:
    set_id = DomainId.generate()
    foreign = make_permission(permission_set_id=DomainId.generate())
    with pytest.raises(DomainInvariantError):
        PermissionSet(set_id, make_role_urn(), PermissionEffect.ALLOW, (foreign,))


def test_empty_permission_set_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionSet(DomainId.generate(), make_role_urn(), PermissionEffect.ALLOW, ())


def test_permission_set_has_no_name_description_or_extension() -> None:
    permission_set = make_permission_set()
    for absent in ("name", "description", "extension", "scope"):
        assert not hasattr(permission_set, absent)
        assert absent not in PermissionSet.__dataclass_fields__
