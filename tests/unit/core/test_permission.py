"""Permission domain object tests: identity, ownership, and scope limits."""

import pytest
from helpers import make_permission, make_permission_urn, make_role_urn

from mtmf_core import (
    DomainId,
    DomainInvariantError,
    ImmutabilityError,
    Permission,
    PermissionEffect,
    PermissionSet,
    PermissionUrn,
)


def test_permission_carries_uuid_owner_and_matcher_urn() -> None:
    owner = DomainId.generate()
    permission = Permission(
        DomainId.generate(), owner, make_permission_urn(verb="set", qualifier="alias")
    )
    assert isinstance(permission.id, DomainId)
    assert permission.permission_set_id == owner
    assert isinstance(permission.urn, PermissionUrn)


def test_duplicate_matcher_urn_on_distinct_uuids_is_valid() -> None:
    same_matcher = make_permission_urn(verb="set", qualifier="*")
    permission_one = Permission(DomainId.generate(), DomainId.generate(), same_matcher)
    permission_two = Permission(DomainId.generate(), DomainId.generate(), same_matcher)
    assert permission_one.id != permission_two.id
    assert permission_one.urn == permission_two.urn


def test_permission_uuid_immutable() -> None:
    permission = make_permission()
    with pytest.raises(ImmutabilityError):
        permission.id = DomainId.generate()  # type: ignore[misc]


def test_permission_owner_immutable() -> None:
    permission = make_permission()
    with pytest.raises(ImmutabilityError):
        permission.permission_set_id = DomainId.generate()  # type: ignore[misc]


def test_permission_matcher_urn_immutable() -> None:
    permission = make_permission()
    with pytest.raises(ImmutabilityError):
        permission.urn = make_permission_urn(verb="delete")  # type: ignore[misc]


def test_permission_has_no_independent_effect() -> None:
    permission = make_permission()
    assert not hasattr(permission, "effect")
    assert "effect" not in Permission.__dataclass_fields__


def test_permission_has_no_extension() -> None:
    permission = make_permission()
    assert not hasattr(permission, "extension")
    assert "extension" not in Permission.__dataclass_fields__


def test_permission_has_no_scope_nor_assignment_state() -> None:
    permission = make_permission()
    for absent in ("scope", "role_urn", "assignment", "identity_id"):
        assert not hasattr(permission, absent)
        assert absent not in Permission.__dataclass_fields__


def test_wildcard_permission_set_can_own_distinct_uuid_permissions() -> None:
    wildcard = make_permission_urn(verb="set", qualifier="*")
    set_id = DomainId.generate()
    permission_set = PermissionSet(
        set_id,
        make_role_urn(),
        PermissionEffect.ALLOW,
        (
            Permission(DomainId.generate(), set_id, wildcard),
            Permission(DomainId.generate(), set_id, wildcard),
        ),
    )
    assert len(permission_set.permissions) == 2
    assert permission_set.permissions[0].urn == permission_set.permissions[1].urn


def test_malformed_permission_urn_fails_at_construction() -> None:
    with pytest.raises(DomainInvariantError):
        PermissionUrn("urn:mtmf:iam:permissions:system:principal:set")
