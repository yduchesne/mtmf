"""Tests for strict scope dominance (PR 4 Part 5, matrix D01-D11)."""

from mtmf_core import SecurityScope, strictly_dominates

_ROW = SecurityScope


def test_root_dominates_system_tenant_organization() -> None:
    assert strictly_dominates(_ROW.ROOT, _ROW.SYSTEM)
    assert strictly_dominates(_ROW.ROOT, _ROW.TENANT)
    assert strictly_dominates(_ROW.ROOT, _ROW.ORGANIZATION)


def test_system_never_dominates_root() -> None:
    assert not strictly_dominates(_ROW.SYSTEM, _ROW.ROOT)


def test_system_dominates_tenant_and_organization() -> None:
    assert strictly_dominates(_ROW.SYSTEM, _ROW.TENANT)
    assert strictly_dominates(_ROW.SYSTEM, _ROW.ORGANIZATION)


def test_tenant_dominates_organization() -> None:
    assert strictly_dominates(_ROW.TENANT, _ROW.ORGANIZATION)


def test_same_scope_never_dominates() -> None:
    for scope in SecurityScope:
        assert not strictly_dominates(scope, scope)


def test_organization_dominates_nothing() -> None:
    for target in SecurityScope:
        assert not strictly_dominates(_ROW.ORGANIZATION, target)


def test_full_strict_dominance_truth_table() -> None:
    expectations: dict[tuple[SecurityScope, SecurityScope], bool] = {
        (_ROW.ROOT, _ROW.ROOT): False,
        (_ROW.ROOT, _ROW.SYSTEM): True,
        (_ROW.ROOT, _ROW.TENANT): True,
        (_ROW.ROOT, _ROW.ORGANIZATION): True,
        (_ROW.SYSTEM, _ROW.ROOT): False,
        (_ROW.SYSTEM, _ROW.SYSTEM): False,
        (_ROW.SYSTEM, _ROW.TENANT): True,
        (_ROW.SYSTEM, _ROW.ORGANIZATION): True,
        (_ROW.TENANT, _ROW.ROOT): False,
        (_ROW.TENANT, _ROW.SYSTEM): False,
        (_ROW.TENANT, _ROW.TENANT): False,
        (_ROW.TENANT, _ROW.ORGANIZATION): True,
        (_ROW.ORGANIZATION, _ROW.ROOT): False,
        (_ROW.ORGANIZATION, _ROW.SYSTEM): False,
        (_ROW.ORGANIZATION, _ROW.TENANT): False,
        (_ROW.ORGANIZATION, _ROW.ORGANIZATION): False,
    }
    for subject in SecurityScope:
        for target in SecurityScope:
            assert strictly_dominates(subject, target) == expectations[(subject, target)]


def test_helper_derives_no_rule_beyond_strict_less_than() -> None:
    # The helper implements exactly the documented numeric rule; it has
    # no other state or options and cannot express alternate dominance.
    assert strictly_dominates(SecurityScope.SYSTEM, SecurityScope.TENANT) is (
        SecurityScope.SYSTEM < SecurityScope.TENANT
    )
