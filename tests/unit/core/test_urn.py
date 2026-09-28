"""Unit tests for the foundational URN value type."""

from dataclasses import FrozenInstanceError

import pytest

from mtmf_core.domain import Urn


def test_valid_urn_created_and_preserved() -> None:
    canon = "urn:mtmf:role:system.admin"
    urn = Urn(canon)
    assert urn.value == canon
    assert str(urn) == canon


def test_empty_urn_rejected() -> None:
    with pytest.raises(ValueError):
        Urn("")


def test_obviously_malformed_non_urn_rejected() -> None:
    with pytest.raises(ValueError):
        Urn("just-a-string")
    with pytest.raises(ValueError):
        Urn("https://example.com/role")


def test_missing_namespace_identifier_rejected() -> None:
    with pytest.raises(ValueError):
        Urn("urn::role:system.admin")


def test_missing_namespace_specific_string_rejected() -> None:
    with pytest.raises(ValueError):
        Urn("urn:mtmf:")


def test_missing_colon_separator_rejected() -> None:
    with pytest.raises(ValueError):
        Urn("urn:mtmf-role")


def test_whitespace_padded_urn_rejected() -> None:
    with pytest.raises(ValueError):
        Urn("urn:mtmf:role:system.admin ")


def test_same_urn_values_equal_and_hash_equally() -> None:
    canon = "urn:mtmf:action:data.read"
    assert Urn(canon) == Urn(canon)
    assert hash(Urn(canon)) == hash(Urn(canon))


def test_different_urn_values_are_unequal() -> None:
    assert Urn("urn:mtmf:role:a") != Urn("urn:mtmf:role:b")


def test_urn_is_immutable() -> None:
    urn = Urn("urn:mtmf:role:a")
    with pytest.raises(FrozenInstanceError):
        urn.value = "urn:mtmf:role:b"  # type: ignore[misc]
