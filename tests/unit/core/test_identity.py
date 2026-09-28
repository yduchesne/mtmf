"""Unit tests for the foundational UUID object-identity type."""

from dataclasses import FrozenInstanceError
from uuid import UUID

import pytest

from mtmf_core.domain import DomainId

RAW = "12345678-1234-5678-1234-567812345678"


def test_construct_from_valid_uuid() -> None:
    raw = UUID(RAW)
    domain_id = DomainId(raw)
    assert domain_id.value == raw


def test_identity_equality_for_same_uuid() -> None:
    raw = UUID(RAW)
    assert DomainId(raw) == DomainId(raw)
    assert hash(DomainId(raw)) == hash(DomainId(raw))


def test_identity_inequality_for_different_uuids() -> None:
    first = DomainId(UUID(RAW))
    second = DomainId(UUID("87654321-4321-8765-4321-876543218765"))
    assert first != second
    assert first.value != second.value


def test_identity_canonical_string_round_trip() -> None:
    assert str(DomainId(UUID(RAW))) == RAW


def test_identity_parsing_round_trip() -> None:
    parsed = DomainId.from_str(RAW)
    assert parsed == DomainId(UUID(RAW))
    assert str(parsed) == RAW


def test_generate_returns_random_uuids() -> None:
    first = DomainId.generate()
    second = DomainId.generate()
    assert isinstance(first.value, UUID)
    assert second.value != first.value


def test_invalid_textual_uuid_rejected() -> None:
    with pytest.raises(ValueError):
        DomainId.from_str("not-a-uuid")


def test_identity_is_immutable() -> None:
    domain_id = DomainId(UUID(RAW))
    with pytest.raises(FrozenInstanceError):
        domain_id.value = UUID("87654321-4321-8765-4321-876543218765")  # type: ignore[misc]
