"""Foundational UUID object-identity value type.

Later PRs specialize this type for concrete MTMF domain entities
(Tenant, Organization, Principal, Identity, Group, PermissionSet, and
Permission). This module provides only the dependency-free foundation
those entities reuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class DomainId:
    """An immutable globally unique UUID object identifier.

    Wrapping :class:`uuid.UUID` behind a dedicated value type prevents
    accidental mixing of unrelated raw UUID fields in later domain
    entities.
    """

    value: UUID

    @classmethod
    def from_str(cls, text: str) -> DomainId:
        """Parse canonical UUID text, rejecting malformed input.

        :param text: textual UUID representation accepted by
            :class:`uuid.UUID`.
        :raises ValueError: if ``text`` is not a valid UUID.
        """
        try:
            parsed = UUID(text)
        except ValueError as exc:
            raise ValueError(f"invalid UUID text: {text!r}") from exc
        return cls(parsed)

    @classmethod
    def generate(cls) -> DomainId:
        """Create a new identifier from a random UUIDv4 value."""
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
