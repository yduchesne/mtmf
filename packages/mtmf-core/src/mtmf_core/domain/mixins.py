"""Small plain-Python building blocks shared by core domain entities.

These mixins deliberately do not form a generic enterprise entity
framework: they only express the immutability and lifecycle mechanics
required by the settled domain model.
"""

from __future__ import annotations

from typing import ClassVar

from mtmf_core.domain.errors import DomainInvariantError, ImmutabilityError
from mtmf_core.domain.lifecycle import DeletionStatus

_MISSING = object()


class ImmutableFieldGuard:
    """Protect immutable identity/provenance fields from replacement.

    Subclasses declare ``_immutable_fields``; a listed field may be
    assigned exactly once, during construction. Any later replacement
    raises :class:`ImmutabilityError`. Documented mutable state (names,
    deletion status, extension data) remains fully assignable.

    The guard prevents casual re-parenting and identity swaps without
    globally freezing objects in ways that would block legitimate
    mutation of presentation metadata.
    """

    __slots__ = ()

    _immutable_fields: ClassVar[frozenset[str]] = frozenset()

    def __setattr__(self, name: str, value: object) -> None:
        if name in type(self)._immutable_fields and getattr(self, name, _MISSING) is not _MISSING:
            raise ImmutabilityError(
                f"{type(self).__name__}.{name} is immutable and cannot be replaced"
            )
        object.__setattr__(self, name, value)


class SoftDeletableMixin:
    """Soft-deletion behavior shared by deletable MTMF entities.

    Reuses :class:`DeletionStatus` verbatim. Soft deletion preserves
    stable identity and provenance. Restoration is deliberately absent.
    """

    # Declared for typing and storage. Each concrete @dataclass also
    # declares the real field, which maps onto this inherited slot.
    deletion_status: DeletionStatus
    __slots__ = ("deletion_status",)

    @property
    def deleted(self) -> bool:
        """True when the object is soft-deleted (explicit comparison)."""
        return self.deletion_status is DeletionStatus.DELETED

    def soft_delete(self) -> None:
        """Transition deletion status to :attr:`DeletionStatus.DELETED`.

        Identity, provenance, and extension data are preserved.

        :raises DomainInvariantError: if already DELETED; both
            restoration and re-deletion are absent.
        """
        if self.deletion_status is DeletionStatus.DELETED:
            raise DomainInvariantError(f"{type(self).__name__} is already soft-deleted")
        self.deletion_status = DeletionStatus.DELETED
