"""Permission: a PermissionSet-owned Action matcher."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from mtmf_core.domain.iam_urn import PermissionUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.mixins import ImmutableFieldGuard


@dataclass(slots=True)
class Permission(ImmutableFieldGuard):
    """A PermissionSet-owned Action matcher.

    The immutable :attr:`id` is the Permission object's UUID object
    identity; the immutable matcher :attr:`urn` describes which Actions
    this Permission matches (exactly, or through the complete qualifier
    ``*`` wildcard).

    A Permission has no effect independently of its PermissionSet, no
    extension, no Role assignment, and no security scope. Distinct
    Permission objects MAY carry the same Permission URN: the URN is
    matcher semantics, not object identity.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"id", "permission_set_id", "urn"})

    id: DomainId
    permission_set_id: DomainId
    urn: PermissionUrn
