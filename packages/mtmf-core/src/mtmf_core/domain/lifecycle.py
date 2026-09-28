"""Exact lifecycle enums from the authoritative domain model.

Soft deletion and active/inactive state are independent lifecycle
dimensions. The numeric values are part of the documented contract and
MUST NOT be reordered or renumbered.
"""

from __future__ import annotations

from enum import IntEnum


class DeletionStatus(IntEnum):
    """Soft-deletion state for domain objects.

    ``DeletionStatus`` is NOT Boolean truthiness; application code must
    compare enum members rather than interpret deletion through truthy
    evaluation.
    """

    DELETED = 1
    NOT_DELETED = 2


class ActiveStatus(IntEnum):
    """Active/inactive lifecycle state where the domain supports it."""

    INACTIVE = 0
    ACTIVE = 1
