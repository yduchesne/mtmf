"""Security scope enum from the authoritative security model.

The numeric ordering exists to support privilege/protection comparisons.
It MUST NOT by itself imply authorization rules: permission, dominance,
membership, and operation-specific constraints are evaluated separately.
"""

from __future__ import annotations

from enum import IntEnum


class SecurityScope(IntEnum):
    """The exact MTMF privilege/protection scope hierarchy.

    A smaller numeric value represents a broader and more privileged
    scope. The values are part of the documented contract and MUST NOT
    be reordered or renumbered.
    """

    ROOT = 0
    SYSTEM = 1
    TENANT = 2
    ORGANIZATION = 3
