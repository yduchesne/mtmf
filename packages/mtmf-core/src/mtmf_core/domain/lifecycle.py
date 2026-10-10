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


class IdentityOrigin(IntEnum):
    """Explicit, immutable classification of an Identity's origin (PR 10).

    ``LOCAL`` and ``FEDERATED`` are the only legal values; there is
    deliberately no ``UNKNOWN``. The value is a stable identity attribute
    and MUST NOT be inferred from a name, email, Identity UUID, issuer
    text, or external-login availability. It is classification only: it is
    not a password store, an authentication implementation, or evidence
    that a human can sign in. The numeric values are part of the
    documented contract and MUST NOT be reordered or renumbered.
    """

    LOCAL = 1
    FEDERATED = 2


class TenantLifecycle(IntEnum):
    """Explicit ordinary-Tenant lifecycle, independent of soft deletion (PR 10).

    ``PROVISIONING`` and ``SUSPENDED`` Tenants are non-authorizing; only
    ``ACTIVE`` Tenants can admit ordinary sessions. The root Tenant is
    established ``ACTIVE`` by protected bootstrap and can never be
    suspended or demoted. The numeric values are part of the documented
    contract and MUST NOT be reordered or renumbered.
    """

    PROVISIONING = 0
    ACTIVE = 1
    SUSPENDED = 2
