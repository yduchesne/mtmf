"""PR 14 authentication binding domain value objects.

Two explicit, tenant-independent binding facts (never a polymorphic
``(subject_type, subject_id)`` model):

- :class:`ServiceCredentialBinding` — immutable ``(issuer, client_id)`` maps
  to exactly one registered Application.
- :class:`ExternalSubjectBinding` — immutable ``(issuer, subject)`` maps to
  exactly one MTMF Identity.

Semantic keys and targets are immutable provenance; only the documented
lifecycle may change, and only through operator/installation-only
persistence functions. These objects confer no authority by themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum

from mtmf_core.domain.identity import DomainId

__all__ = [
    "BindingLifecycle",
    "ExternalSubjectBinding",
    "RootRegistryRecord",
    "ServiceCredentialBinding",
]


class BindingLifecycle(IntEnum):
    """Lifecycle of one authentication binding.

    ``REVOKED`` is terminal: a revoked binding is never reactivated. The
    numeric values are part of the documented contract and MUST NOT be
    reordered or renumbered.
    """

    ACTIVE = 1
    REVOKED = 2


def _require_aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True, slots=True)
class ServiceCredentialBinding:
    """Immutable ``(issuer, client_id)`` to one Application binding."""

    id: DomainId
    issuer: str
    client_id: str
    application_id: DomainId
    created_at: datetime
    lifecycle: BindingLifecycle = BindingLifecycle.ACTIVE

    def __post_init__(self) -> None:
        if not self.issuer or not self.client_id:
            raise ValueError("issuer and client_id are required")
        _require_aware(self.created_at, "created_at")

    @property
    def is_active(self) -> bool:
        """Whether the binding currently admits verification."""
        return self.lifecycle is BindingLifecycle.ACTIVE


@dataclass(frozen=True, slots=True)
class ExternalSubjectBinding:
    """Immutable ``(issuer, subject)`` to one MTMF Identity binding."""

    id: DomainId
    issuer: str
    subject: str
    identity_id: DomainId
    created_at: datetime
    lifecycle: BindingLifecycle = BindingLifecycle.ACTIVE

    def __post_init__(self) -> None:
        if not self.issuer or not self.subject:
            raise ValueError("issuer and subject are required")
        _require_aware(self.created_at, "created_at")

    @property
    def is_active(self) -> bool:
        """Whether the binding currently admits verification."""
        return self.lifecycle is BindingLifecycle.ACTIVE


@dataclass(frozen=True, slots=True)
class RootRegistryRecord:
    """The protected canonical root registry identifiers (read-only)."""

    root_tenant_id: DomainId
    root_principal_id: DomainId
    root_identity_id: DomainId
