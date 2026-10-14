"""Immutable application-owned domain values for the reference app.

These types are the reference application's own model. They are deliberately
independent of MTMF domain objects and DTOs: the only MTMF concept the app
materializes is the wire-level ``ResourceTarget`` derived from an actual
loaded row.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

__all__ = ["Document", "FixtureMapping", "SubjectTenantBinding"]


@dataclass(frozen=True, slots=True)
class Document:
    """One Tenant-scoped Document owned by the reference application.

    ``document_id`` and ``tenant_id`` are canonical lowercase UUID strings so
    that equality and storage are byte-exact. The ``title`` and ``body`` are
    opaque application content that is disclosed only after an MTMF ``ALLOW``.
    """

    document_id: str
    tenant_id: str
    title: str
    body: str


@dataclass(frozen=True, slots=True)
class SubjectTenantBinding:
    """The server-owned mapping from a verified subject to its Tenant."""

    subject: str
    tenant_id: UUID


@dataclass(frozen=True, slots=True)
class FixtureMapping:
    """Initializer-generated, read-only subject/Application/Tenant fixture.

    The mapping is an *additional consumer-side restriction*: the reference app
    only ever builds a trusted context for a subject that appears here, and the
    Tenant is server-owned configuration rather than caller input. MTMF still
    independently verifies the propagated user token, subject binding, and
    Tenant eligibility; this map is not proof on its own.
    """

    application_id: UUID
    tenant_id: UUID
    subjects: dict[str, SubjectTenantBinding]
    version: int = 1

    def binding_for(self, subject: str) -> SubjectTenantBinding | None:
        """Return the server-owned binding for ``subject`` or ``None``."""
        return self.subjects.get(subject)
