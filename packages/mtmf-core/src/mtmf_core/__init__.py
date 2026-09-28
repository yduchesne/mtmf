"""MTMF core framework package."""

from __future__ import annotations

from mtmf_core.domain import (
    ActiveStatus,
    DeletionStatus,
    DomainId,
    JsonObject,
    JsonScalar,
    JsonValue,
    Urn,
    new_extension,
)

__all__ = [
    "ActiveStatus",
    "DeletionStatus",
    "DomainId",
    "JsonObject",
    "JsonScalar",
    "JsonValue",
    "Urn",
    "new_extension",
]
