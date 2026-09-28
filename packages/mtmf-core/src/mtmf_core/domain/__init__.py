"""Foundational domain primitives shared by later MTMF domain PRs."""

from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, JsonScalar, JsonValue, new_extension
from mtmf_core.domain.lifecycle import ActiveStatus, DeletionStatus
from mtmf_core.domain.urn import Urn

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
