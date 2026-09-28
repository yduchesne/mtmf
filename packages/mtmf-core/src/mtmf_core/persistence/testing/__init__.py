"""Deterministic in-memory persistence provider for contract tests.

``InMemoryMtmfSpi`` is a test/internal provider that validates the
:class:`~mtmf_core.persistence.spi.MtmfSpi` contracts (UnitOfWork
lifecycle, transaction isolation, multi-repository atomicity, duplicate
identity handling, detached snapshots) without introducing PostgreSQL
mechanics. It is not a production persistence provider.
"""

from __future__ import annotations

from mtmf_core.persistence.testing.in_memory import InMemoryMtmfSpi

__all__ = ["InMemoryMtmfSpi"]
