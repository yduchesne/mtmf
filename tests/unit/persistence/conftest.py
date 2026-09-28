"""Shared fixtures for the persistence contract suites.

The ``spi`` fixture is the single provider seam used by every contract
test: a later PR adding the PostgreSQL provider can supply it through
the same fixture so these suites run unchanged against the new provider.
"""

from __future__ import annotations

import pytest

from mtmf_core.persistence import MtmfSpi
from mtmf_core.persistence.testing import InMemoryMtmfSpi


@pytest.fixture
def spi() -> MtmfSpi:
    """A fresh in-memory persistence provider instance per test."""
    return InMemoryMtmfSpi()
