"""MTMF reference application (``mtmf-reference-app``).

A deliberately small, independently deployed Policy Enforcement Point (PEP)
that owns its own Document resource store, authenticates end users at its own
HTTP boundary, calls MTMF **only** through the official ``mtmf-client`` HTTP
library, and enforces the returned ``ALLOW``/``DENY`` decision against the
exact loaded resource.

This package is an example, not a framework. It imports no ``mtmf-core`` or
``mtmf-service`` code, never opens an MTMF database connection, and embeds no
policy evaluator.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
