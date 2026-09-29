"""Packaged versioned SQL resources owned by MTMF.

Each directory (``v001``, ...) holds immutable, reviewable SQL files
installed by an Alembic migration in sorted filename order. Function
semantics must not be silently edited inside a shipped version; change
the schema or add a new version instead.
"""

from __future__ import annotations
