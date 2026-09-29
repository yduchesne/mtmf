"""Shared test bootstrap: make the core test helpers importable everywhere.

Existing core tests import ``helpers`` through pytest's per-directory
sys.path insertion for ``tests/unit/core``. Newer suites (for example
``tests/unit/authorization``) reuse the same helpers, so the containing
directory is registered here. This adds no tests and changes no behavior
for existing suites.
"""

from __future__ import annotations

import sys
from pathlib import Path

_CORE_TEST_DIR = Path(__file__).resolve().parent / "core"
if str(_CORE_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_TEST_DIR))
