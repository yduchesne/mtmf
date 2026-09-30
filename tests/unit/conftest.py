"""Shared test bootstrap: make the core test helpers importable everywhere.

Existing core tests import ``helpers`` through pytest's per-directory
sys.path insertion for ``tests/unit/core``. Newer suites (for example
``tests/unit/authorization``) reuse the same helpers, so the containing
directory is registered here. This adds no tests and changes no behavior
for existing suites.

The experimental compiled-policy evaluator and benchmark (PR 8G) live
under ``benchmarks/`` and are consumed by unit tests, so the benchmark
package directory is registered here too.
"""

from __future__ import annotations

import sys
from pathlib import Path

_CORE_TEST_DIR = Path(__file__).resolve().parent / "core"
if str(_CORE_TEST_DIR) not in sys.path:
    sys.path.insert(0, str(_CORE_TEST_DIR))

_BENCHMARKS_DIR = Path(__file__).resolve().parents[2] / "benchmarks"
if str(_BENCHMARKS_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCHMARKS_DIR))
