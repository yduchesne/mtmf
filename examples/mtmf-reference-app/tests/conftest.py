"""Ensure the example src layout is importable regardless of rootdir selection."""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
_TESTS = Path(__file__).resolve().parent
_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
for _path in (_SRC, _TESTS, _SCRIPTS):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))
