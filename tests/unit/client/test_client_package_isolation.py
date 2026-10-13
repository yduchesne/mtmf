"""Package isolation and dependency-boundary tests (plan matrix CL-U01)."""

from __future__ import annotations

import subprocess
import sys
from importlib.metadata import requires
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]

_SUBMODULES = (
    "mtmf_client",
    "mtmf_client.client",
    "mtmf_client.config",
    "mtmf_client.credentials",
    "mtmf_client.errors",
    "mtmf_client.snapshot",
    "mtmf_client.transport",
)

_BANNED = (
    "mtmf_core",
    "mtmf_service",
    "fastapi",
    "uvicorn",
    "starlette",
    "pydantic",
    "psycopg",
    "alembic",
    "sqlalchemy",
    "jwt",
    "_mtmf_permission_engine",
)


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_cl_u01_import_graph_has_no_forbidden_dependencies() -> None:
    code = (
        "import importlib, sys\n"
        f"for name in {_SUBMODULES!r}:\n"
        "    importlib.import_module(name)\n"
        f"banned = {_BANNED!r}\n"
        "loaded = [name for name in banned if name in sys.modules]\n"
        "if loaded:\n"
        "    raise SystemExit(f'forbidden imports: {loaded}')\n"
    )
    result = _run(code)
    assert result.returncode == 0, result.stderr


def test_cl_u01_dependency_metadata_is_http_only() -> None:
    requirements = requires("mtmf-client")
    assert requirements is not None
    names: set[str] = set()
    for item in requirements:
        base = item.split(";", 1)[0].strip()
        for separator in ("==", ">=", "<=", "~=", "<", ">"):
            base = base.split(separator, 1)[0]
        names.add(base.strip())
    assert names == {"mtmf-api", "httpx"}, names
