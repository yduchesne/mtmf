"""Package isolation and packaging tests (plan matrix A24, A25)."""

from __future__ import annotations

import shutil
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

BANNED_MODULES = (
    "mtmf_core",
    "mtmf_service",
    "mtmf_client",
    "fastapi",
    "uvicorn",
    "starlette",
    "pydantic",
    "psycopg",
    "alembic",
    "sqlalchemy",
    "jwt",
    "httpx",
    "requests",
    "_mtmf_permission_engine",
)

_SUBMODULES = (
    "mtmf_api",
    "mtmf_api.authorization",
    "mtmf_api.conformance",
    "mtmf_api.errors",
    "mtmf_api.json_codec",
)

_EXERCISE = r"""
import json
from mtmf_api import parse_request_json, serialize_request

payload = (
    '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
    '"actions":[{"request_id":"check-1",'
    '"action":"urn:mtmf:iam:actions:system:document:read-object",'
    '"resource":{"kind":"capability"}}]}'
)
request = parse_request_json(payload)
assert request.actions[0].request_id == "check-1"
json.loads(serialize_request(request))
"""


def _run_isolated(interpreter: str, code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [interpreter, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )


def test_a24_import_graph_has_no_forbidden_dependencies() -> None:
    banned = repr(BANNED_MODULES)
    code = (
        "import importlib, sys\n"
        f"for name in {_SUBMODULES!r}:\n"
        "    importlib.import_module(name)\n"
        f"banned = {banned}\n"
        "loaded = [name for name in banned if name in sys.modules]\n"
        "if loaded:\n"
        "    raise SystemExit(f'forbidden imports: {loaded}')\n"
    )
    result = _run_isolated(sys.executable, code)
    assert result.returncode == 0, result.stderr


def test_a24_api_cannot_import_core_or_service() -> None:
    code = (
        "import mtmf_api, sys\n"
        "bad = [n for n in ('mtmf_core', 'mtmf_service') if n in sys.modules]\n"
        "sys.exit(1 if bad else 0)\n"
    )
    result = _run_isolated(sys.executable, code)
    assert result.returncode == 0, result.stderr


def test_a25_wheel_builds_installs_and_imports_in_isolation(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    if uv is None:  # pragma: no cover - canonical toolchain always provides uv
        pytest.skip("uv is required for the isolated packaging check")

    wheel_dir = tmp_path / "wheel"
    build = subprocess.run(
        [uv, "build", "--wheel", "--package", "mtmf-api", "-o", str(wheel_dir)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert build.returncode == 0, build.stderr
    wheels = list(wheel_dir.glob("mtmf_api-*.whl"))
    assert len(wheels) == 1

    with zipfile.ZipFile(wheels[0]) as archive:
        names = archive.namelist()
    assert any(name.endswith("mtmf_api/py.typed") for name in names)
    assert any(name.endswith("mtmf_api/authorization.py") for name in names)
    assert any(name.endswith("mtmf_api/json_codec.py") for name in names)

    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(environment)
    interpreter = environment / "bin" / "python"
    install = subprocess.run(
        [str(interpreter), "-m", "pip", "install", "--no-deps", str(wheels[0])],
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr

    exercise = _run_isolated(str(interpreter), _EXERCISE)
    assert exercise.returncode == 0, exercise.stderr

    banned = repr(BANNED_MODULES)
    isolation = (
        "import importlib, sys\n"
        f"for name in {_SUBMODULES!r}:\n"
        "    importlib.import_module(name)\n"
        f"banned = {banned}\n"
        "loaded = [name for name in banned if name in sys.modules]\n"
        "if loaded:\n"
        "    sys.exit(f'forbidden imports: {loaded}')\n"
    )
    result = _run_isolated(str(interpreter), isolation)
    assert result.returncode == 0, result.stderr
