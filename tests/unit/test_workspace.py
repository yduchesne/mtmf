"""Workspace, dependency-boundary, and coverage-configuration tests."""

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

PACKAGE_TO_IMPORT = {
    "mtmf-api": "mtmf_api",
    "mtmf-core": "mtmf_core",
    "mtmf-client": "mtmf_client",
    "mtmf-service": "mtmf_service",
}


def _pyproject(package: str) -> dict:
    path = REPO_ROOT / "packages" / package / "pyproject.toml"
    with path.open("rb") as handle:
        return tomllib.load(handle)


def _dependencies(package: str) -> list[str]:
    return _pyproject(package)["project"].get("dependencies", [])


@pytest.mark.parametrize("import_name", sorted(PACKAGE_TO_IMPORT.values()))
def test_distribution_imports(import_name: str) -> None:
    assert __import__(import_name) is not None


def test_core_importable_without_importing_api() -> None:
    code = "import mtmf_core, sys; sys.exit('mtmf_api' in sys.modules)"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_api_importable_without_importing_core() -> None:
    code = "import mtmf_api, sys; sys.exit('mtmf_core' in sys.modules)"
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_core_metadata_has_no_dependency_on_api() -> None:
    assert "mtmf-api" not in _dependencies("mtmf-core")


def test_core_metadata_has_no_runtime_dependencies() -> None:
    assert _dependencies("mtmf-core") == []


def test_api_metadata_has_no_dependency_on_core() -> None:
    assert "mtmf-core" not in _dependencies("mtmf-api")


def test_api_metadata_has_no_runtime_dependencies() -> None:
    assert _dependencies("mtmf-api") == []


def test_client_metadata_depends_on_workspace_api_only() -> None:
    dependencies = _dependencies("mtmf-client")
    assert any("mtmf-api" in dependency for dependency in dependencies)
    assert not any("mtmf-core" in dependency for dependency in dependencies)


def test_service_metadata_depends_on_api_and_core_without_http_framework() -> None:
    dependencies = _dependencies("mtmf-service")
    assert any("mtmf-api" in dependency for dependency in dependencies)
    assert any("mtmf-core" in dependency for dependency in dependencies)
    assert not any(
        name in dependency for dependency in dependencies for name in ("fastapi", "uvicorn")
    )


def test_workspace_members_are_declared() -> None:
    root = REPO_ROOT / "pyproject.toml"
    with root.open("rb") as handle:
        root_config = tomllib.load(handle)
    members = root_config["tool"]["uv"]["workspace"]["members"]
    for package in PACKAGE_TO_IMPORT:
        assert f"packages/{package}" in members


def test_coverage_fail_under_is_at_least_85() -> None:
    root = REPO_ROOT / "pyproject.toml"
    with root.open("rb") as handle:
        root_config = tomllib.load(handle)
    fail_under = root_config["tool"]["coverage"]["report"]["fail_under"]
    assert fail_under >= 85


@pytest.mark.parametrize("package", ["mtmf-api", "mtmf-core", "mtmf-client", "mtmf-service"])
def test_package_metadata_uses_python_314_baseline(package: str) -> None:
    assert _pyproject(package)["project"]["requires-python"] == ">=3.14"
