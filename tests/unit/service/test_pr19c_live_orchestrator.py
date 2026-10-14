"""Deterministic tests for the PR 19C isolated acceptance orchestrator.

These exercise the secret lifecycle, Compose isolation validation,
canonical acceptance-issuer invariants and default-launcher preservation
without touching Podman, Keycloak or PostgreSQL.
"""

from __future__ import annotations

import importlib.util
import stat
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def _load(name: str, filename: str):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


orch = _load("mtmf_pr19c_live", "mtmf-pr19c-live.py")
default_launcher = _load("mtmf_dev_stack", "mtmf-dev-stack.py")


def test_oru05_iso06_acceptance_issuer_is_exact() -> None:
    assert orch.ACCEPTANCE_ISSUER == "https://keycloak.mtmf.test:29443/realms/mtmf-dev"
    assert orch.ACCEPTANCE_JWKS == (
        "https://keycloak.mtmf.test:29443/realms/mtmf-dev/protocol/openid-connect/certs"
    )
    orch._verify_issuer_constants()


def test_oru01_iso01_committed_compose_is_isolated() -> None:
    # The committed standalone model must pass the isolation validation.
    orch._validate_compose_isolation()


def test_iso01_external_compose_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "compose.yaml"
    path.write_text(
        "volumes:\n  mtmf-postgres-data:\n    external: true\n  mtmf-dev-keycloak-data:\n",
        encoding="utf-8",
    )
    with pytest.raises(orch.AcceptanceError):
        orch._validate_compose_isolation(path)


def test_iso02_globally_named_volume_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "compose.yaml"
    path.write_text(
        "volumes:\n  mtmf-postgres-data:\n"
        "  mtmf-dev-keycloak-data:\n    name: mtmf-dev-keycloak-data\n",
        encoding="utf-8",
    )
    with pytest.raises(orch.AcceptanceError):
        orch._validate_compose_isolation(path)


def test_oru03_secrets_are_owner_only(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(orch, "ACCEPTANCE_SECRET_DIR", tmp_path / "secrets")
    files = orch._stage_secrets()
    run_dir = tmp_path / "secrets"
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    for name in files:
        assert stat.S_IMODE((run_dir / name).stat().st_mode) == 0o600
    assert stat.S_IMODE((run_dir / "dev-user-password").stat().st_mode) == 0o600


def test_oru04_secrets_are_redacted() -> None:
    orch._SECRET_VALUES.clear()
    orch._SECRET_VALUES.append("supersecretvalue")
    assert orch._redact("X=supersecretvalue") == "X=<redacted>"
    assert "supersecretvalue" not in orch._redact("a supersecretvalue b")
    orch._SECRET_VALUES.clear()


def test_oru08_build_env_uses_acceptance_issuer_and_admin_secret() -> None:
    staged = {
        "admin_password": "admin-secret-value",
        "user_password": "user-secret-value",
        "db_password": "db-secret-value",
        "migrator_password": "mig-secret-value",
        "runtime_password": "run-secret-value",
    }
    env = orch._build_env(staged, {})
    assert env["MTMF_AUTH_ISSUER"] == orch.ACCEPTANCE_ISSUER
    assert env["MTMF_AUTH_JWKS_URI"] == orch.ACCEPTANCE_JWKS
    assert env["MTMF_DEV_KC_ADMIN_PASSWORD"] == "admin-secret-value"
    assert env["MTMF_DEV_USER_CREATE"] == "true"
    assert env["MTMF_POSTGRES_PORT"] == str(orch.ACCEPTANCE_POSTGRES_PORT)
    assert env["MTMF_MIGRATOR_DATABASE_URL"].endswith("@postgres:5432/mtmf")
    assert env["MTMF_PR19C_CA_FILE"].startswith(str(orch.ACCEPTANCE_CA_DIR))


def test_iso10_acceptance_project_is_distinct() -> None:
    assert orch.ACCEPTANCE_PROJECT == "mtmf-pr19c-acceptance"
    assert orch.ACCEPTANCE_PROJECT != orch.DEFAULT_PROJECT


def test_iso14_default_launcher_remains_exact() -> None:
    assert default_launcher.PROJECT == "mtmf"
    assert default_launcher.CANONICAL_KC_PORT == 28443
    assert default_launcher.CANONICAL_KC_ISSUER == (
        "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
    )
    assert default_launcher.COMPOSE_FILES == (
        "-f",
        "compose.yaml",
        "-f",
        "compose.dev.yaml",
    )
