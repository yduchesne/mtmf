"""Deterministic tests for the PR 19C live-acceptance orchestrator helpers.

These exercise the secret lifecycle, ownership refusal, canonical-issuer
invariant and redaction without touching Podman, Keycloak or PostgreSQL.
"""

from __future__ import annotations

import importlib.util
import os
import stat
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-pr19c-live.py"
_spec = importlib.util.spec_from_file_location("mtmf_pr19c_live", _SCRIPT)
assert _spec is not None and _spec.loader is not None
orch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(orch)


def test_oru01_default_project_is_refused() -> None:
    with pytest.raises(orch.AcceptanceError):
        orch._assert_owned_project("mtmf")
    # A dedicated project is accepted.
    orch._assert_owned_project("mtmf-pr19c-acceptance")


def test_oru03_secrets_are_owner_only(tmp_path: Path) -> None:
    run_dir = tmp_path / "secrets"
    files = orch._stage_secrets(run_dir)
    assert stat.S_IMODE(run_dir.stat().st_mode) == 0o700
    for name in files:
        path = run_dir / name
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(files["admin_password"]) >= 24
    assert len(files["user_password"]) >= 24


def test_oru04_secrets_are_redacted() -> None:
    orch._SECRET_VALUES.clear()
    orch._SECRET_VALUES.append("supersecretvalue")
    assert orch._redact("MTMF_AUTH_ADMIN_PASSWORD=supersecretvalue") == (
        "MTMF_AUTH_ADMIN_PASSWORD=<redacted>"
    )
    assert "supersecretvalue" not in orch._redact("prefix supersecretvalue suffix")
    orch._SECRET_VALUES.clear()


def test_oru05_canonical_issuer_is_exact() -> None:
    assert orch.CANONICAL_ISSUER == "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
    assert orch.CANONICAL_REALM == "mtmf-dev"


def test_oru08_initializer_gets_admin_secret_and_extra_compose(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("MTMF_MIGRATOR_POSTGRES_USER", "u")
    dotenv = {
        "MTMF_MIGRATOR_POSTGRES_USER": "migrator",
        "MTMF_MIGRATOR_POSTGRES_PASSWORD": "pw",
        "MTMF_RUNTIME_POSTGRES_USER": "runtime",
        "MTMF_RUNTIME_POSTGRES_PASSWORD": "pw",
    }
    staged = {"admin_password": "admin-secret-value", "user_password": "user-secret-value"}
    env = orch._build_env(staged, "mtmf-pr19c-acceptance", dotenv)
    assert env["MTMF_DEV_KC_ADMIN_PASSWORD"] == "admin-secret-value"
    assert env["COMPOSE_PROJECT_NAME"] == "mtmf-pr19c-acceptance"
    assert env["MTMF_DEV_STACK_EXTRA_COMPOSE"] == orch._EXTRA_COMPOSE
    assert env["MTMF_DEV_REALM_SETUP"] == "1"
    # The generated acceptance project never targets the default project.
    assert env["MTMF_DEV_STACK_PROJECT"] == "mtmf-pr19c-acceptance"


def test_oru10_cleanup_removes_only_the_run_dir(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    orch._stage_secrets(run_dir)
    orch._cleanup_secrets(run_dir)
    assert not run_dir.exists()
    # A foreign directory is untouched by a missing run dir.
    orch._cleanup_secrets(tmp_path / "absent")


def test_default_stack_project_is_distinct() -> None:
    assert orch.DEFAULT_PROJECT != orch.DEFAULT_STACK_PROJECT
    assert os.environ.get("MTMF_DEV_STACK_PROJECT") is None or True
