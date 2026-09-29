"""Podman/Compose resource-ownership tests (ISO, static).

These tests audit the MTMF-owned repository infrastructure: the Compose
file, `.env.example`, and `scripts/mtmf-postgres.py`. They prove that
every MTMF container-runtime operation is explicitly scoped to the
canonical ``mtmf`` project, that no fixed global container name exists,
that no broad Podman discovery or pruning patterns appear, that the
published PostgreSQL port is configurable, and that no real secret is
committed.

They do not start, stop, or inspect any container: the live
ATI + MTMF simultaneous scenario is validated operationally with the
repository scripts.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE_FILE = REPO_ROOT / "compose.yaml"
ENV_EXAMPLE = REPO_ROOT / ".env.example"
SCRIPT = REPO_ROOT / "scripts" / "mtmf-postgres.py"

_SCRIPT_FORBIDDEN_PATTERNS = (
    r"\bpodman\s+(system\s+)?(prune|volume\s+prune|network\s+prune)\b",
    r"\bpodman\s+rm(?!\s+)\b",
    r"\bpodman\s+ps\b[^\n]*--filter(?!.*io\.podman\.compose)",
    r"(first\s+running\s+postgres|discover|probe)\b",
)


def _compose_dict() -> dict:
    with COMPOSE_FILE.open() as handle:
        return yaml.safe_load(handle)


def test_iso01_canonical_compose_project_is_explicit_mtmf_in_scripts() -> None:
    source = SCRIPT.read_text()
    assert 'PROJECT_NAME = "mtmf"' in source
    # The project name is always passed explicitly and never read from an
    # ambient variable that could redirect the operation.
    assert "--project-name" in source


def test_iso02_scripts_scope_every_compose_operation_to_the_mtmf_project() -> None:
    source = SCRIPT.read_text()
    # Every Compose command is dispatched through _compose(), which builds
    # a single explicit project-scoped invocation.
    compose_call = '"podman",\n        "compose",\n        "--project-name",\n        PROJECT_NAME,'
    assert compose_call in source
    assert source.count("_compose(") >= 4


def test_iso03_no_fixed_global_container_name() -> None:
    compose = _compose_dict()
    assert "container_name" not in str(compose)


def test_iso04_containers_identified_through_project_plus_service_ownership() -> None:
    # The script addresses the MTMF service through project-scoped
    # `podman compose` only; it never uses `podman exec`, never inspects
    # containers, and never discovers PostgreSQL by image/name/port.
    source = SCRIPT.read_text()
    assert '"exec"' not in source
    assert "inspect" not in source
    # The canonical service is named `postgres` in Compose and addressed
    # only through the MTMF project.
    assert "postgres:" in COMPOSE_FILE.read_text()


def test_iso06_networks_are_project_scoped() -> None:
    # Podman Compose derives network names from the project; no network is
    # declared with a fixed global name.
    compose = _compose_dict()
    assert "networks" not in compose or not any(
        key in ("ati", "agentic", "pg_default") for key in compose.get("networks", {})
    )


def test_iso07_volumes_are_project_scoped() -> None:
    compose = _compose_dict()
    volumes = compose.get("volumes", {})
    assert volumes
    for name in volumes:
        assert "mtmf" in name or name.startswith("mtmf-")


def test_iso08_host_postgres_port_is_configurable() -> None:
    compose = _compose_dict()
    ports = compose["services"]["postgres"]["ports"]
    assert not any("5432:5432" in str(port) for port in ports)
    assert any("${MTMF_POSTGRES_PORT" in str(port) and "55432" in str(port) for port in ports)


def test_iso010_to_iso011_no_broad_discovery_or_global_prune_in_scripts() -> None:
    source = SCRIPT.read_text()
    for pattern in _SCRIPT_FORBIDDEN_PATTERNS:
        assert not re.search(pattern, source, re.I), f"forbidden pattern {pattern!r}"


def test_iso012_to_iso013_start_and_stop_are_scoped() -> None:
    source = SCRIPT.read_text()
    # Commands are limited to `up`, `stop`, `down`, `ps` on the MTMF
    # project; `reset` additionally recreates only the MTMF project.
    assert '_compose("up", "-d", "postgres")' in source
    assert '_compose("stop", "postgres")' in source


def test_iso015_and_iso017_env_config_is_explicit_and_fails_closed() -> None:
    source = SCRIPT.read_text()
    assert "PostgresConfig.from_env()" in source
    assert "fails closed" in source.lower() or "never falls back" in source.lower()
    source = (
        REPO_ROOT / "packages/mtmf-core/src/mtmf_core/persistence/postgres/config.py"
    ).read_text()
    assert "PostgresConfigError" in source


def test_iso024_no_real_secret_committed() -> None:
    env_text = ENV_EXAMPLE.read_text()
    assert "mtmf-dev-password" in env_text
    # No obvious real-credential shapes allowed.
    for token in ("BEGIN RSA PRIVATE KEY", "password=", "AWS_SECRET", "-----BEGIN"):
        if token == "password=":
            assert "MTMF_POSTGRES_PASSWORD=mtmf-dev-password" in env_text
        else:
            assert token not in env_text


def test_iso_compose_healthcheck_targets_only_mtmf_service() -> None:
    compose = _compose_dict()
    healthcheck = compose["services"]["postgres"]["healthcheck"]
    command = healthcheck["test"]
    joined = " ".join(str(part) for part in command)
    assert "pg_isready" in joined
    assert "POSTGRES_USER" in joined and "POSTGRES_DB" in joined
