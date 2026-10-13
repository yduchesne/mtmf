"""PR 17-B I16: real Compose container environment and secret-mount isolation.

Opt-in and heavy: set ``MTMF_PR17B_COMPOSE=1`` in addition to the live
Keycloak/PostgreSQL environment. The test creates the actual MTMF Compose
containers from ``compose.yaml`` + ``compose.dev.yaml``, inspects their real
environment and mounts, then runs the composed initializer image against real
Keycloak over host networking to prove the restricted secret mount works and
that no password appears in the logs.

It never runs ``podman-compose down`` (which would remove the MTMF PostgreSQL
container) and removes only the explicitly named MTMF-owned containers it
created. Secret values are never printed.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import uuid
from pathlib import Path

import pytest
from test_pr17b_live_acceptance import AdminRest  # type: ignore[import-not-found]

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR17B_COMPOSE") != "1",
    reason="real Compose isolation check is opt-in (set MTMF_PR17B_COMPOSE=1)",
)

REPO_ROOT = Path(__file__).resolve().parents[3]
COMPOSE = ["podman-compose", "-p", "mtmf", "-f", "compose.yaml", "-f", "compose.dev.yaml"]
INITIALIZER = "mtmf_initializer_1"
SERVICE = "mtmf_service_1"
EXTRA_COMPOSE_CONTAINER = "mtmf_" + "keycloak_1"
#: Removed leaf-first so Podman's dependency graph permits removal.
CLEANUP_ORDER = (SERVICE, INITIALIZER, EXTRA_COMPOSE_CONTAINER)
_RUN_TAG = "Pr17b-"
_INITIALIZER_SECRETS = (
    "MTMF_AUTH_ADMIN_PASSWORD",
    "MTMF_PR14_KC_ADMIN_PASSWORD",
    "MTMF_MIGRATOR_DATABASE_URL",
    "MTMF_DEV_USER_USERNAME",
    "MTMF_DEV_USER_PASSWORD_FILE",
    "MTMF_DEV_USER_CREATE",
)
_FORBIDDEN_ON_SERVICE = (
    "MTMF_AUTH_ADMIN_PASSWORD",
    "MTMF_PR14_KC_ADMIN_PASSWORD",
    "MTMF_MIGRATOR_DATABASE_URL",
    "MTMF_DEV_USER_USERNAME",
    "MTMF_DEV_USER_PASSWORD_FILE",
    "MTMF_DEV_USER_CREATE",
    "MTMF_DEV_USER_EMAIL",
)


def _password() -> str:
    """Return a non-secret, per-run test password (never a stored credential)."""
    return _RUN_TAG + uuid.uuid4().hex


def _compose_env() -> dict[str, str]:
    env = dict(os.environ)
    if not env.get("MTMF_MIGRATOR_DATABASE_URL"):
        env["MTMF_MIGRATOR_DATABASE_URL"] = (
            f"postgresql+psycopg://{env['MTMF_MIGRATOR_POSTGRES_USER']}:"
            f"{env['MTMF_MIGRATOR_POSTGRES_PASSWORD']}@{env['MTMF_MIGRATOR_POSTGRES_HOST']}:"
            f"{env['MTMF_MIGRATOR_POSTGRES_PORT']}/{env['MTMF_MIGRATOR_POSTGRES_DB']}"
        )
    if not env.get("MTMF_RUNTIME_DATABASE_URL"):
        env["MTMF_RUNTIME_DATABASE_URL"] = (
            f"postgresql+psycopg://{env['MTMF_RUNTIME_POSTGRES_USER']}:"
            f"{env['MTMF_RUNTIME_POSTGRES_PASSWORD']}@{env['MTMF_RUNTIME_POSTGRES_HOST']}:"
            f"{env['MTMF_RUNTIME_POSTGRES_PORT']}/{env['MTMF_RUNTIME_POSTGRES_DB']}"
        )
    issuer = f"{env['MTMF_PR14_KC_BASE']}/realms/mtmf-pr14-dev"
    env.update(
        {
            "MTMF_POSTGRES_DB": env.get("MTMF_POSTGRES_DB", "mtmf"),
            "MTMF_PR14_KC_TLS_DIR": env.get(
                "MTMF_PR14_KC_TLS_DIR", str(Path(tempfile.gettempdir()) / "mtmf-pr14-kc-tls")
            ),
            "MTMF_AUTH_ISSUER": issuer,
            "MTMF_AUTH_SERVICE_AUDIENCE": "mtmf-service-api",
            "MTMF_AUTH_USER_AUDIENCE": "mtmf-user-api",
            "MTMF_AUTH_JWKS_URI": f"{issuer}/protocol/openid-connect/certs",
            "MTMF_AUTH_ADMIN_BASE": env["MTMF_PR14_KC_BASE"],
            "MTMF_AUTH_ADMIN_REALM": "mtmf-pr14-dev",
            "MTMF_AUTH_ADMIN_USERNAME": env["MTMF_PR14_KC_ADMIN_USERNAME"],
            "MTMF_AUTH_ADMIN_PASSWORD": env["MTMF_PR14_KC_ADMIN_PASSWORD"],
            "MTMF_AUTH_ATTESTATION_CLIENT_ID": "mtmf-attestation-reader",
            "MTMF_AUTH_ATTESTATION_CLIENT_SECRET": "mtmf-attestation-reader-dev-secret",
            "MTMF_DEV_USER_USERNAME": "pr17b-compose-inspect",
            "MTMF_DEV_USER_CREATE": "false",
        }
    )
    return env


def _run(
    args: list[str], env: dict[str, str], *, timeout: float = 900.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )


def _env_keys(container: dict[str, object]) -> dict[str, str]:
    config = container.get("Config") or {}
    env = config.get("Env") or []  # type: ignore[union-attr]
    return {item.split("=", 1)[0]: item.split("=", 1)[1] for item in env if "=" in item}


def _inspect(env: dict[str, str]) -> dict[str, dict[str, object]]:
    result = _run(["podman", "inspect", INITIALIZER, SERVICE], env, timeout=120)
    assert result.returncode == 0, result.stderr
    return {container["Name"]: container for container in json.loads(result.stdout)}


def test_i16_compose_container_isolation_and_live_secret_mount(tmp_path: Path) -> None:
    env = _compose_env()
    secret_dir = Path(
        env.get("MTMF_DEV_SECRET_DIR", str(Path(tempfile.gettempdir()) / "mtmf-dev-secrets"))
    )
    secret_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    secret_file = secret_dir / "dev-user-password"
    password = _password()
    secret_file.write_text(password)
    secret_file.chmod(0o600)
    admin = AdminRest()
    username = f"pr17b-container-{uuid.uuid4().hex[:10]}"
    run_env_file = tmp_path / "container.env"
    try:
        # Create the real Compose containers. A dependency-start failure on a
        # port already owned by another MTMF fixture is acceptable; the
        # container definitions must exist and be inspectable.
        _run([*COMPOSE, "up", "-d", "--no-deps", "initializer", "service"], env)
        containers = _inspect(env)

        initializer_env = _env_keys(containers[INITIALIZER])
        service_env = _env_keys(containers[SERVICE])
        for key in _INITIALIZER_SECRETS:
            assert key in initializer_env, f"initializer missing {key}"
        for key in _FORBIDDEN_ON_SERVICE:
            assert key not in service_env, f"HTTP service must not receive {key}"

        initializer_mounts = {
            str(mount["Destination"]): mount for mount in containers[INITIALIZER].get("Mounts", [])
        }
        assert initializer_mounts["/run/mtmf-secrets"]["RW"] is False
        service_mounts = {
            str(mount["Destination"]) for mount in containers[SERVICE].get("Mounts", [])
        }
        assert "/run/mtmf-secrets" not in service_mounts

        # Live composed-image run over host networking (the documented
        # issuer-hostname accommodation) against the real Keycloak fixture.
        run_env_file.write_text(
            "\n".join(
                [
                    "MTMF_SERVICE_DEPLOYMENT_MODE=development",
                    f"MTMF_MIGRATOR_DATABASE_URL={env['MTMF_MIGRATOR_DATABASE_URL']}",
                    f"MTMF_POSTGRES_DB={env['MTMF_POSTGRES_DB']}",
                    f"MTMF_AUTH_ISSUER={env['MTMF_AUTH_ISSUER']}",
                    f"MTMF_AUTH_SERVICE_AUDIENCE={env['MTMF_AUTH_SERVICE_AUDIENCE']}",
                    f"MTMF_AUTH_USER_AUDIENCE={env['MTMF_AUTH_USER_AUDIENCE']}",
                    f"MTMF_AUTH_ADMIN_BASE={env['MTMF_AUTH_ADMIN_BASE']}",
                    f"MTMF_AUTH_ADMIN_REALM={env['MTMF_AUTH_ADMIN_REALM']}",
                    f"MTMF_AUTH_ADMIN_USERNAME={env['MTMF_AUTH_ADMIN_USERNAME']}",
                    f"MTMF_AUTH_ADMIN_PASSWORD={env['MTMF_AUTH_ADMIN_PASSWORD']}",
                    "MTMF_DEV_SECRET_DIR=/app/.secrets",
                    "MTMF_DEV_APPLICATION_KEYS=sample-app",
                    f"MTMF_DEV_TENANT_KEY=pr17b-container-{username[-8:]}",
                    "MTMF_DEV_TENANT_NAME=PR17B Container Tenant",
                    f"MTMF_DEV_USER_USERNAME={username}",
                    f"MTMF_DEV_USER_EMAIL={username}@example.invalid",
                    "MTMF_DEV_USER_CREATE=true",
                    "MTMF_DEV_USER_PASSWORD_FILE=/run/mtmf-secrets/dev-user-password",
                    "SSL_CERT_FILE=/certs/dev-ca.crt",
                ]
            )
        )
        run_env_file.chmod(0o600)
        live = _run(
            [
                "podman",
                "run",
                "--rm",
                "--network=host",
                "--name",
                f"pr17b-init-{uuid.uuid4().hex[:8]}",
                "-v",
                f"{secret_dir}:/run/mtmf-secrets:ro",
                "-v",
                f"{env['MTMF_PR14_KC_CA_FILE']}:/certs/dev-ca.crt:ro",
                "--env-file",
                str(run_env_file),
                "localhost/mtmf_initializer:latest",
                "python",
                "scripts/mtmf-dev-initialize.py",
            ],
            env,
            timeout=300,
        )
        assert live.returncode == 0, live.stderr
        assert "development initialization complete" in live.stdout
        assert _RUN_TAG not in live.stdout + live.stderr
        assert password not in live.stdout + live.stderr
        assert secret_file.stat().st_mode & 0o077 == 0
        users = admin.find_users(username)
        assert len(users) == 1
    finally:
        for container in CLEANUP_ORDER:
            _run(["podman", "rm", "-f", container], env, timeout=60)
        admin.delete_user(username)
        run_env_file.unlink(missing_ok=True)
