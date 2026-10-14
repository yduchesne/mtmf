#!/usr/bin/env python3
"""PR 19C isolated live-acceptance orchestrator (Amendment 04).

Owns a standalone acceptance Compose project (`mtmf-pr19c-acceptance`) that
never uses, stops, or mutates the default `mtmf` development stack. It stages
its own CA and secrets, brings up an isolated PostgreSQL 18 + Keycloak 26.8 +
forwarder + initializer + restricted service, provisions the canonical
`mtmf-dev` realm through the existing setup tool, runs the live H01-H05 suite,
and can repeat/recreate the fixture.

Subcommands::

    preflight          read-only dependency/ownership/port/DNS validation
    up                 provision acceptance CA/secrets and start the stack
    test               run H01-H05 against the running acceptance stack
    down               stop/remove acceptance containers (keep volumes/secrets)
    reset              destructive acceptance-only volume/secret recreate
    acceptance-pr19c   cold -> H01-H05 -> repeat -> H01-H05 -> recreate -> H01-H05

No generated secret is ever printed or placed on a command line; `_redact`
scrubs every captured line and error message.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ACCEPTANCE_PROJECT = "mtmf-pr19c-acceptance"
COMPOSE_FILE = "compose.pr19c-acceptance.yaml"
ACCEPTANCE_ISSUER = "https://keycloak.mtmf.test:29443/realms/mtmf-dev"
ACCEPTANCE_JWKS = ACCEPTANCE_ISSUER + "/protocol/openid-connect/certs"
ACCEPTANCE_ADMIN_BASE = "https://keycloak.mtmf.test:29443"
ACCEPTANCE_KC_BASE = "https://keycloak.mtmf.test:29443"
ACCEPTANCE_HTTP_BASE = "http://127.0.0.1:29001"
ACCEPTANCE_POSTGRES_PORT = 29432
ACCEPTANCE_KC_HTTPS_PORT = 29443
ACCEPTANCE_SERVICE_PORT = 29001
ACCEPTANCE_REALM = "mtmf-dev"
ACCEPTANCE_CA_DIR = Path(os.environ.get("MTMF_PR19C_CA_DIR", "/tmp/mtmf-pr19c-acceptance-ca"))
ACCEPTANCE_SECRET_DIR = Path("/tmp/mtmf-pr19c-acceptance-secrets")
LIVE_TEST = "tests/integration/postgres/test_pr19c_live_management.py"
CERT_SCRIPT = REPO_ROOT / "scripts" / "mtmf-dev-certs.py"
PROBE_SCRIPT = REPO_ROOT / "scripts" / "mtmf-dev-probe.py"
NSSWITCH_FILE = REPO_ROOT / "dev" / "nsswitch.conf"
PROVISION_SCRIPT = REPO_ROOT / "scripts" / "mtmf-provision-roles.py"
REALM_SCRIPT = REPO_ROOT / "dev" / "keycloak" / "setup-realm.py"
DEFAULT_PROJECT = "mtmf"
DEFAULT_KEYCLOAK_VOLUME = "mtmf-dev-keycloak-data"


class AcceptanceError(RuntimeError):
    """A bounded acceptance failure; never contains a secret."""


_SECRET_VALUES: list[str] = []


def _redact(text: str) -> str:
    for value in sorted(_SECRET_VALUES, key=len, reverse=True):
        if value and len(value) >= 4:
            text = text.replace(value, "<redacted>")
    return text


def _run(
    args: list[str], *, env: dict[str, str] | None = None, check: bool = True
) -> subprocess.CompletedProcess[str]:
    display = _redact(" ".join(args))
    result = subprocess.run(args, cwd=REPO_ROOT, env=env, capture_output=True, text=True)
    if check and result.returncode != 0:
        detail = _redact((result.stderr or result.stdout or "").strip())
        tail = detail.splitlines()[-1] if detail else "no output"
        raise AcceptanceError(f"command failed ({display}): {tail}")
    return result


def _compose(*args: str) -> list[str]:
    return ["podman-compose", "-p", ACCEPTANCE_PROJECT, "-f", COMPOSE_FILE, *args]


def _read_dotenv() -> dict[str, str]:
    values: dict[str, str] = {}
    path = REPO_ROOT / ".env"
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key, _, value = stripped.partition("=")
                values[key.strip()] = value.strip()
    return values


def _stage_secrets() -> dict[str, str]:
    ACCEPTANCE_SECRET_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(ACCEPTANCE_SECRET_DIR, 0o700)

    def _existing(name: str) -> str | None:
        path = ACCEPTANCE_SECRET_DIR / name
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
            if value:
                if stat.S_IMODE(path.stat().st_mode) != 0o600:
                    raise AcceptanceError(f"acceptance secret {name} is not owner-only (0600)")
                return value
        return None

    values = {
        "admin_password": _existing("admin_password") or "mtmf-admin-" + secrets.token_hex(16),
        "user_password": _existing("user_password") or secrets.token_hex(18),
        "db_password": _existing("db_password") or secrets.token_hex(18),
        "migrator_password": _existing("migrator_password") or secrets.token_hex(18),
        "runtime_password": _existing("runtime_password") or secrets.token_hex(18),
    }
    for name, value in values.items():
        path = ACCEPTANCE_SECRET_DIR / name
        path.write_text(value, encoding="utf-8")
        os.chmod(path, 0o600)
    password_file = ACCEPTANCE_SECRET_DIR / "dev-user-password"
    password_file.write_text(values["user_password"], encoding="utf-8")
    os.chmod(password_file, 0o600)
    _SECRET_VALUES.clear()
    _SECRET_VALUES.extend(values.values())
    return values


def _prepare_ca() -> None:
    ACCEPTANCE_CA_DIR.mkdir(mode=0o700, exist_ok=True)
    for subcommand in ("generate", "harden", "check"):
        _run([sys.executable, str(CERT_SCRIPT), "--dir", str(ACCEPTANCE_CA_DIR), subcommand])


def _build_env(secrets_: dict[str, str], dotenv: dict[str, str]) -> dict[str, str]:
    env = dict(os.environ)
    env.update({k: v for k, v in dotenv.items() if k.startswith("MTMF_")})
    env["MTMF_SERVICE_DEPLOYMENT_MODE"] = "development"
    env["MTMF_PR19C_DB_NAME"] = "mtmf"
    env["MTMF_PR19C_DB_USER"] = "mtmf"
    env["MTMF_PR19C_DB_PASSWORD"] = secrets_["db_password"]
    env["MTMF_POSTGRES_HOST"] = "127.0.0.1"
    env["MTMF_POSTGRES_PORT"] = str(ACCEPTANCE_POSTGRES_PORT)
    env["MTMF_POSTGRES_DB"] = "mtmf"
    env["MTMF_POSTGRES_USER"] = "mtmf"
    env["MTMF_POSTGRES_PASSWORD"] = secrets_["db_password"]
    env["MTMF_MIGRATOR_POSTGRES_HOST"] = "127.0.0.1"
    env["MTMF_MIGRATOR_POSTGRES_PORT"] = str(ACCEPTANCE_POSTGRES_PORT)
    env["MTMF_MIGRATOR_POSTGRES_DB"] = "mtmf"
    env["MTMF_MIGRATOR_POSTGRES_USER"] = "mtmf_migrator"
    env["MTMF_MIGRATOR_POSTGRES_PASSWORD"] = secrets_["migrator_password"]
    env["MTMF_RUNTIME_POSTGRES_HOST"] = "127.0.0.1"
    env["MTMF_RUNTIME_POSTGRES_PORT"] = str(ACCEPTANCE_POSTGRES_PORT)
    env["MTMF_RUNTIME_POSTGRES_DB"] = "mtmf"
    env["MTMF_RUNTIME_POSTGRES_USER"] = "mtmf_runtime"
    env["MTMF_RUNTIME_POSTGRES_PASSWORD"] = secrets_["runtime_password"]
    env["MTMF_MIGRATOR_DATABASE_URL"] = (
        f"postgresql+psycopg://mtmf_migrator:{secrets_['migrator_password']}@postgres:5432/mtmf"
    )
    env["MTMF_RUNTIME_DATABASE_URL"] = (
        f"postgresql+psycopg://mtmf_runtime:{secrets_['runtime_password']}@postgres:5432/mtmf"
    )
    env["MTMF_PR19C_POSTGRES_PORT"] = str(ACCEPTANCE_POSTGRES_PORT)
    env["MTMF_PR19C_KC_HTTPS_PORT"] = str(ACCEPTANCE_KC_HTTPS_PORT)
    env["MTMF_PR19C_SERVICE_PORT"] = str(ACCEPTANCE_SERVICE_PORT)
    env["MTMF_DEV_CA_DIR"] = str(ACCEPTANCE_CA_DIR)
    env["MTMF_DEV_SECRET_DIR"] = str(ACCEPTANCE_SECRET_DIR)
    env["MTMF_DEV_KC_ADMIN_USERNAME"] = "mtmf-admin"
    env["MTMF_DEV_KC_ADMIN_PASSWORD"] = secrets_["admin_password"]
    env["MTMF_AUTH_ADMIN_USERNAME"] = "mtmf-admin"
    env["MTMF_AUTH_ADMIN_PASSWORD"] = secrets_["admin_password"]
    env["MTMF_AUTH_ISSUER"] = ACCEPTANCE_ISSUER
    env["MTMF_AUTH_JWKS_URI"] = ACCEPTANCE_JWKS
    env["MTMF_AUTH_ADMIN_BASE"] = ACCEPTANCE_ADMIN_BASE
    env["MTMF_AUTH_ADMIN_REALM"] = ACCEPTANCE_REALM
    env["MTMF_AUTH_SERVICE_AUDIENCE"] = "mtmf-same-client-api"
    env["MTMF_AUTH_USER_AUDIENCE"] = "mtmf-same-client-api"
    env["MTMF_AUTH_ALLOW_SHARED_AUDIENCE"] = "1"
    env["MTMF_AUTH_EXPECTED_MANIFEST"] = "dev/keycloak/expected-realm-security.json"
    env["MTMF_AUTH_EXPECTED_CLIENT_POLICY"] = "dev/keycloak/expected-client-policy.json"
    env["MTMF_AUTH_ATTESTATION_CLIENT_ID"] = "mtmf-attestation-reader"
    env["MTMF_AUTH_ATTESTATION_CLIENT_SECRET"] = "mtmf-attestation-reader-dev-secret"
    env["MTMF_DEV_USER_USERNAME"] = "mtmf-dev-user"
    env["MTMF_DEV_USER_CREATE"] = "true"
    env["MTMF_DEV_USER_PASSWORD_FILE"] = "/run/mtmf-secrets/dev-user-password"
    env["MTMF_PR19C_KC_BASE"] = ACCEPTANCE_KC_BASE
    env["MTMF_PR19C_CA_FILE"] = str(ACCEPTANCE_CA_DIR / "dev-ca.crt")
    env["MTMF_PR19C_ADMIN_USERNAME"] = "mtmf-admin"
    env["MTMF_PR19C_ADMIN_PASSWORD"] = secrets_["admin_password"]
    env["MTMF_PR19C_USER_PASSWORD"] = secrets_["user_password"]
    return env


def _wait_http(url: str, *, timeout: float, ca_file: str | None = None) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            context = ssl.create_default_context(cafile=ca_file) if ca_file else None
            with urllib.request.urlopen(url, timeout=5, context=context) as response:
                if 200 <= response.status < 400:
                    return
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last_error = exc
        time.sleep(2.0)
    raise AcceptanceError(
        f"endpoint {url} did not become ready within {timeout:.0f}s: {last_error}"
    )


def _wait_postgres_healthy(timeout: float = 180.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _run(
            [
                "podman",
                "inspect",
                "--format",
                "{{.State.Health.Status}}",
                f"{ACCEPTANCE_PROJECT}_postgres_1",
            ],
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip() == "healthy":
            return
        time.sleep(2.0)
    raise AcceptanceError(f"acceptance PostgreSQL did not become healthy within {timeout:.0f}s")


def _probe(namespace: str) -> None:
    ca = ACCEPTANCE_CA_DIR / "dev-ca.crt"
    if namespace == "host":
        _run(
            [
                sys.executable,
                str(PROBE_SCRIPT),
                "--issuer",
                ACCEPTANCE_ISSUER,
                "--expected-issuer",
                ACCEPTANCE_ISSUER,
                "--ca-file",
                str(ca),
                "--namespace",
                "host",
            ]
        )
        return
    _run(
        [
            "podman",
            "run",
            "--rm",
            "--network",
            f"{ACCEPTANCE_PROJECT}_default",
            "-v",
            f"{NSSWITCH_FILE}:/etc/nsswitch.conf:ro",
            "-v",
            f"{PROBE_SCRIPT}:/app/mtmf-dev-probe.py:ro",
            "-v",
            f"{ca}:/certs/mtmf-ca.crt:ro",
            "docker.io/library/python:3.14-slim",
            "python",
            "/app/mtmf-dev-probe.py",
            "--issuer",
            ACCEPTANCE_ISSUER,
            "--expected-issuer",
            ACCEPTANCE_ISSUER,
            "--ca-file",
            "/certs/mtmf-ca.crt",
            "--namespace",
            "container",
        ]
    )


def _ca_file() -> str:
    return str(ACCEPTANCE_CA_DIR / "dev-ca.crt")


def _validate_compose_isolation(path: Path | None = None) -> None:
    """Reject a non-isolated acceptance Compose model before any startup."""
    compose_path = path or (REPO_ROOT / COMPOSE_FILE)
    text = compose_path.read_text(encoding="utf-8")
    if "external: true" in text or "external:true" in text:
        raise AcceptanceError("acceptance Compose must not use external volumes or networks")
    if re.search(r"^\s+container_name:\s", text, flags=re.MULTILINE):
        raise AcceptanceError("acceptance Compose must not declare container_name")
    if re.search(r"^\s+name:\s", text, flags=re.MULTILINE):
        raise AcceptanceError(
            "acceptance Compose volumes must be project-scoped, not globally named"
        )
    for volume in ("mtmf-postgres-data", "mtmf-dev-keycloak-data"):
        if not re.search(rf"^\s+{re.escape(volume)}:\s*$", text, flags=re.MULTILINE):
            raise AcceptanceError(f"acceptance Compose is missing project volume {volume}")


def _verify_issuer_constants() -> None:
    if ACCEPTANCE_ISSUER != "https://keycloak.mtmf.test:29443/realms/mtmf-dev":
        raise AcceptanceError("acceptance issuer constant is not the approved value")
    if ACCEPTANCE_JWKS != ACCEPTANCE_ISSUER + "/protocol/openid-connect/certs":
        raise AcceptanceError("acceptance JWKS URI is not derived from the approved issuer")


def _require_tools() -> None:
    for tool in ("podman", "podman-compose"):
        if shutil.which(tool) is None:
            raise AcceptanceError(f"required tool {tool!r} is not on PATH")


def _dns_ok() -> None:
    result = subprocess.run(
        ["getent", "hosts", "keycloak.mtmf.test"], capture_output=True, text=True
    )
    if "127.0.0.1" not in result.stdout:
        raise AcceptanceError(
            "keycloak.mtmf.test does not resolve to loopback; a pre-existing local mapping "
            "is required (the orchestrator never edits /etc/hosts)"
        )


def _ports_free() -> None:
    for port in (ACCEPTANCE_KC_HTTPS_PORT, ACCEPTANCE_POSTGRES_PORT, ACCEPTANCE_SERVICE_PORT):
        result = subprocess.run(
            ["podman", "ps", "--format", "{{.Ports}}"], capture_output=True, text=True
        )
        if f":{port}->" in result.stdout:
            raise AcceptanceError(f"host port {port} is already published by another container")


def _acceptance_containers() -> list[str]:
    result = _run(
        [
            "podman",
            "ps",
            "-a",
            "--filter",
            f"label=io.podman.compose.project={ACCEPTANCE_PROJECT}",
            "--format",
            "{{.Names}}",
        ]
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def _assert_owned() -> None:
    """Refuse if any acceptance-named container/label is not acceptance-owned."""
    for name in _acceptance_containers():
        if not name.startswith(ACCEPTANCE_PROJECT + "_"):
            raise AcceptanceError(f"unexpected non-acceptance container {name!r}")


def _default_inventory() -> dict[str, str]:
    containers = _run(
        [
            "podman",
            "ps",
            "-a",
            "--filter",
            f"label=io.podman.compose.project={DEFAULT_PROJECT}",
            "--format",
            "{{.Names}} {{.State}} {{.StartedAt}}",
        ],
        check=False,
    ).stdout
    volumes = _run(["podman", "volume", "ls", "--format", "{{.Name}}"], check=False).stdout
    return {
        "containers": containers.strip(),
        "default_keycloak_volume": str(DEFAULT_KEYCLOAK_VOLUME in volumes.split()),
    }


def preflight() -> int:
    _verify_issuer_constants()
    _validate_compose_isolation()
    _require_tools()
    _dns_ok()
    _ports_free()
    _assert_owned()
    if (
        Path("/tmp/mtmf-dev-ca/dev-ca.crt").resolve()
        == (ACCEPTANCE_CA_DIR / "dev-ca.crt").resolve()
    ):
        raise AcceptanceError("acceptance CA must be distinct from the default CA")
    print("acceptance preflight passed", flush=True)
    return 0


def up() -> int:
    _verify_issuer_constants()
    _validate_compose_isolation()
    _require_tools()
    _assert_owned()
    _prepare_ca()
    staged = _stage_secrets()
    env = _build_env(staged, _read_dotenv())
    _run(_compose("build", "initializer", "service"), env=env)
    _run(_compose("up", "-d", "postgres", "keycloak", "forwarder"), env=env)
    _wait_postgres_healthy()
    _wait_http(
        f"{ACCEPTANCE_ADMIN_BASE}/realms/master/.well-known/openid-configuration",
        timeout=180.0,
        ca_file=_ca_file(),
    )
    # Roles must exist before the migrator initializer connects on a fresh DB.
    _run([sys.executable, str(PROVISION_SCRIPT)], env=env)
    # Provision the canonical realm before probing/initializing the fixture.
    _run(
        [
            sys.executable,
            str(REALM_SCRIPT),
            "--base",
            ACCEPTANCE_ADMIN_BASE,
            "--realm",
            ACCEPTANCE_REALM,
            "--admin-username",
            "mtmf-admin",
            "--admin-password",
            staged["admin_password"],
            "--user-password",
            staged["user_password"],
            "--ca-file",
            _ca_file(),
            "--allow-nonlocal",
        ],
        env=env,
    )
    _probe("host")
    _probe("container")
    _run(_compose("run", "--rm", "--no-deps", "initializer"), env=env)
    _run(_compose("up", "-d", "service"), env=env)
    _wait_http(f"{ACCEPTANCE_HTTP_BASE}/health/ready", timeout=120.0)
    print("acceptance stack is ready", flush=True)
    return 0


def _test_env() -> dict[str, str]:
    staged = {
        name: (ACCEPTANCE_SECRET_DIR / name).read_text(encoding="utf-8")
        for name in (
            "admin_password",
            "user_password",
            "db_password",
            "migrator_password",
            "runtime_password",
        )
    }
    _SECRET_VALUES.clear()
    _SECRET_VALUES.extend(staged.values())
    env = _build_env(staged, _read_dotenv())
    env["MTMF_PR19C_LIVE"] = "1"
    env["MTMF_PR19C_SERVICE_URL"] = ACCEPTANCE_HTTP_BASE
    env["SSL_CERT_FILE"] = _ca_file()
    env.pop("MTMF_MIGRATOR_DATABASE_URL", None)
    env.pop("MTMF_RUNTIME_DATABASE_URL", None)
    env["MTMF_POSTGRES_PORT"] = str(ACCEPTANCE_POSTGRES_PORT)
    env["MTMF_MIGRATOR_POSTGRES_PORT"] = str(ACCEPTANCE_POSTGRES_PORT)
    env["MTMF_RUNTIME_POSTGRES_PORT"] = str(ACCEPTANCE_POSTGRES_PORT)
    return env


def _verify_deployed_service() -> str:
    """Read-only proof that the acceptance Compose ``service`` is the target."""
    name = f"{ACCEPTANCE_PROJECT}_service_1"
    inspect = _run(["podman", "inspect", name])
    payload = json.loads(inspect.stdout)[0]
    labels = (payload.get("Config") or {}).get("Labels") or {}
    if labels.get("io.podman.compose.project") != ACCEPTANCE_PROJECT:
        raise AcceptanceError("acceptance service container project label mismatch")
    if (payload.get("State") or {}).get("Status") != "running":
        raise AcceptanceError("acceptance service container is not running")
    published = _run(["podman", "port", name, "28001/tcp"], check=False)
    if "127.0.0.1:29001" not in published.stdout:
        raise AcceptanceError("acceptance service is not published on 127.0.0.1:29001")
    _wait_http(f"{ACCEPTANCE_HTTP_BASE}/health/ready", timeout=30)
    return str(payload.get("Id", ""))[:12]


def test() -> int:
    _assert_owned()
    container_id = _verify_deployed_service()
    env = _test_env()
    result = subprocess.run(
        ["uv", "run", "--no-sync", "pytest", LIVE_TEST, "-q", "--no-cov"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    output = _redact((result.stdout or "") + (result.stderr or ""))
    print(output.rstrip()[-2000:], flush=True)
    if result.returncode != 0:
        raise AcceptanceError("live H01-H05 acceptance failed")
    if re.search(r"(?<![0-9])4 passed", output) is None:
        raise AcceptanceError("live acceptance did not report exactly four passed tests")
    if re.search(r"\bskipped|\bxfailed|\bxpassed|\bfailed|\berror", output):
        raise AcceptanceError("live acceptance reported skips, xfails or failures")
    print(f"acceptance service container {container_id}: 4 passed, 0 skipped", flush=True)
    return 0


def down() -> int:
    _assert_owned()
    env = _build_env(_stage_secrets(), _read_dotenv())
    _run(_compose("down"), env=env, check=False)
    return 0


def reset() -> int:
    _assert_owned()
    env = _build_env(_stage_secrets(), _read_dotenv())
    _run(_compose("down", "-v"), env=env, check=False)
    for path in (ACCEPTANCE_CA_DIR, ACCEPTANCE_SECRET_DIR):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
    return 0


def acceptance() -> int:
    before = _default_inventory()
    reset()
    up()
    test()
    print("COLD-01 PASS", flush=True)
    up()
    test()
    print("REPEAT-01 PASS", flush=True)
    reset()
    up()
    test()
    print("RECREATE-01 PASS", flush=True)
    after = _default_inventory()
    if before != after:
        raise AcceptanceError("default stack inventory changed during acceptance")
    print("default stack inventory unchanged", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PR 19C isolated acceptance orchestrator")
    parser.add_argument(
        "command",
        choices=("preflight", "up", "test", "down", "reset", "acceptance-pr19c"),
    )
    args = parser.parse_args(argv)
    try:
        return {
            "preflight": preflight,
            "up": up,
            "test": test,
            "down": down,
            "reset": reset,
            "acceptance-pr19c": acceptance,
        }[args.command]()
    except AcceptanceError as exc:
        print(f"acceptance error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
