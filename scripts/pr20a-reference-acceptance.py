#!/usr/bin/env python3
"""PR 20A isolated reference-consumer live-acceptance orchestrator.

Owns a standalone acceptance Compose project (``mtmf-pr20a-acceptance``) that
never uses, stops, or mutates the default ``mtmf`` development stack or any
other project. It stages its own CA/secrets/fixtures, brings up an isolated
PostgreSQL 18 + Keycloak 26.8 + Keycloak forwarder + restricted MTMF service +
TLS terminator + independent reference app, provisions the reviewed fixture
through the privileged one-shot initializer, seeds the reference SQLite store,
and runs the live L01-L05 suite.

Subcommands::

    preflight    read-only dependency/ownership/port/DNS validation
    up           provision CA/secrets and start the full acceptance stack
    test         run L01-L05 against the running acceptance stack
    down         stop/remove acceptance containers (keep volumes/secrets)
    recreate     destructive acceptance-only volume/secret recreate
    acceptance   cold -> L01-L05 -> repeat -> L01-L05 -> recreate -> L01-L05

No generated secret is ever printed or placed on a command line; ``_redact``
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
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

import pr20a_reference_fixture as fixture  # noqa: E402

ACCEPTANCE_PROJECT = "mtmf-pr20a-acceptance"
COMPOSE_FILE = "compose.pr20a-acceptance.yaml"
ACCEPTANCE_ISSUER = "https://keycloak.mtmf.test:29543/realms/mtmf-dev"
ACCEPTANCE_JWKS = ACCEPTANCE_ISSUER + "/protocol/openid-connect/certs"
ACCEPTANCE_ADMIN_BASE = "https://keycloak.mtmf.test:29543"
ACCEPTANCE_SERVICE_BASE = "http://127.0.0.1:29501"
ACCEPTANCE_REFERENCE_BASE = "http://127.0.0.1:29511"
ACCEPTANCE_POSTGRES_PORT = 29532
ACCEPTANCE_KC_HTTPS_PORT = 29543
ACCEPTANCE_SERVICE_PORT = 29501
ACCEPTANCE_REFERENCE_APP_PORT = 29511
ACCEPTANCE_REALM = "mtmf-dev"
ACCEPTANCE_APPLICATION_KEY = fixture.DEFAULT_APPLICATION_KEY
ACCEPTANCE_CLIENT_ID = f"mtmf-{ACCEPTANCE_APPLICATION_KEY}"
ACCEPTANCE_ALLOWED_USERNAME = "mtmf-user-alice"
ACCEPTANCE_DENIED_USERNAME = "mtmf-user-bob"
ACCEPTANCE_CA_DIR = Path(os.environ.get("MTMF_PR20A_CA_DIR", "/tmp/mtmf-pr20a-acceptance-ca"))
ACCEPTANCE_SECRET_DIR = Path("/tmp/mtmf-pr20a-acceptance-secrets")
ACCEPTANCE_FIXTURE_DIR = Path("/tmp/mtmf-pr20a-acceptance-fixtures")
LIVE_TEST = "tests/e2e/reference_app/test_pr20a_live_reference_app.py"
CERT_SCRIPT = REPO_ROOT / "scripts" / "mtmf-dev-certs.py"
PROBE_SCRIPT = REPO_ROOT / "scripts" / "mtmf-dev-probe.py"
NSSWITCH_FILE = REPO_ROOT / "dev" / "nsswitch.conf"
PROVISION_SCRIPT = REPO_ROOT / "scripts" / "mtmf-provision-roles.py"
REALM_SCRIPT = REPO_ROOT / "dev" / "keycloak" / "setup-realm.py"
DEFAULT_PROJECT = "mtmf"
DEFAULT_KEYCLOAK_VOLUME = "mtmf-dev-keycloak-data"

ALLOWED_DOCUMENT_ID = "d0c0a1e0-0001-4000-8000-000000000001"
OTHER_TENANT_DOCUMENT_ID = "d0c0a1e0-0002-4000-8000-000000000002"
OTHER_TENANT_ID = "d0c0a1e0-0003-4000-8000-000000000003"
ALLOWED_DOCUMENT_TITLE = "Reference Document"
ALLOWED_DOCUMENT_BODY = "reference-app-body-v1"


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
    ACCEPTANCE_SECRET_DIR.mkdir(mode=0o711, exist_ok=True)
    # Traverse-only (0711): the unprivileged reference app must reach its
    # 0600 secret without the directory being listable; the secret files
    # themselves never gain group/other permission.
    os.chmod(ACCEPTANCE_SECRET_DIR, 0o711)

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
    ACCEPTANCE_CA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    for subcommand in ("generate", "harden", "check"):
        _run([sys.executable, str(CERT_SCRIPT), "--dir", str(ACCEPTANCE_CA_DIR), subcommand])
    _generate_service_leaf()


def _generate_service_leaf() -> None:
    """Generate an additional leaf for the internal MTMF TLS terminator.

    Signed by the same acceptance CA so the reference app can trust both the
    Keycloak issuer leaf and the MTMF service leaf with one CA bundle. Never
    overwrites an existing valid pair; rotates only when absent.
    """
    cert = ACCEPTANCE_CA_DIR / "mtmf-service.crt"
    key = ACCEPTANCE_CA_DIR / "mtmf-service.key"
    if cert.is_file() and key.is_file():
        return
    with tempfile.TemporaryDirectory(prefix="mtmf-pr20a-leaf-") as work:
        csr = Path(work) / "service.csr"
        ext = Path(work) / "service-ext.cnf"
        ext.write_text(
            "\n".join(
                [
                    "basicConstraints=critical,CA:FALSE",
                    "keyUsage=critical,digitalSignature,keyEncipherment",
                    "extendedKeyUsage=serverAuth",
                    "subjectAltName=DNS:mtmf.mtmf.test",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(csr),
                "-subj",
                "/CN=mtmf.mtmf.test",
            ]
        )
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ACCEPTANCE_CA_DIR / "dev-ca.crt"),
                "-CAkey",
                str(ACCEPTANCE_CA_DIR / "dev-ca.key"),
                "-CAcreateserial",
                "-out",
                str(cert),
                "-days",
                "825",
                "-sha256",
                "-extfile",
                str(ext),
            ]
        )
    os.chmod(key, 0o600)
    os.chmod(cert, 0o644)


def _build_env(secrets_: dict[str, str], dotenv: dict[str, str]) -> dict[str, str]:
    env = dict(os.environ)
    env.update({k: v for k, v in dotenv.items() if k.startswith("MTMF_")})
    env["MTMF_SERVICE_DEPLOYMENT_MODE"] = "development"
    env["MTMF_PR20A_DB_NAME"] = "mtmf"
    env["MTMF_PR20A_DB_USER"] = "mtmf"
    env["MTMF_PR20A_DB_PASSWORD"] = secrets_["db_password"]
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
    env["MTMF_PR20A_POSTGRES_PORT"] = str(ACCEPTANCE_POSTGRES_PORT)
    env["MTMF_PR20A_KC_HTTPS_PORT"] = str(ACCEPTANCE_KC_HTTPS_PORT)
    env["MTMF_PR20A_SERVICE_PORT"] = str(ACCEPTANCE_SERVICE_PORT)
    env["MTMF_PR20A_REFERENCE_APP_PORT"] = str(ACCEPTANCE_REFERENCE_APP_PORT)
    env["MTMF_PR20A_APPLICATION_KEY"] = ACCEPTANCE_APPLICATION_KEY
    env["MTMF_PR20A_CLIENT_ID"] = ACCEPTANCE_CLIENT_ID
    env["MTMF_PR20A_APPLICATION_ID"] = str(fixture.application_id(ACCEPTANCE_APPLICATION_KEY))
    env["MTMF_PR20A_ALLOWED_USERNAME"] = ACCEPTANCE_ALLOWED_USERNAME
    env["MTMF_PR20A_DENIED_USERNAME"] = ACCEPTANCE_DENIED_USERNAME
    env["MTMF_PR20A_FIXTURE_DIR"] = str(ACCEPTANCE_FIXTURE_DIR)
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
    env["MTMF_DEV_TENANT_KEY"] = "dev"
    env["MTMF_DEV_TENANT_NAME"] = "Development Tenant"
    env["MTMF_PR20A_KC_BASE"] = ACCEPTANCE_ADMIN_BASE
    env["MTMF_PR20A_CA_FILE"] = str(ACCEPTANCE_CA_DIR / "dev-ca.crt")
    env["MTMF_PR20A_ADMIN_USERNAME"] = "mtmf-admin"
    env["MTMF_PR20A_ADMIN_PASSWORD"] = secrets_["admin_password"]
    env["MTMF_PR20A_USER_PASSWORD"] = secrets_["user_password"]
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
    for volume in ("mtmf-postgres-data", "mtmf-dev-keycloak-data", "reference-app-data"):
        if not re.search(rf"^\s+{re.escape(volume)}:\s*$", text, flags=re.MULTILINE):
            raise AcceptanceError(f"acceptance Compose is missing project volume {volume}")


def _verify_issuer_constants() -> None:
    if ACCEPTANCE_ISSUER != "https://keycloak.mtmf.test:29543/realms/mtmf-dev":
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
    published = subprocess.run(
        ["podman", "ps", "--format", "{{.Ports}}"], capture_output=True, text=True
    ).stdout
    for port in (
        ACCEPTANCE_KC_HTTPS_PORT,
        ACCEPTANCE_POSTGRES_PORT,
        ACCEPTANCE_SERVICE_PORT,
        ACCEPTANCE_REFERENCE_APP_PORT,
    ):
        if f":{port}->" in published:
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
    print("PR 20A acceptance preflight passed", flush=True)
    return 0


def _read_fixture_mapping() -> dict[str, Any]:
    path = ACCEPTANCE_FIXTURE_DIR / "reference-app-fixture.json"
    if not path.is_file():
        raise AcceptanceError("the reference-app fixture mapping was not generated")
    return json.loads(path.read_text(encoding="utf-8"))


def _write_documents_manifest(tenant_id: str) -> None:
    ACCEPTANCE_FIXTURE_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    manifest = {
        "documents": [
            {
                "document_id": ALLOWED_DOCUMENT_ID,
                "tenant_id": tenant_id,
                "title": ALLOWED_DOCUMENT_TITLE,
                "body": ALLOWED_DOCUMENT_BODY,
            },
            {
                "document_id": OTHER_TENANT_DOCUMENT_ID,
                "tenant_id": OTHER_TENANT_ID,
                "title": "Other Tenant Document",
                "body": "other-tenant-body",
            },
        ]
    }
    (ACCEPTANCE_FIXTURE_DIR / "documents.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )


def _reference_app_container() -> str:
    name = f"{ACCEPTANCE_PROJECT}_reference-app_1"
    result = _run(["podman", "ps", "--filter", f"name={name}", "--format", "{{.Names}}"])
    names = [line for line in result.stdout.splitlines() if line.strip()]
    if names != [name]:
        raise AcceptanceError("the reference-app container is not the expected acceptance one")
    return name


def _seed_reference_store(env: dict[str, str]) -> None:
    container = _reference_app_container()
    _run(
        [
            "podman",
            "exec",
            container,
            "python",
            "-m",
            "mtmf_reference_app.fixture_loader",
            "--manifest",
            "/run/fixtures/documents.json",
            "--sqlite",
            "/data/reference-app.db",
        ],
        env=env,
    )


def up() -> int:
    _verify_issuer_constants()
    _validate_compose_isolation()
    _require_tools()
    _assert_owned()
    ACCEPTANCE_FIXTURE_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    _prepare_ca()
    staged = _stage_secrets()
    env = _build_env(staged, _read_dotenv())
    _run(_compose("build", "initializer", "service", "reference-app"), env=env)
    _run(_compose("up", "-d", "postgres", "keycloak", "forwarder"), env=env)
    _wait_postgres_healthy()
    _wait_http(
        f"{ACCEPTANCE_ADMIN_BASE}/realms/master/.well-known/openid-configuration",
        timeout=180.0,
        ca_file=_ca_file(),
    )
    _run([sys.executable, str(PROVISION_SCRIPT)], env=env)
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
    mapping = _read_fixture_mapping()
    _write_documents_manifest(str(mapping["tenant_id"]))
    _run(_compose("up", "-d", "service", "service-tls-proxy", "reference-app"), env=env)
    _wait_http(f"{ACCEPTANCE_SERVICE_BASE}/health/ready", timeout=120.0)
    _wait_http(f"{ACCEPTANCE_REFERENCE_BASE}/health/ready", timeout=120.0)
    _seed_reference_store(env)
    print("PR 20A acceptance stack is ready", flush=True)
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
    mapping = _read_fixture_mapping()
    # The client secret is owned by the unprivileged reference-app user, so the
    # host launcher reads it through the already-deployed container (stdout, not
    # a command line) and immediately redacts it.
    container = _reference_app_container()
    secret_result = _run(
        [
            "podman",
            "exec",
            container,
            "cat",
            "/run/secrets/mtmf-evidence-same-client.secret",
        ]
    )
    client_secret = secret_result.stdout.strip()
    if not client_secret:
        raise AcceptanceError("the reference-app client secret could not be read")
    _SECRET_VALUES.append(client_secret)
    env = _build_env(staged, _read_dotenv())
    env["MTMF_PR20A_LIVE"] = "1"
    env["MTMF_PR20A_REFERENCE_APP_URL"] = ACCEPTANCE_REFERENCE_BASE
    env["MTMF_PR20A_KC_BASE"] = ACCEPTANCE_ADMIN_BASE
    env["MTMF_PR20A_CA_FILE"] = _ca_file()
    env["MTMF_PR20A_CLIENT_ID"] = ACCEPTANCE_CLIENT_ID
    env["MTMF_PR20A_CLIENT_SECRET"] = client_secret
    env["MTMF_PR20A_TENANT_ID"] = str(mapping["tenant_id"])
    env["MTMF_PR20A_APPLICATION_ID"] = str(mapping["application_id"])
    env["MTMF_PR20A_ALLOWED_USERNAME"] = ACCEPTANCE_ALLOWED_USERNAME
    env["MTMF_PR20A_DENIED_USERNAME"] = ACCEPTANCE_DENIED_USERNAME
    env["MTMF_PR20A_DOCUMENT_ID"] = ALLOWED_DOCUMENT_ID
    env["MTMF_PR20A_OTHER_TENANT_DOCUMENT_ID"] = OTHER_TENANT_DOCUMENT_ID
    env["MTMF_PR20A_EXPECTED_TITLE"] = ALLOWED_DOCUMENT_TITLE
    env["MTMF_PR20A_EXPECTED_BODY"] = ALLOWED_DOCUMENT_BODY
    env["MTMF_PR20A_REFERENCE_CONTAINER"] = _reference_app_container()
    env["SSL_CERT_FILE"] = _ca_file()
    env.pop("MTMF_MIGRATOR_DATABASE_URL", None)
    env.pop("MTMF_RUNTIME_DATABASE_URL", None)
    return env


def _verify_deployed_reference_app() -> str:
    """Read-only proof that the acceptance Compose reference app is the target."""
    name = _reference_app_container()
    payload = json.loads(_run(["podman", "inspect", name]).stdout)[0]
    labels = (payload.get("Config") or {}).get("Labels") or {}
    if labels.get("io.podman.compose.project") != ACCEPTANCE_PROJECT:
        raise AcceptanceError("reference-app container project label mismatch")
    if (payload.get("State") or {}).get("Status") != "running":
        raise AcceptanceError("reference-app container is not running")
    published = _run(["podman", "port", name, "8080/tcp"], check=False)
    if f"127.0.0.1:{ACCEPTANCE_REFERENCE_APP_PORT}" not in published.stdout:
        raise AcceptanceError("reference app is not published on the expected loopback port")
    _wait_http(f"{ACCEPTANCE_REFERENCE_BASE}/health/ready", timeout=30)
    return str(payload.get("Id", ""))[:12]


def test() -> int:
    _assert_owned()
    container_id = _verify_deployed_reference_app()
    env = _test_env()
    result = subprocess.run(
        ["uv", "run", "--no-sync", "pytest", LIVE_TEST, "-q", "--no-cov", "-p", "no:cacheprovider"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    output = _redact((result.stdout or "") + (result.stderr or ""))
    print(output.rstrip()[-4000:], flush=True)
    if result.returncode != 0:
        raise AcceptanceError("live L01-L05 acceptance failed")
    if re.search(r"(?<![0-9])5 passed", output) is None:
        raise AcceptanceError("live acceptance did not report exactly five passed tests")
    if re.search(r"\bskipped|\bxfailed|\bxpassed|\bfailed|\berror", output):
        raise AcceptanceError("live acceptance reported skips, xfails or failures")
    print(f"reference-app container {container_id}: 5 passed, 0 skipped", flush=True)
    return 0


def down() -> int:
    _assert_owned()
    env = _build_env(_stage_secrets(), _read_dotenv())
    _run(_compose("down"), env=env, check=False)
    return 0


def recreate() -> int:
    _assert_owned()
    env = _build_env(_stage_secrets(), _read_dotenv())
    _run(_compose("down", "-v"), env=env, check=False)
    for path in (ACCEPTANCE_SECRET_DIR, ACCEPTANCE_FIXTURE_DIR):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
    return 0


def acceptance() -> int:
    before = _default_inventory()
    recreate()
    up()
    test()
    print("COLD-01 PASS", flush=True)
    up()
    test()
    print("REPEAT-01 PASS", flush=True)
    recreate()
    up()
    test()
    print("RECREATE-01 PASS", flush=True)
    after = _default_inventory()
    if before != after:
        raise AcceptanceError("default stack inventory changed during acceptance")
    print("default stack inventory unchanged", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PR 20A isolated acceptance orchestrator")
    parser.add_argument(
        "command",
        choices=("preflight", "up", "test", "down", "recreate", "acceptance"),
    )
    args = parser.parse_args(argv)
    try:
        return {
            "preflight": preflight,
            "up": up,
            "test": test,
            "down": down,
            "recreate": recreate,
            "acceptance": acceptance,
        }[args.command]()
    except AcceptanceError as exc:
        print(f"acceptance error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
