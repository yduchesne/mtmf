#!/usr/bin/env python3
"""Portable MTMF development stack orchestration (PR 17 Amendment #1, G3; PR 17-C).

`podman-compose 1.0.6` does not honor
`depends_on: condition: service_completed_successfully`, so it cannot order
the privileged one-shot initializer before the unprivileged HTTP service.
This development-only wrapper performs that ordering explicitly and fails
closed at every step:

    prepare canonical CA/leaf (owner-map the key)
    ->  postgres + keycloak + forwarder up  ->  wait for health
    ->  preflight the canonical issuer from host AND container namespaces
    ->  migrations + privilege postflight + one-shot initializer
    ->  unprivileged service up  ->  wait for readiness 200

It manages only the explicit `mtmf` Compose project and never discovers,
prunes, or mutates resources owned by another application. Privileged
credentials are consumed only by the one-shot initializer container; the
HTTP service environment never receives them (see `compose.dev.yaml`).

Usage:
    python scripts/mtmf-dev-stack.py up
    python scripts/mtmf-dev-stack.py preflight
    python scripts/mtmf-dev-stack.py status
    python scripts/mtmf-dev-stack.py down
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROJECT = "mtmf"
COMPOSE_FILES = ("-f", "compose.yaml", "-f", "compose.dev.yaml")
SERVICE_READY_URL = "http://127.0.0.1:28001/health/ready"
SERVICE_LIVE_URL = "http://127.0.0.1:28001/health/live"

#: Canonical development issuer authority (PR 17-C). The same hostname/port
#: appears in discovery `issuer`, token `iss`, `MTMF_AUTH_ISSUER` and the JWKS
#: URI; containers resolve it through the MTMF-owned forwarder network alias.
CANONICAL_KC_HOSTNAME = "keycloak.mtmf.test"
CANONICAL_KC_PORT = 28443
FORWARDER_CONTAINER = "mtmf_forwarder_1"
CA_CERT_IN_CONTAINER = "/certs/mtmf-ca.crt"
CERT_SCRIPT = REPO_ROOT / "scripts" / "mtmf-dev-certs.py"
PROBE_SCRIPT = REPO_ROOT / "scripts" / "mtmf-dev-probe.py"


class OrchestrationError(RuntimeError):
    """The development stack could not be brought up safely."""


def _secret_values() -> list[str]:
    """Return bounded secret values to redact from subprocess output.

    ``podman-compose`` echoes the fully substituted ``podman run`` command,
    including environment values, so every captured subprocess output is
    redacted before it is printed. Secrets come from the launcher's own
    environment and are never written to disk.
    """
    values: list[str] = []
    for name, value in os.environ.items():
        if not value or len(value) < 4:
            continue
        upper = name.upper()
        if any(hint in upper for hint in ("PASSWORD", "SECRET", "TOKEN")) or upper.endswith(
            "DATABASE_URL"
        ):
            values.append(value)
    # Longest first so a shorter secret cannot leave a longer one partially visible.
    return sorted(set(values), key=len, reverse=True)


def _redact(text: str) -> str:
    """Replace any known secret value in ``text`` with a redaction marker."""
    for value in _secret_values():
        text = text.replace(value, "<redacted>")
    return text


def _run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run a command, capturing and redacting its output before printing."""
    print(f"+ {' '.join(args)}", flush=True)
    result = subprocess.run(args, cwd=REPO_ROOT, capture_output=True, text=True)
    combined = _redact((result.stdout or "") + (result.stderr or ""))
    if combined.strip():
        print(combined.rstrip(), flush=True)
    if check and result.returncode != 0:
        raise OrchestrationError(f"command failed with exit {result.returncode}: {' '.join(args)}")
    return result


def _compose(*args: str) -> list[str]:
    return ["podman-compose", "-p", PROJECT, *COMPOSE_FILES, *args]


def _wait_http(url: str, *, timeout: float, ca_file: str | None = None) -> None:
    """Poll ``url`` until it answers 2xx/3xx or the deadline expires."""
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            context = None
            if ca_file:
                import ssl

                context = ssl.create_default_context(cafile=ca_file)
            with urllib.request.urlopen(url, timeout=2, context=context) as response:
                if 200 <= response.status < 400:
                    return
        except (urllib.error.URLError, OSError, ValueError) as exc:
            last_error = exc
        time.sleep(1.0)
    raise OrchestrationError(f"timed out waiting for {url}: {last_error}")


def _require_development() -> None:
    mode = os.environ.get("MTMF_SERVICE_DEPLOYMENT_MODE", "development").strip()
    if mode != "development":
        raise OrchestrationError(
            "the development stack launcher refuses any non-development profile"
        )


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise OrchestrationError(f"required environment {name} is not set")
    return value


def _ca_dir() -> Path:
    """Return the configured development CA directory."""
    value = os.environ.get("MTMF_DEV_CA_DIR", "").strip()
    return Path(value) if value else Path("/tmp/mtmf-dev-ca")


def _ca_cert_file() -> Path:
    """Return the configured development CA certificate path."""
    override = os.environ.get("MTMF_PR14_KC_CA_FILE", "").strip()
    return Path(override) if override else _ca_dir() / "dev-ca.crt"


def _prepare_certificates() -> None:
    """Generate (idempotently) and container-harden the development CA/leaf."""
    _run([sys.executable, str(CERT_SCRIPT), "--dir", str(_ca_dir()), "generate"])
    _run([sys.executable, str(CERT_SCRIPT), "--dir", str(_ca_dir()), "harden"])


def _probe_host(issuer: str) -> None:
    """Verify the canonical issuer from the WSL host namespace."""
    _run(
        [
            sys.executable,
            str(PROBE_SCRIPT),
            "--issuer",
            issuer,
            "--ca-file",
            str(_ca_cert_file()),
            "--namespace",
            "host",
        ]
    )


def _probe_container(issuer: str) -> None:
    """Verify the canonical issuer from inside the isolated MTMF network.

    Runs a fresh, throwaway container that receives the same
    ``keycloak.mtmf.test`` mapping as the initializer and service, so the
    check proves the canonical authority is reachable and TLS-verified on the
    real container network path (not the host's loopback).
    """
    forwarder_ip = os.environ.get("MTMF_DEV_FORWARDER_IP", "").strip() or _forwarder_ip()
    _run(
        [
            "podman",
            "run",
            "--rm",
            "--network",
            f"{PROJECT}_default",
            "--add-host",
            f"{CANONICAL_KC_HOSTNAME}:{forwarder_ip}",
            "-v",
            f"{PROBE_SCRIPT}:/app/mtmf-dev-probe.py:ro",
            "-v",
            f"{_ca_cert_file()}:/certs/mtmf-ca.crt:ro",
            "docker.io/library/python:3.14-slim",
            "python",
            "/app/mtmf-dev-probe.py",
            "--issuer",
            issuer,
            "--ca-file",
            CA_CERT_IN_CONTAINER,
            "--namespace",
            "container",
        ]
    )


def _forwarder_ip() -> str:
    """Return the running forwarder's IP on the MTMF network."""
    result = subprocess.run(
        [
            "podman",
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
            FORWARDER_CONTAINER,
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    addresses = (result.stdout or "").split()
    if result.returncode != 0 or not addresses:
        raise OrchestrationError("cannot determine the MTMF forwarder container address")
    return addresses[0]


def _database_url_for_containers(name: str) -> str:
    """Rewrite a host database URL to the isolated Compose network.

    Containers cannot use the host loopback; the database is addressed by its
    Compose service name (``postgres``) and internal port (``5432``).
    """
    value = os.environ.get(name, "").strip()
    if not value:
        raise OrchestrationError(f"required environment {name} is not set")
    parsed = urllib.parse.urlsplit(value)
    if not parsed.hostname:
        raise OrchestrationError(f"{name} is not a usable database URL")
    userinfo = ""
    if parsed.username is not None:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo += ":" + parsed.password
        userinfo += "@"
    netloc = f"{userinfo}postgres:5432"
    return urllib.parse.urlunsplit(
        (parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment)
    )


def _wait_keycloak_http(admin_base: str, ca_file: str) -> None:
    """Wait for the Keycloak master-realm discovery endpoint over TLS."""
    _wait_http(
        f"{admin_base.rstrip('/')}/realms/master/.well-known/openid-configuration",
        timeout=180,
        ca_file=ca_file or None,
    )


def _probe_until_stable(
    probe: Callable[[str], None], issuer: str, *, timeout: float = 60.0
) -> None:
    """Retry a canonical-issuer probe until it passes or the deadline expires.

    Keycloak's HTTPS listener and the forwarder can be briefly unavailable
    while containers are (re)created; a transient failure is retried rather
    than reported as a topology failure. A persistent failure still fails
    closed.
    """
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            probe(issuer)
            return
        except OrchestrationError as exc:
            last_error = exc
            time.sleep(2.0)
    raise OrchestrationError(f"canonical issuer probe did not pass: {last_error}")


def _postgres_inspect() -> None:
    """Require the MTMF PostgreSQL healthcheck to report healthy."""
    # Container name is project-scoped and deterministic for project `mtmf`.
    result = _run(
        ["podman", "inspect", "--format", "{{.State.Health.Status}}", "mtmf_postgres_1"],
        check=False,
    )
    if result.returncode != 0 or (result.stdout or "").strip() != "healthy":
        raise OrchestrationError("the MTMF PostgreSQL container is not healthy")


def up() -> int:
    """Bring up the development stack in the required order."""
    _require_development()
    _required_env("MTMF_MIGRATOR_DATABASE_URL")
    _required_env("MTMF_RUNTIME_DATABASE_URL")
    issuer = _required_env("MTMF_AUTH_ISSUER")
    if CANONICAL_KC_HOSTNAME not in issuer:
        raise OrchestrationError(
            "MTMF_AUTH_ISSUER must use the canonical development authority "
            f"{CANONICAL_KC_HOSTNAME}:{CANONICAL_KC_PORT}"
        )

    # Containers cannot reach the host loopback: address the database by its
    # Compose service name over the isolated network.
    os.environ["MTMF_MIGRATOR_DATABASE_URL"] = _database_url_for_containers(
        "MTMF_MIGRATOR_DATABASE_URL"
    )
    os.environ["MTMF_RUNTIME_DATABASE_URL"] = _database_url_for_containers(
        "MTMF_RUNTIME_DATABASE_URL"
    )

    # The canonical leaf key must be owner-mapped to the Keycloak container UID
    # before Compose starts; never fall back to a world-readable private key.
    _prepare_certificates()

    _run(_compose("up", "-d", "postgres", "keycloak", "forwarder"))
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            _postgres_inspect()
            break
        except OrchestrationError:
            time.sleep(2.0)
    else:
        raise OrchestrationError("PostgreSQL did not become healthy within 180s")
    _wait_keycloak_http(_required_env("MTMF_AUTH_ADMIN_BASE"), str(_ca_cert_file()))

    # Pin the canonical authority to the forwarder for the initializer/service
    # (the copied host `/etc/hosts` entry must not shadow it) and prove the
    # canonical issuer path from both namespaces before writing state.
    os.environ["MTMF_DEV_FORWARDER_IP"] = _forwarder_ip()
    _probe_until_stable(_probe_host, issuer)
    _probe_until_stable(_probe_container, issuer)

    # Privileged one-shot: migrations + postflight + fixture reconciliation.
    _run(_compose("run", "--rm", "--no-deps", "initializer"))

    # Unprivileged HTTP service, only after a successful initializer exit.
    _run(_compose("up", "-d", "service"))
    _wait_http(SERVICE_READY_URL, timeout=120)
    print("MTMF development stack is ready", flush=True)
    return 0


def preflight() -> int:
    """Run the canonical-issuer preflight from host and container namespaces."""
    _require_development()
    issuer = _required_env("MTMF_AUTH_ISSUER")
    if CANONICAL_KC_HOSTNAME not in issuer:
        raise OrchestrationError(
            "MTMF_AUTH_ISSUER must use the canonical development authority "
            f"{CANONICAL_KC_HOSTNAME}:{CANONICAL_KC_PORT}"
        )
    _probe_host(issuer)
    _probe_container(issuer)
    print("canonical issuer preflight passed from host and container namespaces", flush=True)
    return 0


HOST_NETWORK_SERVICE_NAME = "mtmf-service-hostnet"
HOST_NETWORK_IMAGE = "localhost/mtmf-service:dev"

#: Deterministic ownership labels applied to the host-network service container.
OWNERSHIP_LABELS = {
    "io.mtmf.owner": "mtmf",
    "io.mtmf.component": "http-service",
    "io.mtmf.deployment-mode": "development",
}
OWNERSHIP_LABELS_ARGS: list[str] = [
    item for key, value in OWNERSHIP_LABELS.items() for item in ("--label", f"{key}={value}")
]


def _inspect_container(name: str) -> dict[str, object] | None:
    """Return container metadata, or ``None`` when it is verifiably absent."""
    result = subprocess.run(
        ["podman", "inspect", name], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").lower()
        if "no such" in stderr or "unable to find" in stderr or "does not exist" in stderr:
            return None
        raise OrchestrationError(f"cannot inspect container {name!r}")
    try:
        payload = json.loads(result.stdout)
    except ValueError as exc:
        raise OrchestrationError(f"malformed inspect output for {name!r}") from exc
    if not isinstance(payload, list) or not payload:
        return None
    first = payload[0]
    return first if isinstance(first, dict) else None


def _cleanup_host_network_service() -> None:
    """Remove the host-network service only when ownership is proven.

    An absent container is an idempotent success. A present container whose
    ownership labels do not match exactly is a foreign/legacy resource: the
    cleanup aborts and never removes it. Any removal error propagates.
    """
    info = _inspect_container(HOST_NETWORK_SERVICE_NAME)
    if info is None:
        return
    labels = (info.get("Config") or {}).get("Labels") or {}  # type: ignore[union-attr]
    mismatched = [key for key, value in OWNERSHIP_LABELS.items() if labels.get(key) != value]
    if mismatched:
        raise OrchestrationError(
            f"refusing to remove {HOST_NETWORK_SERVICE_NAME!r}: it is not a proven "
            "MTMF-owned container (ownership labels do not match)"
        )
    result = subprocess.run(
        ["podman", "rm", "-f", HOST_NETWORK_SERVICE_NAME],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise OrchestrationError(f"failed to remove {HOST_NETWORK_SERVICE_NAME!r}")


READER_SECRET_MOUNT = "/run/secrets/mtmf-attestation-reader"


def _auth_env() -> list[str]:
    """Return the approved attestation-reader environment (never migrator/admin)."""
    names = (
        "MTMF_AUTH_ISSUER",
        "MTMF_AUTH_SERVICE_AUDIENCE",
        "MTMF_AUTH_USER_AUDIENCE",
        "MTMF_AUTH_JWKS_URI",
        "MTMF_AUTH_EXPECTED_MANIFEST",
        "MTMF_AUTH_EXPECTED_CLIENT_POLICY",
        "MTMF_AUTH_ADMIN_BASE",
        "MTMF_AUTH_ADMIN_REALM",
        "MTMF_AUTH_ATTESTATION_CLIENT_ID",
        "MTMF_AUTH_ALLOW_SHARED_AUDIENCE",
    )
    env: list[str] = []
    for name in names:
        value = os.environ.get(name, "")
        if value:
            env.extend(["-e", f"{name}={value}"])
    return env


def _reader_secret_file() -> Path:
    """Return a 0600 file holding the reader secret, without exposing it in argv."""
    file_hint = os.environ.get("MTMF_AUTH_ATTESTATION_CLIENT_SECRET_FILE", "").strip()
    if file_hint:
        return Path(file_hint)
    secret = os.environ.get("MTMF_AUTH_ATTESTATION_CLIENT_SECRET", "").strip()
    if not secret:
        raise OrchestrationError("MTMF_AUTH_ATTESTATION_CLIENT_SECRET or _FILE is required")
    directory = Path(os.environ.get("MTMF_DEV_SECRET_DIR", "/tmp/mtmf-dev-secrets"))
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / "mtmf-attestation-reader.secret"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(secret)
    return target


def up_host_network() -> int:
    """Approved development-only host-network topology (D3, 2026-10-12).

    Starts PostgreSQL + Keycloak, runs the privileged one-shot initializer, then
    runs the unprivileged HTTP service in a Podman host-network container bound
    to ``127.0.0.1`` only. The runtime container receives the restricted runtime
    database credential and the approved attestation-reader credential, never a
    migrator/owner/root/bootstrap credential. Development profile only.
    """
    _require_development()
    _required_env("MTMF_RUNTIME_DATABASE_URL")
    _required_env("MTMF_MIGRATOR_DATABASE_URL")
    _required_env("MTMF_AUTH_ISSUER")
    ca_file = os.environ.get("MTMF_PR14_KC_CA_FILE", "")
    if not ca_file:
        raise OrchestrationError("MTMF_PR14_KC_CA_FILE is required for the host-network mode")

    _run(_compose("up", "-d", "postgres", "keycloak"))
    _postgres_inspect()
    _wait_http(
        f"{_required_env('MTMF_AUTH_ADMIN_BASE').rstrip('/')}/realms/master/.well-known/"
        "openid-configuration",
        timeout=180,
        ca_file=ca_file,
    )
    _run(_compose("run", "--rm", "--no-deps", "initializer"))

    _cleanup_host_network_service()
    reader_secret = _reader_secret_file()
    run_args = [
        "podman",
        "run",
        "-d",
        "--name",
        HOST_NETWORK_SERVICE_NAME,
        *OWNERSHIP_LABELS_ARGS,
        "--network=host",
        "-v",
        f"{ca_file}:/certs/dev-ca.crt:ro",
        "-v",
        f"{reader_secret}:{READER_SECRET_MOUNT}:ro",
        "-e",
        f"MTMF_AUTH_ATTESTATION_CLIENT_SECRET_FILE={READER_SECRET_MOUNT}",
        "-e",
        "MTMF_SERVICE_DEPLOYMENT_MODE=development",
        "-e",
        "MTMF_SERVICE_HOST=127.0.0.1",
        "-e",
        "MTMF_SERVICE_PORT=28001",
        "-e",
        "MTMF_SERVICE_INITIALIZED=1",
        "-e",
        f"MTMF_RUNTIME_DATABASE_URL={os.environ['MTMF_RUNTIME_DATABASE_URL']}",
        "-e",
        "MTMF_RUNTIME_STATEMENT_TIMEOUT_MS="
        + os.environ.get("MTMF_RUNTIME_STATEMENT_TIMEOUT_MS", "10000"),
        "-e",
        "MTMF_RUNTIME_LOCK_TIMEOUT_MS=" + os.environ.get("MTMF_RUNTIME_LOCK_TIMEOUT_MS", "3000"),
        "-e",
        "SSL_CERT_FILE=/certs/dev-ca.crt",
        *_auth_env(),
        HOST_NETWORK_IMAGE,
    ]
    _run(run_args)
    _wait_http(SERVICE_READY_URL, timeout=120)
    print("MTMF development host-network service is ready on 127.0.0.1:28001", flush=True)
    return 0


def status() -> int:
    """Print project-scoped container status and liveness/readiness."""
    _run(_compose("ps"), check=False)
    for label, url in (("live", SERVICE_LIVE_URL), ("ready", SERVICE_READY_URL)):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                print(f"{label}: {response.status}")
        except (urllib.error.URLError, OSError) as exc:
            print(f"{label}: unavailable ({exc})")
    return 0


def down() -> int:
    """Stop the MTMF-owned development stack (volumes preserved)."""
    _cleanup_host_network_service()
    _run(_compose("down"))
    return 0


def down_volumes() -> int:
    """Destroy only MTMF-owned development resources and volumes."""
    _cleanup_host_network_service()
    _run(_compose("down", "-v"))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse a subcommand and run the development stack operation."""
    parser = argparse.ArgumentParser(description="MTMF development stack orchestrator")
    parser.add_argument(
        "command", choices=("up", "up-host-network", "status", "preflight", "down", "destroy")
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "up":
            return up()
        if args.command == "up-host-network":
            return up_host_network()
        if args.command == "preflight":
            return preflight()
        if args.command == "status":
            return status()
        if args.command == "down":
            return down()
        return down_volumes()
    except (OrchestrationError, subprocess.CalledProcessError) as exc:
        print(f"development stack error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
