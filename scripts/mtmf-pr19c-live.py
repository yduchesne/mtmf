#!/usr/bin/env python3
"""Bounded, noninteractive PR 19C live acceptance orchestrator.

Recreates an MTMF-owned, disposable development fixture (PostgreSQL 18 +
canonical ``mtmf-dev`` Keycloak + TLS forwarder + restricted service),
provisions the canonical realm through the existing setup tool, runs the
authoritative PR 19C live acceptance against the real issuer, and tears the
disposable fixture down again.

Usage::

    python scripts/mtmf-pr19c-live.py --fresh          # disposable cold start
    python scripts/mtmf-pr19c-live.py                  # idempotent reuse
    python scripts/mtmf-pr19c-live.py --keep           # retain fixture for diagnosis

The script never prints or logs secrets, never edits /etc/hosts or the trust
store, never uses a non-canonical issuer, and only ever manages the explicit
MTMF-owned acceptance Compose project (default ``mtmf-pr19c-acceptance``).
The canonical host ports are fixed by the Compose model, so the disposable
project requires the default ``mtmf`` stack to be stopped first; pass
``--stop-default`` to stop those MTMF-owned containers (volumes are preserved).
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROJECT = "mtmf-pr19c-acceptance"
DEFAULT_STACK_PROJECT = "mtmf"
CANONICAL_ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
CANONICAL_REALM = "mtmf-dev"
CANONICAL_CA_DIR = Path("/tmp/mtmf-dev-ca")
ACCEPTANCE_CLIENTS = ("mtmf-evidence-same-client",)
LIVE_TEST = "tests/integration/postgres/test_pr19c_live_management.py"
_EXTRA_COMPOSE = "compose.pr19c-acceptance.yaml"
COMPOSE_FILES = ("-f", "compose.yaml", "-f", "compose.dev.yaml")


class AcceptanceError(RuntimeError):
    """A bounded acceptance-orchestration failure (never carries secrets)."""


#: Generated secret values redacted from any captured/printed text.
_SECRET_VALUES: list[str] = []


def _redact(text: str) -> str:
    """Replace generated secret values with a redaction marker."""
    for value in sorted(_SECRET_VALUES, key=len, reverse=True):
        if value and len(value) >= 4:
            text = text.replace(value, "<redacted>")
    return text


def _run(
    args: list[str],
    *,
    env: dict[str, str] | None = None,
    check: bool = True,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    display = _redact(" ".join(args))
    result = subprocess.run(
        args, cwd=cwd or REPO_ROOT, env=env, capture_output=True, text=True, check=False
    )
    if check and result.returncode != 0:
        detail = _redact((result.stderr or result.stdout or "").strip())
        tail = detail.splitlines()[-1] if detail else "no output"
        raise AcceptanceError(f"command failed ({display} ...): {tail}")
    return result


def _read_dotenv() -> dict[str, str]:
    values: dict[str, str] = {}
    path = REPO_ROOT / ".env"
    if not path.is_file():
        raise AcceptanceError(".env with MTMF_* PostgreSQL configuration is required")
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip()
    return values


def _stage_secrets(run_dir: Path) -> dict[str, str]:
    """Create an owner-only run directory and generate fresh credentials."""
    run_dir.mkdir(mode=0o700, parents=False, exist_ok=True)
    os.chmod(run_dir, 0o700)
    admin_password = "mtmf-admin-" + secrets.token_hex(16)
    user_password = secrets.token_hex(18)
    files = {
        "admin_password": admin_password,
        "user_password": user_password,
    }
    for name, value in files.items():
        path = run_dir / name
        path.write_text(value, encoding="utf-8")
        os.chmod(path, 0o600)
    return files


def _cleanup_secrets(run_dir: Path) -> None:
    if run_dir.is_dir():
        shutil.rmtree(run_dir, ignore_errors=True)


def _require_tools() -> None:
    for tool in ("podman", "podman-compose"):
        if shutil.which(tool) is None:
            raise AcceptanceError(f"required tool {tool!r} is not on PATH")
    if not (CANONICAL_CA_DIR / "dev-ca.crt").is_file():
        raise AcceptanceError(
            "canonical development CA is absent; run scripts/mtmf-dev-certs.py generate"
        )


def _canonical_dns_ok() -> None:
    result = subprocess.run(
        ["getent", "hosts", "keycloak.mtmf.test", "127.0.0.1"], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise AcceptanceError(
            "keycloak.mtmf.test does not resolve to loopback; add the OS host mapping "
            "(the orchestrator never edits /etc/hosts)"
        )


def _assert_owned_project(project: str) -> None:
    """Refuse to manage a project that is not the explicit acceptance project."""
    if project == DEFAULT_STACK_PROJECT:
        raise AcceptanceError(
            "refusing to run the disposable acceptance against the default project; "
            "pass a dedicated --project"
        )


def _compose(project: str, *args: str, extra: bool = False) -> list[str]:
    files = [*COMPOSE_FILES, *(["-f", _EXTRA_COMPOSE] if extra else [])]
    return ["podman-compose", "-p", project, *files, *args]


def _stop_default_stack(env: dict[str, str]) -> None:
    """Stop (never destroy) the default MTMF-owned stack to free fixed ports."""
    stop_env = {
        **env,
        "COMPOSE_PROJECT_NAME": DEFAULT_STACK_PROJECT,
        "MTMF_DEV_STACK_PROJECT": DEFAULT_STACK_PROJECT,
    }
    result = _run(
        _compose(DEFAULT_STACK_PROJECT, "down"),
        env=stop_env,
        check=False,
    )
    if result.returncode != 0:
        raise AcceptanceError("failed to stop the default MTMF stack")


def _fresh_project(project: str, env: dict[str, str]) -> None:
    """Tear down only the verified disposable acceptance project and volumes."""
    _assert_owned_project(project)
    fresh_env = {**env, "COMPOSE_PROJECT_NAME": project}
    _run(_compose(project, "down", "-v", extra=True), env=fresh_env, check=False)


def _build_env(staged: dict[str, str], project: str, dotenv: dict[str, str]) -> dict[str, str]:
    env = dict(os.environ)
    env.update(dotenv)
    env["MTMF_DEV_STACK_PROJECT"] = project
    # podman-compose 1.0.6 prefers COMPOSE_PROJECT_NAME over ``-p``; keep them
    # consistent so the disposable project never collapses onto ``mtmf``.
    env["COMPOSE_PROJECT_NAME"] = project
    env["MTMF_SERVICE_DEPLOYMENT_MODE"] = "development"
    env["MTMF_DEV_KC_ADMIN_USERNAME"] = "mtmf-admin"
    env["MTMF_DEV_KC_ADMIN_PASSWORD"] = staged["admin_password"]
    env["MTMF_AUTH_ADMIN_USERNAME"] = "mtmf-admin"
    env["MTMF_AUTH_ADMIN_PASSWORD"] = staged["admin_password"]
    env["MTMF_AUTH_ISSUER"] = CANONICAL_ISSUER
    env["MTMF_AUTH_JWKS_URI"] = f"{CANONICAL_ISSUER}/protocol/openid-connect/certs"
    env["MTMF_AUTH_ADMIN_BASE"] = "https://keycloak.mtmf.test:28443"
    env["MTMF_AUTH_ADMIN_REALM"] = CANONICAL_REALM
    env["MTMF_AUTH_SERVICE_AUDIENCE"] = "mtmf-service-api"
    env["MTMF_AUTH_USER_AUDIENCE"] = "mtmf-user-api"
    env["MTMF_AUTH_EXPECTED_MANIFEST"] = "dev/keycloak/expected-realm-security.json"
    env["MTMF_AUTH_EXPECTED_CLIENT_POLICY"] = "dev/keycloak/expected-client-policy.json"
    env["MTMF_AUTH_ATTESTATION_CLIENT_ID"] = "mtmf-attestation-reader"
    env["MTMF_AUTH_ATTESTATION_CLIENT_SECRET"] = "mtmf-attestation-reader-dev-secret"
    env["MTMF_DEV_CA_DIR"] = str(CANONICAL_CA_DIR)
    env["MTMF_PR14_KC_CA_FILE"] = str(CANONICAL_CA_DIR / "dev-ca.crt")
    env["MTMF_PR14_KC_USER_PASSWORD"] = staged["user_password"]
    env["MTMF_DEV_REALM_SETUP"] = "1"
    env["MTMF_DEV_STACK_EXTRA_COMPOSE"] = _EXTRA_COMPOSE
    env["MTMF_DEV_SECRET_DIR"] = str(Path(env.get("PR19C_RUN_DIR", "/tmp/mtmf-pr19c-live")))
    env["MTMF_DEV_USER_USERNAME"] = "mtmf-dev-user"
    env["MTMF_DEV_USER_CREATE"] = "false"
    env["MTMF_DEV_USER_PASSWORD_FILE"] = "/run/mtmf-secrets/dev-user-password"
    for role in ("MIGRATOR", "RUNTIME"):
        user = dotenv.get(f"MTMF_{role}_POSTGRES_USER", "")
        password = dotenv.get(f"MTMF_{role}_POSTGRES_PASSWORD", "")
        host = dotenv.get(f"MTMF_{role}_POSTGRES_HOST", "127.0.0.1")
        port = dotenv.get(f"MTMF_{role}_POSTGRES_PORT", "25432")
        database = dotenv.get(f"MTMF_{role}_POSTGRES_DB", "mtmf")
        if not user or not password:
            raise AcceptanceError(f"MTMF_{role}_POSTGRES_* configuration is incomplete")
        env[f"MTMF_{role}_DATABASE_URL"] = (
            f"postgresql+psycopg://{user}:{password}@{host}:{port}/{database}"
        )
    return env


def _wait_http(url: str, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                if response.status == 200:
                    return
        except urllib.error.URLError, OSError:
            time.sleep(2.0)
    raise AcceptanceError(f"endpoint {url} did not become ready within {timeout:.0f}s")


def run(args: argparse.Namespace) -> int:
    _require_tools()
    _canonical_dns_ok()
    _assert_owned_project(args.project)
    dotenv = _read_dotenv()

    run_dir = Path(f"/tmp/{args.project}-secrets")
    files = _stage_secrets(run_dir)
    _SECRET_VALUES.clear()
    _SECRET_VALUES.extend([files["admin_password"], files["user_password"]])
    # The initializer expects an owner-only user password file in the mounted dir.
    user_file = run_dir / "dev-user-password"
    user_file.write_text(files["user_password"], encoding="utf-8")
    os.chmod(user_file, 0o600)

    env = _build_env(files, args.project, dotenv)
    env["PR19C_RUN_DIR"] = str(run_dir)
    env["MTMF_DEV_SECRET_DIR"] = str(run_dir)
    env["MTMF_ALLOW_NONLOCAL"] = "1"
    if args.fresh:
        _stop_default_stack(env)
        _fresh_project(args.project, env)
    try:
        _run(_compose(args.project, "build", "initializer", "service", extra=True), env=env)
        _run(
            [sys.executable, str(REPO_ROOT / "scripts" / "mtmf-dev-stack.py"), "up"],
            env=env,
        )
        if args.skip_tests:
            return 0
        test_env = {
            **env,
            "MTMF_PR19C_LIVE": "1",
            "MTMF_PR14_KC_BASE": "https://keycloak.mtmf.test:28443",
            "MTMF_PR14_KC_ADMIN_USERNAME": "mtmf-admin",
            "MTMF_PR14_KC_ADMIN_PASSWORD": files["admin_password"],
            "MTMF_PR14_KC_USER_PASSWORD": files["user_password"],
            "MTMF_PR14_KC_CA_FILE": str(CANONICAL_CA_DIR / "dev-ca.crt"),
            "MTMF_AUTH_ADMIN_REALM": CANONICAL_REALM,
            "SSL_CERT_FILE": str(CANONICAL_CA_DIR / "dev-ca.crt"),
        }
        test_env.pop("MTMF_MIGRATOR_DATABASE_URL", None)
        test_env.pop("MTMF_RUNTIME_DATABASE_URL", None)
        result = subprocess.run(
            ["uv", "run", "--no-sync", "pytest", LIVE_TEST, "-q", "--no-cov"],
            cwd=REPO_ROOT,
            env=test_env,
            check=False,
        )
        if result.returncode != 0:
            raise AcceptanceError("PR 19C live acceptance failed")
        return 0
    finally:
        if not args.keep:
            _run(_compose(args.project, "down", "-v", extra=True), env=env, check=False)
            _cleanup_secrets(run_dir)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PR 19C live acceptance orchestrator")
    parser.add_argument("--fresh", action="store_true", help="disposable cold start")
    parser.add_argument("--keep", action="store_true", help="retain the fixture for diagnosis")
    parser.add_argument("--skip-tests", action="store_true", help="provision only")
    parser.add_argument("--stop-default", action="store_true", help="(reserved) default stack stop")
    parser.add_argument("--project", default=DEFAULT_PROJECT)
    args = parser.parse_args(argv)
    try:
        return run(args)
    except AcceptanceError as exc:
        print(f"acceptance error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
