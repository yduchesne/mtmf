"""PR 17-B live acceptance harness for the previously unexecuted I-cases.

Opt-in and authoritative only when ``MTMF_PR17B_LIVE=1`` and the isolated
Keycloak fixture plus the real PostgreSQL role topology are available. Every
case drives the **production** ``scripts/mtmf-dev-initialize.py`` entry point
(a separate process) against real Keycloak and a freshly migrated real
``mtmf`` schema, and asserts authoritative cross-system state.

Cases: I10 (incompatible binding), I12 (two simultaneous initializers),
I13/I14 (terminate after Keycloak creation / restart after commit),
I15 (POST committed but response lost / unsuccessful POST / indeterminate),
I18 (multiple approved Applications).

Required environment: ``MTMF_PR14_KC_BASE``, ``MTMF_PR14_KC_ADMIN_USERNAME``,
``MTMF_PR14_KC_ADMIN_PASSWORD``, ``MTMF_PR14_KC_CA_FILE``, plus the
``MTMF_MIGRATOR_*``/``MTMF_RUNTIME_*`` PostgreSQL configuration. Tokens and
secrets are never printed or persisted.
"""

from __future__ import annotations

import importlib.util
import os
import ssl
import subprocess
import sys
import threading
import urllib.parse
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import helpers  # type: ignore[import-not-found]
import httpx
import psycopg
import pytest
from pr17b_fault_proxy import FaultProxy  # type: ignore[import-not-found]

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR17B_LIVE") != "1",
    reason="PR 17-B live acceptance is opt-in (set MTMF_PR17B_LIVE=1)",
)

REALM = "mtmf-pr14-dev"
SERVICE_AUDIENCE = "mtmf-service-api"
USER_AUDIENCE = "mtmf-user-api"
SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-initialize.py"
_EVIDENCE = Path(__file__).resolve().parents[3] / "scripts" / "pr14-keycloak-evidence.py"
_spec = importlib.util.spec_from_file_location("pr14_keycloak_evidence_pr17b", _EVIDENCE)
assert _spec is not None and _spec.loader is not None
_ev = importlib.util.module_from_spec(_spec)
sys.modules["pr14_keycloak_evidence_pr17b"] = _ev
_spec.loader.exec_module(_ev)


# --------------------------------------------------------------------------
# environment / transport helpers
# --------------------------------------------------------------------------


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"PR 17-B live acceptance requires {name}")
    return value


def _kc_base() -> str:
    return _required("MTMF_PR14_KC_BASE")


def _issuer() -> str:
    return f"{_kc_base()}/realms/{REALM}"


class AdminRest:
    """Minimal Admin REST client; never logs secrets."""

    def __init__(self) -> None:
        self._base = _kc_base()
        self._username = _required("MTMF_PR14_KC_ADMIN_USERNAME")
        self._password = _required("MTMF_PR14_KC_ADMIN_PASSWORD")
        self._client = httpx.Client(
            verify=ssl.create_default_context(cafile=_required("MTMF_PR14_KC_CA_FILE")),
            timeout=20.0,
            follow_redirects=False,
        )

    def _token(self) -> str:
        response = self._client.post(
            f"{self._base}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self._username,
                "password": self._password,
            },
        )
        response.raise_for_status()
        return str(response.json()["access_token"])

    def request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> tuple[int, Any]:
        headers = {"Authorization": f"Bearer {self._token()}"}
        response = self._client.request(method, f"{self._base}{path}", json=body, headers=headers)
        payload = response.content
        return response.status_code, (response.json() if payload else None)

    def find_users(self, username: str) -> list[dict[str, Any]]:
        quoted = urllib.parse.quote(username, safe="")
        status, rows = self.request(
            "GET", f"/admin/realms/{REALM}/users?username={quoted}&exact=true"
        )
        if status != 200 or not isinstance(rows, list):
            raise RuntimeError(f"Keycloak user lookup failed with HTTP {status}")
        return [
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("username", "")).casefold() == username.casefold()
        ]

    def create_user(self, username: str, password: str) -> dict[str, Any]:
        status, _ = self.request(
            "POST",
            f"/admin/realms/{REALM}/users",
            {
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "email": f"{username}@example.invalid",
                "firstName": "MTMF",
                "lastName": "Live",
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
        )
        if status not in (201, 204, 409):
            raise RuntimeError(f"Keycloak user creation failed with HTTP {status}")
        users = self.find_users(username)
        if len(users) != 1:
            raise RuntimeError("the just-created Keycloak user could not be read back")
        return users[0]

    def delete_user(self, username: str) -> None:
        for user in self.find_users(username):
            self.request("DELETE", f"/admin/realms/{REALM}/users/{user['id']}")


def _base_env(secret_dir: Path, **overrides: str) -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        {
            "MTMF_SERVICE_DEPLOYMENT_MODE": "development",
            "MTMF_AUTH_ISSUER": _issuer(),
            "MTMF_AUTH_SERVICE_AUDIENCE": SERVICE_AUDIENCE,
            "MTMF_AUTH_USER_AUDIENCE": USER_AUDIENCE,
            "MTMF_AUTH_ADMIN_BASE": _kc_base(),
            "MTMF_AUTH_ADMIN_REALM": REALM,
            "MTMF_AUTH_ADMIN_USERNAME": _required("MTMF_PR14_KC_ADMIN_USERNAME"),
            "MTMF_AUTH_ADMIN_PASSWORD": _required("MTMF_PR14_KC_ADMIN_PASSWORD"),
            "MTMF_DEV_APPLICATION_KEYS": "sample-app",
            "MTMF_DEV_TENANT_KEY": "dev",
            "MTMF_DEV_TENANT_NAME": "Development Tenant",
            "MTMF_DEV_SECRET_DIR": str(secret_dir),
            "SSL_CERT_FILE": _required("MTMF_PR14_KC_CA_FILE"),
        }
    )
    env.pop("MTMF_DEV_USER_SUBJECT", None)
    env.pop("MTMF_DEV_TEST_FAILPOINT", None)
    env.update(overrides)
    return env


def _run_initializer(
    env: dict[str, str], *, timeout: float = 180.0
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _password() -> str:
    """Return a non-secret, per-run test password (never a stored credential)."""
    return "Pr17b-" + uuid.uuid4().hex


def _write_password(directory: Path, content: str | None = None) -> Path:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / "dev-user-password"
    target.write_text(content if content is not None else _password())
    target.chmod(0o600)
    return target


def _unique(prefix: str) -> str:
    return f"pr17b-{prefix}-{uuid.uuid4().hex[:10]}"


def _counts(db: psycopg.Connection[Any]) -> tuple[int, int, int, int, int]:
    return (
        db.execute("SELECT count(*) FROM mtmf.root_registry").fetchone()[0],
        db.execute("SELECT count(*) FROM mtmf.tenant WHERE scope = 2").fetchone()[0],
        db.execute("SELECT count(*) FROM mtmf.application").fetchone()[0],
        db.execute("SELECT count(*) FROM mtmf.tenant_application_subscription").fetchone()[0],
        db.execute(
            "SELECT count(*) FROM mtmf.external_subject_identity WHERE lifecycle = 1"
        ).fetchone()[0],
    )


def _active_binding_identity(db: psycopg.Connection[Any], subject: str) -> Any:
    return db.execute(
        "SELECT identity_id FROM mtmf.external_subject_identity "
        "WHERE issuer = %s AND subject = %s AND lifecycle = 1",
        (_issuer(), subject),
    ).fetchone()


def _oidc_login_sub(username: str, password: str) -> str:
    issuer = _ev.Issuer(base=_kc_base(), realm=REALM, ca_file=_required("MTMF_PR14_KC_CA_FILE"))
    token = _ev.authorization_code_token(
        issuer,
        "mtmf-evidence-same-client",
        "mtmf-evidence-same-client-dev-secret",
        username,
        password,
        "http://127.0.0.1:28400/callback",
        28400,
    )
    payload = _ev.verify_token(issuer, token["access_token"], "mtmf-same-client-api")
    return str(payload["sub"])


# --------------------------------------------------------------------------
# I10 — pre-existing incompatible external-subject binding
# --------------------------------------------------------------------------


def test_i10_incompatible_existing_binding_fails_closed(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:
    admin = AdminRest()
    username = _unique("i10")
    password = _password()
    try:
        user = admin.create_user(username, password)
        subject = str(user["id"])
        conflict_principal = helpers.new_id()
        conflict_identity = helpers.new_id()
        db.execute(
            "SELECT mtmf.principal_add(%s, %s, %s, %s::jsonb)",
            (conflict_principal, "I10 Conflict", 2, "{}"),
        )
        db.execute(
            "SELECT mtmf.identity_add(%s, %s, %s, %s, %s, %s::jsonb)",
            (conflict_identity, conflict_principal, "I10 Conflict Identity", 2, 2, "{}"),
        )
        db.execute(
            "SELECT mtmf.external_subject_identity_add(%s, %s, %s, %s, %s, %s)",
            (helpers.new_id(), _issuer(), subject, conflict_identity, 1, datetime.now(UTC)),
        )
        before = db.execute("SELECT count(*) FROM mtmf.external_subject_identity").fetchone()[0]

        result = _run_initializer(
            _base_env(
                tmp_path / "secrets",
                MTMF_DEV_USER_USERNAME=username,
                MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
                MTMF_DEV_USER_CREATE="false",
            )
        )
        assert result.returncode != 0, result.stdout + result.stderr
        assert "conflicts with the expected development Identity" in result.stderr

        rows = db.execute(
            "SELECT identity_id FROM mtmf.external_subject_identity "
            "WHERE issuer = %s AND subject = %s",
            (_issuer(), subject),
        ).fetchall()
        assert len(rows) == 1 and str(rows[0][0]) == conflict_identity
        assert (
            db.execute("SELECT count(*) FROM mtmf.external_subject_identity").fetchone()[0]
            == before
        )
    finally:
        admin.delete_user(username)


# --------------------------------------------------------------------------
# I12 — two simultaneous initializers
# --------------------------------------------------------------------------


def test_i12_two_simultaneous_initializers_converge(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:
    admin = AdminRest()
    username = _unique("i12")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    barrier = threading.Barrier(2)
    results: list[subprocess.CompletedProcess[str]] = []

    def worker() -> None:
        barrier.wait(timeout=30)
        results.append(_run_initializer(env))

    try:
        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=240)
        assert len(results) == 2

        # Acceptable outcomes: both clean successes, or one success and one
        # bounded fail-closed outcome recovered by an idempotent retry.
        successes = [result for result in results if result.returncode == 0]
        assert successes, [(r.returncode, r.stderr) for r in results]
        for result in results:
            if result.returncode != 0:
                assert "partially" in result.stderr or "failed" in result.stderr

        users = admin.find_users(username)
        assert len(users) == 1
        subject = str(users[0]["id"])
        assert _active_binding_identity(db, subject) is not None
        assert _counts(db) == (1, 1, 1, 1, 1)

        retry = _run_initializer(env)
        assert retry.returncode == 0, retry.stderr
        assert len(admin.find_users(username)) == 1
        assert _counts(db) == (1, 1, 1, 1, 1)
    finally:
        admin.delete_user(username)


# --------------------------------------------------------------------------
# I13 / I14 — terminate after Keycloak creation; restart after commit
# --------------------------------------------------------------------------


def test_i13_i14_kill_after_create_then_restart_is_idempotent(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:
    admin = AdminRest()
    username = _unique("i13")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    try:
        # Terminate after the Keycloak user exists but before any MTMF write.
        failed = _run_initializer({**env, "MTMF_DEV_TEST_FAILPOINT": "after-user-verify"})
        assert failed.returncode == 99, failed.stderr
        assert "test failpoint reached: after-user-verify" in failed.stderr

        users = admin.find_users(username)
        assert len(users) == 1
        subject = str(users[0]["id"])
        assert _active_binding_identity(db, subject) is None
        assert _counts(db) == (0, 0, 0, 0, 0)

        # Normal rerun completes with the same Keycloak subject and password.
        first = _run_initializer(env)
        assert first.returncode == 0, first.stderr
        assert _counts(db) == (1, 1, 1, 1, 1)
        assert _active_binding_identity(db, subject) is not None
        assert _oidc_login_sub(username, password) == subject

        # I14: restart after the MTMF commit is stable (no new identities).
        second = _run_initializer(env)
        assert second.returncode == 0, second.stderr
        assert _counts(db) == (1, 1, 1, 1, 1)
        assert len(admin.find_users(username)) == 1
        assert _active_binding_identity(db, subject) is not None
    finally:
        admin.delete_user(username)


# --------------------------------------------------------------------------
# I15 — create committed but response lost / unsuccessful / indeterminate
# --------------------------------------------------------------------------


def test_i15a_lost_create_response_fails_closed_then_reconciles(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:

    admin = AdminRest()
    username = _unique("i15a")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    ca_file = _required("MTMF_PR14_KC_CA_FILE")
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    try:
        with FaultProxy(_kc_base(), ca_file, fault="drop_response") as proxy:
            first = _run_initializer({**env, "MTMF_AUTH_ADMIN_BASE": proxy.base_url})
        # The real POST committed, but without an independent correlation the
        # initializer must not bind the merely-visible matching username.
        assert first.returncode != 0, first.stderr
        assert "not verifiably created" in first.stderr
        assert proxy.create_post_count() == 1
        users = admin.find_users(username)
        assert len(users) == 1
        assert _active_binding_identity(db, str(users[0]["id"])) is None
        assert _counts(db) == (0, 0, 0, 0, 0)

        # An unchanged rerun reuses the now-existing account under the
        # verified-account contract and completes without a second POST.
        second = _run_initializer(env)
        assert second.returncode == 0, second.stderr
        assert len(admin.find_users(username)) == 1
        assert _active_binding_identity(db, str(users[0]["id"])) is not None
        assert _counts(db) == (1, 1, 1, 1, 1)
    finally:
        admin.delete_user(username)


def test_i15b_unsuccessful_create_fails_closed(db: psycopg.Connection[Any], tmp_path: Path) -> None:

    admin = AdminRest()
    username = _unique("i15b")
    password_file = _write_password(tmp_path / "secrets")
    ca_file = _required("MTMF_PR14_KC_CA_FILE")
    try:
        with FaultProxy(_kc_base(), ca_file, fault="error_before_forward") as proxy:
            result = _run_initializer(
                _base_env(
                    tmp_path / "secrets-out",
                    MTMF_AUTH_ADMIN_BASE=proxy.base_url,
                    MTMF_DEV_USER_USERNAME=username,
                    MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
                    MTMF_DEV_USER_CREATE="true",
                    MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
                )
            )
        assert result.returncode != 0
        assert "rejected the development user creation" in result.stderr
        assert admin.find_users(username) == []
        assert _counts(db) == (0, 0, 0, 0, 0)
    finally:
        admin.delete_user(username)


def test_i15c_indeterminate_re_read_fails_closed(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:

    admin = AdminRest()
    username = _unique("i15c")
    password_file = _write_password(tmp_path / "secrets")
    ca_file = _required("MTMF_PR14_KC_CA_FILE")
    try:
        with FaultProxy(_kc_base(), ca_file, fault="drop_and_fail_reads") as proxy:
            result = _run_initializer(
                _base_env(
                    tmp_path / "secrets-out",
                    MTMF_AUTH_ADMIN_BASE=proxy.base_url,
                    MTMF_DEV_USER_USERNAME=username,
                    MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
                    MTMF_DEV_USER_CREATE="true",
                    MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
                )
            )
        assert result.returncode != 0
        # The real POST committed, but the caller could not verify it and
        # therefore claimed no success and wrote no MTMF binding.
        assert len(admin.find_users(username)) == 1
        assert _counts(db) == (0, 0, 0, 0, 0)
        assert proxy.create_post_count() == 1
    finally:
        admin.delete_user(username)


# --------------------------------------------------------------------------
# I18 — multiple approved Applications
# --------------------------------------------------------------------------


def test_i18_multiple_approved_applications(db: psycopg.Connection[Any], tmp_path: Path) -> None:
    admin = AdminRest()
    username = _unique("i18")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_APPLICATION_KEYS="sample-app,evidence-same-client",
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    try:
        first = _run_initializer(env)
        assert first.returncode == 0, first.stderr
        applications = db.execute(
            "SELECT application_key FROM mtmf.application ORDER BY application_key"
        ).fetchall()
        assert [row[0] for row in applications] == ["evidence-same-client", "sample-app"]
        assert (
            db.execute(
                "SELECT count(*) FROM mtmf.application_tenant_registration WHERE lifecycle = 1"
            ).fetchone()[0]
            == 2
        )
        assert (
            db.execute(
                "SELECT count(*) FROM mtmf.tenant_application_subscription WHERE lifecycle = 1"
            ).fetchone()[0]
            == 2
        )
        assert (
            db.execute(
                "SELECT count(*) FROM mtmf.service_credential_application WHERE lifecycle = 1"
            ).fetchone()[0]
            == 2
        )

        second = _run_initializer(env)
        assert second.returncode == 0, second.stderr
        assert db.execute("SELECT count(*) FROM mtmf.application").fetchone()[0] == 2
        assert (
            db.execute(
                "SELECT count(*) FROM mtmf.service_credential_application WHERE lifecycle = 1"
            ).fetchone()[0]
            == 2
        )
    finally:
        admin.delete_user(username)


# --------------------------------------------------------------------------
# I20 — nondefault Tenant key/name override and conflicting override
# --------------------------------------------------------------------------


def test_i20_tenant_override_is_idempotent_and_conflict_fails_closed(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:
    admin = AdminRest()
    tenant_key = f"pr17b-{uuid.uuid4().hex[:8]}"
    tenant_name = "PR17B Override Tenant"
    username = _unique("i20")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_TENANT_KEY=tenant_key,
        MTMF_DEV_TENANT_NAME=tenant_name,
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    try:
        first = _run_initializer(env)
        assert first.returncode == 0, first.stderr
        tenants = db.execute("SELECT name FROM mtmf.tenant WHERE scope = 2").fetchall()
        assert tenants == [(tenant_name,)]
        assert db.execute("SELECT count(*) FROM mtmf.stewardship_designation").fetchone()[0] == 1
        assert (
            db.execute(
                "SELECT count(*) FROM mtmf.external_subject_identity WHERE lifecycle = 1"
            ).fetchone()[0]
            == 1
        )

        # Repeat unchanged: idempotent, no duplicate Tenant.
        second = _run_initializer(env)
        assert second.returncode == 0, second.stderr
        assert db.execute("SELECT count(*) FROM mtmf.tenant WHERE scope = 2").fetchone()[0] == 1

        # Conflicting name for the same key fails closed and does not rename.
        conflict = _run_initializer({**env, "MTMF_DEV_TENANT_NAME": "Conflicting Tenant Name"})
        assert conflict.returncode != 0
        assert "conflicts with the configured tenant name" in conflict.stderr
        assert db.execute("SELECT name FROM mtmf.tenant WHERE scope = 2").fetchone() == (
            tenant_name,
        )
    finally:
        admin.delete_user(username)


# --------------------------------------------------------------------------
# SH16 — newly created user with unverified email can complete real OIDC login
# --------------------------------------------------------------------------


def test_sh16_created_user_with_unverified_email_can_login(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:
    del db  # the initializer runs against the freshly migrated schema
    admin = AdminRest()
    username = _unique("sh16")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    try:
        result = _run_initializer(env)
        assert result.returncode == 0, result.stderr
        users = admin.find_users(username)
        assert len(users) == 1
        # The initializer must not claim email ownership it has not proven.
        assert users[0].get("emailVerified") is False
        # The approved browser/OIDC authorization-code flow still succeeds.
        assert _oidc_login_sub(username, password) == str(users[0]["id"])
    finally:
        admin.delete_user(username)


# --------------------------------------------------------------------------
# PV live — real-Keycloak created-resource Location provenance
# --------------------------------------------------------------------------


def test_pv_live_real_location_shape(tmp_path: Path) -> None:
    del tmp_path
    admin = AdminRest()
    username = _unique("pvshape")
    password = _password()
    ca_file = _required("MTMF_PR14_KC_CA_FILE")
    try:
        with httpx.Client(
            verify=ssl.create_default_context(cafile=ca_file),
            timeout=20.0,
            follow_redirects=False,
        ) as client:
            token_response = client.post(
                f"{_kc_base()}/realms/master/protocol/openid-connect/token",
                data={
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": _required("MTMF_PR14_KC_ADMIN_USERNAME"),
                    "password": _required("MTMF_PR14_KC_ADMIN_PASSWORD"),
                },
            )
            headers = {"Authorization": f"Bearer {token_response.json()['access_token']}"}
            response = client.post(
                f"{_kc_base()}/admin/realms/{REALM}/users",
                headers=headers,
                json={
                    "username": username,
                    "enabled": True,
                    "emailVerified": False,
                    "firstName": "MTMF",
                    "lastName": "Probe",
                    "credentials": [{"type": "password", "value": password, "temporary": False}],
                },
            )
        assert response.status_code == 201
        location = response.headers.get("location")
        prefix = f"{_kc_base()}/admin/realms/{REALM}/users/"
        assert location is not None and location.startswith(prefix)
        created_id = location[len(prefix) :]
        assert created_id and "/" not in created_id
        assert [user["id"] for user in admin.find_users(username)] == [created_id]
    finally:
        admin.delete_user(username)


def test_pv_live_valid_location_via_proxy_succeeds(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:
    admin = AdminRest()
    username = _unique("pvproxy")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    ca_file = _required("MTMF_PR14_KC_CA_FILE")
    try:
        with FaultProxy(_kc_base(), ca_file, fault="none") as proxy:
            result = _run_initializer({**env, "MTMF_AUTH_ADMIN_BASE": proxy.base_url})
        assert result.returncode == 0, result.stderr
        users = admin.find_users(username)
        assert len(users) == 1
        assert _active_binding_identity(db, str(users[0]["id"])) is not None
        assert _counts(db) == (1, 1, 1, 1, 1)
    finally:
        admin.delete_user(username)


def test_pv_live_stripped_location_fails_closed_then_reconciles(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:
    admin = AdminRest()
    username = _unique("pvstrip")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    ca_file = _required("MTMF_PR14_KC_CA_FILE")
    try:
        with FaultProxy(_kc_base(), ca_file, fault="strip_location") as proxy:
            first = _run_initializer({**env, "MTMF_AUTH_ADMIN_BASE": proxy.base_url})
        assert first.returncode != 0, first.stderr
        assert "creation provenance could not be verified" in first.stderr
        users = admin.find_users(username)
        assert len(users) == 1  # real Keycloak committed the create
        assert _active_binding_identity(db, str(users[0]["id"])) is None
        assert _counts(db) == (0, 0, 0, 0, 0)
        # Rerun without the fault reuses the now-existing account read-only.
        second = _run_initializer(env)
        assert second.returncode == 0, second.stderr
        assert _active_binding_identity(db, str(users[0]["id"])) is not None
        assert _counts(db) == (1, 1, 1, 1, 1)
    finally:
        admin.delete_user(username)


def test_pv_live_wrong_realm_location_fails_closed(
    db: psycopg.Connection[Any], tmp_path: Path
) -> None:
    admin = AdminRest()
    username = _unique("pvwrongrealm")
    password = _password()
    password_file = _write_password(tmp_path / "secrets", password)
    env = _base_env(
        tmp_path / "secrets-out",
        MTMF_DEV_USER_USERNAME=username,
        MTMF_DEV_USER_EMAIL=f"{username}@example.invalid",
        MTMF_DEV_USER_CREATE="true",
        MTMF_DEV_USER_PASSWORD_FILE=str(password_file),
    )
    ca_file = _required("MTMF_PR14_KC_CA_FILE")
    try:
        with FaultProxy(_kc_base(), ca_file, fault="wrong_realm_location") as proxy:
            result = _run_initializer({**env, "MTMF_AUTH_ADMIN_BASE": proxy.base_url})
        assert result.returncode != 0, result.stderr
        assert "creation provenance could not be verified" in result.stderr
        users = admin.find_users(username)
        assert len(users) == 1
        assert _active_binding_identity(db, str(users[0]["id"])) is None
        assert _counts(db) == (0, 0, 0, 0, 0)
    finally:
        admin.delete_user(username)
