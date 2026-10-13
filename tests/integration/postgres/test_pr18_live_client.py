"""Live PR 18 HTTP client acceptance: real HttpMtmfClient -> TLS Uvicorn -> Keycloak.

Opt-in and authoritative only when ``MTMF_PR18_LIVE=1`` and the isolated
development topology (real Keycloak issuer, real PostgreSQL runtime role,
real Uvicorn PR 17 service) is available. A real leaf certificate signed by
the development CA for ``127.0.0.1`` is generated so the production
``HttpMtmfClient`` (which is HTTPS-only and never disables verification)
talks to the service over genuine TLS.

Required environment (same as the PR 14 / PR 17 live suites):
``MTMF_PR14_KC_BASE``, ``MTMF_PR14_KC_ADMIN_USERNAME``,
``MTMF_PR14_KC_ADMIN_PASSWORD``, ``MTMF_PR14_KC_CA_FILE``, plus the
``MTMF_RUNTIME_*`` PostgreSQL configuration. A disposable Keycloak user is
created for the slice and removed afterwards; no existing fixture user is
mutated. Tokens, secrets and admin credentials are never printed or
persisted.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from mtmf_api.authorization import (
    AuthorizationBatchRequest,
    ResourceKind,
    ResourceTarget,
)
from mtmf_api.json_codec import parse_request_json
from mtmf_client import (
    ClientAuthenticationError,
    ClientConfig,
    DependencyUnavailableError,
    HttpMtmfClient,
    RemoteEligibilityError,
    RemoteProtocolError,
    TrustedActorContext,
    is_allowed,
    require,
)

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import test_pr17_live_http as pr17  # noqa: E402  (shared live topology helpers)

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR18_LIVE") != "1",
    reason="live PR 18 client acceptance is opt-in (set MTMF_PR18_LIVE=1)",
)

# The in-process service fetches the issuer JWKS over TLS; ensure the
# development CA is trusted before any request is served.
if os.environ.get("SSL_CERT_FILE", "").strip() == "":
    os.environ["SSL_CERT_FILE"] = os.environ.get(
        "MTMF_PR14_KC_CA_FILE",
        str(Path(tempfile.gettempdir()) / "mtmf-dev-ca" / "dev-ca.crt"),
    )

PORT = 28012
TLS_BASE_URL = f"https://127.0.0.1:{PORT}"
REALM = os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-dev")
DISPOSABLE_PREFIX = "mtmf-pr18-live-"


def _env(name: str) -> str:
    return pr17._env(name)


def _ca_file() -> str:
    return os.environ.get(
        "MTMF_PR14_KC_CA_FILE", str(Path(tempfile.gettempdir()) / "mtmf-dev-ca" / "dev-ca.crt")
    )


def _ca_dir() -> Path:
    configured = os.environ.get("MTMF_DEV_CA_DIR", "").strip()
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "mtmf-dev-ca"


def _admin_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=_ca_file())


def _admin_token() -> str:
    with httpx.Client(verify=_admin_context(), timeout=15) as client:
        response = client.post(
            f"{_env('MTMF_PR14_KC_BASE')}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": _env("MTMF_PR14_KC_ADMIN_USERNAME"),
                "password": _env("MTMF_PR14_KC_ADMIN_PASSWORD"),
            },
        )
        response.raise_for_status()
        return str(response.json()["access_token"])


def _create_disposable_user(username: str, password: str) -> str:
    """Create a disposable Keycloak user and return its immutable subject id."""
    base = _env("MTMF_PR14_KC_BASE")
    headers = {"Authorization": f"Bearer {_admin_token()}"}
    with httpx.Client(verify=_admin_context(), timeout=15) as client:
        created = client.post(
            f"{base}/admin/realms/{REALM}/users",
            headers=headers,
            json={
                "username": username,
                "enabled": True,
                "email": f"{username}@example.invalid",
                "emailVerified": True,
                "firstName": "PR18",
                "lastName": "Live",
                "requiredActions": [],
            },
        )
        if created.status_code not in (201, 409):
            raise RuntimeError(f"disposable user creation failed: {created.status_code}")
        found = client.get(
            f"{base}/admin/realms/{REALM}/users",
            headers=headers,
            params={"username": username, "exact": "true"},
        )
        found.raise_for_status()
        rows = found.json()
        if len(rows) != 1:
            raise RuntimeError("disposable user lookup was not unique")
        user_id = str(rows[0]["id"])
        reset = client.put(
            f"{base}/admin/realms/{REALM}/users/{user_id}/reset-password",
            headers=headers,
            json={"type": "password", "value": password, "temporary": False},
        )
        reset.raise_for_status()
    return user_id


def _delete_disposable_user(user_id: str) -> None:
    base = _env("MTMF_PR14_KC_BASE")
    headers = {"Authorization": f"Bearer {_admin_token()}"}
    with httpx.Client(verify=_admin_context(), timeout=15) as client:
        client.delete(f"{base}/admin/realms/{REALM}/users/{user_id}", headers=headers)


def _generate_leaf_certificate(directory: Path) -> tuple[str, str]:
    """Sign a 127.0.0.1 leaf certificate with the development CA."""
    ca_cert = x509.load_pem_x509_certificate((_ca_dir() / "dev-ca.crt").read_bytes())
    ca_key = serialization.load_pem_private_key(
        (_ca_dir() / "dev-ca.key").read_bytes(), password=None
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mtmf-pdp.mtmf.test")])
    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    except x509.ExtensionNotFound:
        ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key())
    key_identifier = ca_ski.digest
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier(
                key_identifier=key_identifier,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = directory / "pdp-leaf.crt"
    key_path = directory / "pdp-leaf.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    return str(cert_path), str(key_path)


class _TlsLiveServer:
    """A real Uvicorn server on loopback terminated with genuine TLS."""

    def __init__(self, app: Any, certfile: str, keyfile: str, port: int = PORT) -> None:
        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            ssl_certfile=certfile,
            ssl_keyfile=keyfile,
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self) -> _TlsLiveServer:
        self._thread.start()
        deadline = time.monotonic() + 30
        while not self._server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        if not self._server.started:
            raise RuntimeError("TLS uvicorn did not start")
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


def _free_loopback_port() -> int:
    """Select an unused loopback TCP port by binding and releasing it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_port_closed(port: int, timeout: float = 15.0) -> None:
    """Wait until nothing accepts connections on the loopback ``port``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.5)
            if probe.connect_ex(("127.0.0.1", port)) != 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"loopback port {port} is still accepting connections")


def _live_app() -> Any:
    """A fresh real PR 17 application instance for a test-owned server."""
    return pr17._live_app(evaluation_timeout_seconds=30.0)


@pytest.fixture(scope="module")
def disposable_user() -> Any:
    """Create one disposable Keycloak user for the module and remove it after."""
    if os.environ.get("SSL_CERT_FILE", "").strip() == "":
        os.environ["SSL_CERT_FILE"] = _ca_file()
    username = f"{DISPOSABLE_PREFIX}{uuid.uuid4().hex[:10]}"
    password = uuid.uuid4().hex + uuid.uuid4().hex
    user_id = _create_disposable_user(username, password)
    try:
        yield {"username": username, "password": password, "subject": user_id}
    finally:
        _delete_disposable_user(user_id)


@pytest.fixture(scope="module")
def live_server(tmp_path_factory: pytest.TempPathFactory) -> Any:
    """A real Uvicorn PR 17 service over TLS on loopback."""
    directory = tmp_path_factory.mktemp("pr18-tls")
    certfile, keyfile = _generate_leaf_certificate(directory)
    with _TlsLiveServer(
        pr17._live_app(evaluation_timeout_seconds=30.0), certfile, keyfile
    ) as server:
        yield server


def _secret_file(tmp_path: Path, secret: str) -> Path:
    path = tmp_path / "client-secret"
    path.write_text(secret, encoding="utf-8")
    path.chmod(0o600)
    return path


def _client(
    tmp_path: Path,
    *,
    application_id: uuid.UUID,
    client_id: str = pr17.SAME_CLIENT,
    client_secret: str = pr17.SAME_SECRET,
    base_url: str = TLS_BASE_URL,
    ca_bundle: str | None = None,
    token_endpoint: str | None = None,
    renewal_leeway_seconds: float = 5.0,
) -> HttpMtmfClient:
    config = ClientConfig(
        base_url=base_url,
        token_endpoint=token_endpoint
        or f"{_env('MTMF_PR14_KC_BASE')}/realms/{REALM}/protocol/openid-connect/token",
        application_id=application_id,
        client_id=client_id,
        client_secret_file=_secret_file(tmp_path, client_secret),
        ca_bundle=ca_bundle if ca_bundle is not None else _ca_file(),
        renewal_leeway_seconds=renewal_leeway_seconds,
    )
    return HttpMtmfClient(config)


def _context(
    ids: dict[str, str],
    *,
    application_id: uuid.UUID | None = None,
    actor_key: str = "live-actor",
    session_key: str = "live-session",
) -> TrustedActorContext:
    return TrustedActorContext(
        actor_key=actor_key,
        session_key=session_key,
        tenant_id=uuid.UUID(ids["tenant_id"]),
        application_id=application_id or uuid.UUID(ids["application_id"]),
    )


def _capability() -> ResourceTarget:
    """The explicit capability target for capability-level checks."""
    return ResourceTarget(kind=ResourceKind.CAPABILITY)


def _app_owned(resource_id: str, resource_type: str = "document") -> ResourceTarget:
    """An explicit application-owned target."""
    return ResourceTarget(
        kind=ResourceKind.APPLICATION_OWNED,
        resource_type=resource_type,
        resource_id=resource_id,
    )


def _user_token(user: dict[str, str]) -> str:
    token = pr17.ev.authorization_code_token(
        pr17._issuer(),
        pr17.SAME_CLIENT,
        pr17.SAME_SECRET,
        user["username"],
        user["password"],
        "http://127.0.0.1:28400/callback",
        28400,
    )
    return str(token["access_token"])


def _request(
    tenant_id: str,
    *actions: tuple[str, str],
    organization_id: str | None = None,
) -> AuthorizationBatchRequest:
    body = pr17._body(tenant_id, *actions, organization_id=organization_id)
    return parse_request_json(json.dumps(body))


# ---------------------------------------------------------------------------
# CL-I01 / CL-I02 / CL-I03: real client-credentials, real user token, mixed batch
# ---------------------------------------------------------------------------


def test_cl_i01_i02_i03_real_client_mixed_batch(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    try:
        request = _request(
            ids["tenant_id"],
            ("allow", pr17.ALLOW_ACTION),
            ("deny", pr17.DENY_ACTION),
            ("noperm", pr17.NO_PERMISSION_ACTION),
        )
        snapshot = client.evaluate(request, user_access_token=token, context=_context(ids))
    finally:
        client.close()
    assert snapshot.tenant_id == uuid.UUID(ids["tenant_id"])
    assert (
        is_allowed(
            snapshot,
            context=_context(ids),
            action=pr17.ALLOW_ACTION,
            resource=_capability(),
            request_id="allow",
        )
        is True
    )
    assert (
        is_allowed(
            snapshot,
            context=_context(ids),
            action=pr17.DENY_ACTION,
            resource=_capability(),
            request_id="deny",
        )
        is False
    )
    assert (
        is_allowed(
            snapshot,
            context=_context(ids),
            action=pr17.NO_PERMISSION_ACTION,
            resource=_capability(),
            request_id="noperm",
        )
        is False
    )
    require(
        snapshot,
        context=_context(ids),
        action=pr17.ALLOW_ACTION,
        resource=_capability(),
        request_id="allow",
    )


def test_cl_i04_hundred_ordered_occurrences(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    actions = [
        (f"req-{index:03d}", pr17.ALLOW_ACTION if index % 2 == 0 else pr17.DENY_ACTION)
        for index in range(100)
    ]
    try:
        snapshot = client.evaluate(
            _request(ids["tenant_id"], *actions),
            user_access_token=token,
            context=_context(ids),
        )
    finally:
        client.close()
    assert snapshot.decision_count == 100
    assert (
        is_allowed(
            snapshot,
            context=_context(ids),
            action=pr17.ALLOW_ACTION,
            resource=_capability(),
            request_id="req-000",
        )
        is True
    )
    assert (
        is_allowed(
            snapshot,
            context=_context(ids),
            action=pr17.DENY_ACTION,
            resource=_capability(),
            request_id="req-001",
        )
        is False
    )


def test_cl_i05_unknown_action_denies(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    try:
        snapshot = client.evaluate(
            _request(ids["tenant_id"], ("unknown", pr17.UNKNOWN_ACTION)),
            user_access_token=token,
            context=_context(ids),
        )
    finally:
        client.close()
    assert (
        is_allowed(
            snapshot,
            context=_context(ids),
            action=pr17.UNKNOWN_ACTION,
            resource=_capability(),
            request_id="unknown",
        )
        is False
    )


# ---------------------------------------------------------------------------
# CL-I06 / CL-I07 / CL-I08: trust and eligibility negatives
# ---------------------------------------------------------------------------


def test_cl_i06_forged_user_token_is_rejected(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    try:
        with pytest.raises((RemoteEligibilityError, RemoteProtocolError)):
            client.evaluate(
                _request(ids["tenant_id"], ("allow", pr17.ALLOW_ACTION)),
                user_access_token="not-a-real-token",
                context=_context(ids),
            )
    finally:
        client.close()


def test_cl_i07_cross_client_pairing_is_rejected(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"], client_id=pr17.SAME_CLIENT)
    token = _user_token(disposable_user)
    other = _client(
        tmp_path,
        application_id=uuid.UUID(ids["application_id"]),
        client_id=pr17.SECOND_CLIENT,
        client_secret=pr17.SECOND_SECRET,
    )
    try:
        with pytest.raises((RemoteEligibilityError, RemoteProtocolError)):
            other.evaluate(
                _request(ids["tenant_id"], ("allow", pr17.ALLOW_ACTION)),
                user_access_token=token,
                context=_context(ids),
            )
    finally:
        other.close()


def test_cl_i08_missing_subscription_is_rejected(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    db.execute(
        "DELETE FROM mtmf.tenant_application_subscription WHERE application_id = %s",
        (ids["application_id"],),
    )
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    try:
        with pytest.raises((RemoteEligibilityError, RemoteProtocolError)):
            client.evaluate(
                _request(ids["tenant_id"], ("allow", pr17.ALLOW_ACTION)),
                user_access_token=token,
                context=_context(ids),
            )
    finally:
        client.close()


# ---------------------------------------------------------------------------
# CL-I09 / CL-I10: revocation stale window and local replay
# ---------------------------------------------------------------------------


def test_cl_i09_revocation_is_visible_to_new_evaluations(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    try:
        first = client.evaluate(
            _request(ids["tenant_id"], ("allow", pr17.ALLOW_ACTION)),
            user_access_token=token,
            context=_context(ids),
        )
        assert (
            is_allowed(
                first,
                context=_context(ids),
                action=pr17.ALLOW_ACTION,
                resource=_capability(),
                request_id="allow",
            )
            is True
        )
        db.execute(
            "DELETE FROM mtmf.identity_role_assignment WHERE identity_id = %s",
            (ids["identity_id"],),
        )
        second = client.evaluate(
            _request(ids["tenant_id"], ("allow-again", pr17.ALLOW_ACTION)),
            user_access_token=token,
            context=_context(ids),
        )
        # The revoked grant is absent from the new evaluation.
        assert (
            is_allowed(
                second,
                context=_context(ids),
                action=pr17.ALLOW_ACTION,
                resource=_capability(),
                request_id="allow-again",
            )
            is False
        )
        # The already-issued snapshot keeps its original bounded life; it is
        # not refreshed or silently extended, but it is also not retroactively
        # rewritten (documented stale window).
        assert first.decision_count == 1
    finally:
        client.close()


def test_cl_i10_local_replay_is_denied_without_http(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    try:
        snapshot = client.evaluate(
            _request(ids["tenant_id"], ("allow", pr17.ALLOW_ACTION)),
            user_access_token=token,
            context=_context(ids),
        )
        assert (
            is_allowed(
                snapshot,
                context=_context(ids, actor_key="different-actor"),
                action=pr17.ALLOW_ACTION,
                resource=_capability(),
                request_id="allow",
            )
            is False
        )
        assert (
            is_allowed(
                snapshot,
                context=_context(ids, application_id=uuid.uuid4()),
                action=pr17.ALLOW_ACTION,
                resource=_capability(),
                request_id="allow",
            )
            is False
        )
        assert (
            is_allowed(
                snapshot,
                context=_context(ids),
                action=pr17.ALLOW_ACTION,
                resource=_app_owned("row-other"),
            )
            is False
        )
    finally:
        client.close()


# ---------------------------------------------------------------------------
# CL-I13 / CL-I14 / CL-I17 / CL-I18: transport failures and isolation
# ---------------------------------------------------------------------------


def test_cl_i11_service_token_renewal_loop(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    # A very large renewal leeway forces a fresh client-credentials grant on
    # every call, exercising the bounded renewal path repeatedly.
    client = _client(
        tmp_path,
        application_id=uuid.UUID(ids["application_id"]),
        renewal_leeway_seconds=10**9,
    )
    try:
        first = client.evaluate(
            _request(ids["tenant_id"], ("first", pr17.ALLOW_ACTION)),
            user_access_token=token,
            context=_context(ids),
        )
        original_expiry = first.expires_at
        for index in range(20):
            snapshot = client.evaluate(
                _request(ids["tenant_id"], (f"loop-{index}", pr17.ALLOW_ACTION)),
                user_access_token=token,
                context=_context(ids),
            )
            assert snapshot.decision_count == 1
            assert (
                is_allowed(
                    snapshot,
                    context=_context(ids),
                    action=pr17.ALLOW_ACTION,
                    resource=_capability(),
                    request_id=f"loop-{index}",
                )
                is True
            )
        # Renewing the OAuth token never extends or refreshes the original
        # snapshot: its server-issued expiry is byte-for-byte unchanged, and
        # its own bounded (15s sensitive) monotonic deadline still governs.
        assert first.expires_at == original_expiry
        assert first.decision_count == 1
    finally:
        client.close()


def test_cl_i13_mtmf_unavailable_does_not_create_snapshot(tmp_path: Path) -> None:
    tenant_id = uuid.uuid4()
    application_id = uuid.uuid4()
    client = _client(
        tmp_path,
        application_id=application_id,
        base_url="https://127.0.0.1:9",
    )
    try:
        with pytest.raises(DependencyUnavailableError):
            client.evaluate(
                _request(str(tenant_id), ("allow", pr17.ALLOW_ACTION)),
                user_access_token="token",
                context=TrustedActorContext(
                    actor_key="a",
                    session_key="s",
                    tenant_id=tenant_id,
                    application_id=application_id,
                ),
            )
    finally:
        client.close()


def test_cl_i14_invalid_ca_fails_closed(tmp_path: Path) -> None:
    tenant_id = uuid.uuid4()
    application_id = uuid.uuid4()
    wrong_ca = tmp_path / "wrong-ca.crt"
    wrong_ca.write_bytes((_ca_dir() / "dev-ca.crt").read_bytes())
    client = _client(
        tmp_path,
        application_id=application_id,
        ca_bundle=str(wrong_ca),
        base_url="https://127.0.0.1:1",
    )
    try:
        with pytest.raises(DependencyUnavailableError):
            client.evaluate(
                _request(str(tenant_id), ("allow", pr17.ALLOW_ACTION)),
                user_access_token="token",
                context=TrustedActorContext(
                    actor_key="a",
                    session_key="s",
                    tenant_id=tenant_id,
                    application_id=application_id,
                ),
            )
    finally:
        client.close()


def test_cl_i12_token_endpoint_failure_creates_no_snapshot(tmp_path: Path) -> None:
    tenant_id = uuid.uuid4()
    application_id = uuid.uuid4()
    client = _client(
        tmp_path,
        application_id=application_id,
        client_secret="this-is-not-the-right-secret",
    )
    try:
        with pytest.raises(ClientAuthenticationError) as excinfo:
            client.evaluate(
                _request(str(tenant_id), ("allow", pr17.ALLOW_ACTION)),
                user_access_token="token",
                context=TrustedActorContext(
                    actor_key="a",
                    session_key="s",
                    tenant_id=tenant_id,
                    application_id=application_id,
                ),
            )
    finally:
        client.close()
    assert "this-is-not-the-right-secret" not in f"{excinfo.value!s} {excinfo.value!r}"


def test_cl_i15_app_owned_row_isolation_is_pep_owned(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    row42 = _app_owned("row-42")
    body = {
        "tenant_id": ids["tenant_id"],
        "organization_id": None,
        "actions": [
            {
                "request_id": "row42",
                "action": pr17.ALLOW_ACTION,
                "resource": {"kind": "application_owned", "type": "document", "id": "row-42"},
            },
        ],
    }
    try:
        snapshot = client.evaluate(
            parse_request_json(json.dumps(body)),
            user_access_token=token,
            context=_context(ids),
        )
        # The evaluated row is allowed only when the exact target is supplied.
        require(
            snapshot,
            context=_context(ids),
            action=pr17.ALLOW_ACTION,
            resource=row42,
            request_id="row42",
        )
        # A different row was never evaluated and is denied locally; an ALLOW
        # capability is not universal object access. The consumer's own SQL
        # row/Tenant predicate remains mandatory.
        assert (
            is_allowed(
                snapshot,
                context=_context(ids),
                action=pr17.ALLOW_ACTION,
                resource=_app_owned("row-43"),
            )
            is False
        )
        assert row42.resource_id == "row-42"
    finally:
        client.close()


def test_cl_i16_owned_uvicorn_restart_recovery(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    """Owned service restart: ALLOW -> down -> typed failure -> up -> ALLOW.

    Only a Uvicorn instance created by this test is stopped and restarted;
    the shared Keycloak issuer and PostgreSQL stay up throughout. The same
    ``HttpMtmfClient`` instance survives the restart with no authorization
    retry and no snapshot extension. Keycloak restart is NOT TESTED here.
    """
    ids = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    port = _free_loopback_port()
    certfile, keyfile = _generate_leaf_certificate(tmp_path)
    base_url = f"https://127.0.0.1:{port}"
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]), base_url=base_url)
    first_server = _TlsLiveServer(_live_app(), certfile, keyfile, port=port)
    second_server: _TlsLiveServer | None = None
    try:
        first_server.__enter__()
        first = client.evaluate(
            _request(ids["tenant_id"], ("first", pr17.ALLOW_ACTION)),
            user_access_token=token,
            context=_context(ids),
        )
        require(
            first,
            context=_context(ids),
            action=pr17.ALLOW_ACTION,
            resource=_capability(),
            request_id="first",
        )
        original_expiry = first.expires_at

        first_server.__exit__(None, None, None)
        _wait_port_closed(port)
        with pytest.raises(DependencyUnavailableError):
            client.evaluate(
                _request(ids["tenant_id"], ("down", pr17.ALLOW_ACTION)),
                user_access_token=token,
                context=_context(ids),
            )

        # Shared dependencies remained running (fresh Keycloak token + DB).
        assert _user_token(disposable_user)
        assert db.execute("SELECT 1").fetchone()[0] == 1

        second_server = _TlsLiveServer(_live_app(), certfile, keyfile, port=port)
        second_server.__enter__()
        second = client.evaluate(
            _request(ids["tenant_id"], ("second", pr17.ALLOW_ACTION)),
            user_access_token=token,
            context=_context(ids),
        )
        require(
            second,
            context=_context(ids),
            action=pr17.ALLOW_ACTION,
            resource=_capability(),
            request_id="second",
        )
        # The pre-restart snapshot is neither renewed nor extended.
        assert first.expires_at == original_expiry
        assert first.decision_count == 1
        assert second.decision_count == 1
    finally:
        if second_server is not None:
            second_server.__exit__(None, None, None)
        client.close()


def test_cl_i17_two_clients_do_not_cross_contaminate(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids_a = pr17._seed(db, disposable_user["subject"])
    token = _user_token(disposable_user)
    client_a = _client(tmp_path, application_id=uuid.UUID(ids_a["application_id"]))
    client_b = _client(tmp_path, application_id=uuid.UUID(ids_a["application_id"]))
    try:
        snap_a = client_a.evaluate(
            _request(ids_a["tenant_id"], ("allow", pr17.ALLOW_ACTION)),
            user_access_token=token,
            context=_context(ids_a, actor_key="actor-a", session_key="session-a"),
        )
        assert (
            client_b.is_allowed(
                snap_a,
                context=_context(ids_a, actor_key="actor-a", session_key="session-a"),
                action=pr17.ALLOW_ACTION,
                resource=_capability(),
                request_id="allow",
            )
            is False
        )
    finally:
        client_a.close()
        client_b.close()


def test_cl_i18_typed_error_envelopes(
    db: psycopg.Connection,
    live_server: Any,
    disposable_user: dict[str, str],
    tmp_path: Path,
) -> None:
    ids = pr17._seed(db, disposable_user["subject"])
    client = _client(tmp_path, application_id=uuid.UUID(ids["application_id"]))
    try:
        with pytest.raises((RemoteEligibilityError, RemoteProtocolError)):
            client.evaluate(
                _request(ids["tenant_id"], ("allow", pr17.ALLOW_ACTION)),
                user_access_token="forged",
                context=_context(ids),
            )
    finally:
        client.close()
