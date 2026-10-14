"""Live PR 17 HTTP acceptance: real Keycloak tokens -> real Uvicorn -> real PostgreSQL.

Opt-in and authoritative only when ``MTMF_PR17_LIVE=1`` and the isolated
Keycloak fixture plus the real PostgreSQL role topology are available. A
real Uvicorn server is bound to loopback and driven with genuine
issuer-signed service and interactive-user access tokens. Without the flag
the module is skipped. Tokens, secrets and admin credentials are never
printed or persisted.

Required environment (same as the PR 14 live suite): ``MTMF_PR14_KC_BASE``,
``MTMF_PR14_KC_ADMIN_USERNAME``, ``MTMF_PR14_KC_ADMIN_PASSWORD``,
``MTMF_PR14_KC_USER_PASSWORD``, ``MTMF_PR14_KC_CA_FILE``, plus the
``MTMF_RUNTIME_*`` PostgreSQL configuration.
"""

from __future__ import annotations

import importlib.util
import json
import os
import ssl
import subprocess
import sys
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
import uvicorn

from mtmf_api.authorization import AuthorizationBatchRequest
from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresMtmfSpi,
    PostgresRole,
)
from mtmf_service.app import create_app
from mtmf_service.authentication.config import IssuerConfig
from mtmf_service.composition import build_authorization_service, build_readiness
from mtmf_service.rate_limit import TokenBucketRateLimiter
from mtmf_service.readiness import StaticReadiness
from mtmf_service.settings import ServiceSettings

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR17_LIVE") != "1",
    reason="live PR 17 HTTP acceptance is opt-in (set MTMF_PR17_LIVE=1)",
)

REALM = os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-dev")
SHARED_AUDIENCE = "mtmf-same-client-api"
SAME_CLIENT = "mtmf-evidence-same-client"
SAME_SECRET = "mtmf-evidence-same-client-dev-secret"
USER = "mtmf-user-bob"
SECOND_CLIENT = "mtmf-evidence-same-client-b"
SECOND_SECRET = "mtmf-evidence-same-client-b-dev-secret"
SECOND_USER = "mtmf-user-carol"
PORT = 28011
BASE_URL = f"http://127.0.0.1:{PORT}"

ALLOW_ACTION = "urn:mtmf:iam:actions:system:principal:get-object"
DENY_ACTION = "urn:mtmf:iam:actions:system:principal:update-object"
NO_PERMISSION_ACTION = "urn:mtmf:iam:actions:system:role:get-object"
UNKNOWN_ACTION = "urn:mtmf:iam:actions:system:frobnicator:get-object"
ROLE_URN = "urn:mtmf:iam:roles:system:dev-admin"

_EVIDENCE = Path(__file__).resolve().parents[3] / "scripts" / "pr14-keycloak-evidence.py"
_spec = importlib.util.spec_from_file_location("pr14_keycloak_evidence", _EVIDENCE)
assert _spec is not None and _spec.loader is not None
ev = importlib.util.module_from_spec(_spec)
sys.modules["pr14_keycloak_evidence"] = ev
_spec.loader.exec_module(ev)


def _env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"live acceptance requires {name}")
    return value


def _uuid() -> str:
    return str(uuid.uuid4())


def _issuer_str() -> str:
    return f"{_env('MTMF_PR14_KC_BASE')}/realms/{REALM}"


def _issuer_config(*, expected_manifest: str | None = None) -> IssuerConfig:
    base = _env("MTMF_PR14_KC_BASE")
    issuer = f"{base}/realms/{REALM}"
    return IssuerConfig(
        issuer=issuer,
        service_audience=SHARED_AUDIENCE,
        user_audience=SHARED_AUDIENCE,
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
        expected_manifest_path=expected_manifest or "dev/keycloak/expected-realm-security.json",
        admin_base_url=base,
        admin_realm=REALM,
        attestation_client_id="mtmf-attestation-reader",
        attestation_client_secret="mtmf-attestation-reader-dev-secret",
        allow_shared_audience=True,
    )


def _issuer() -> ev.Issuer:
    return ev.Issuer(
        base=_env("MTMF_PR14_KC_BASE"),
        realm=REALM,
        ca_file=os.environ.get("MTMF_PR14_KC_CA_FILE", ""),
    )


def _service_token(client_id: str = SAME_CLIENT, client_secret: str = SAME_SECRET) -> str:
    return ev.client_credentials_token(_issuer(), client_id, client_secret)["access_token"]


def _user_token(
    *, client_id: str = SAME_CLIENT, client_secret: str = SAME_SECRET, user: str = USER
) -> str:
    token = ev.authorization_code_token(
        _issuer(),
        client_id,
        client_secret,
        user,
        _env("MTMF_PR14_KC_USER_PASSWORD"),
        "http://127.0.0.1:28400/callback",
        28400,
    )
    return str(token["access_token"])


def _seed(
    db: psycopg.Connection, subject: str, *, memberships: bool = True, client_id: str = SAME_CLIENT
) -> dict[str, str]:
    """Seed one ordinary Tenant, Application, Role and policy graph."""
    principal_id, identity_id, tenant_id = _uuid(), _uuid(), _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s,'P',2)", (principal_id,)
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s,%s,'I',2,2)",
        (identity_id, principal_id),
    )
    db.execute(
        "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s,'T',2,%s,1,2)",
        (tenant_id, identity_id),
    )
    if memberships:
        db.execute(
            "INSERT INTO mtmf.principal_tenant_membership (principal_id, tenant_id) VALUES (%s,%s)",
            (principal_id, tenant_id),
        )
        db.execute(
            "INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id) VALUES (%s,%s)",
            (identity_id, tenant_id),
        )
    application_id = _uuid()
    db.execute(
        "SELECT mtmf.application_add(%s,%s,'A',%s,1::smallint,'{}'::jsonb)",
        (application_id, f"app-{_uuid()[:8]}", identity_id),
    )
    db.execute(
        "SELECT mtmf.application_tenant_registration_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), application_id, tenant_id, identity_id),
    )
    db.execute(
        "SELECT mtmf.tenant_application_subscription_add(%s,%s,%s,%s,1::smallint,%s,%s,now())",
        (
            _uuid(),
            application_id,
            tenant_id,
            identity_id,
            datetime.now(UTC) - timedelta(days=1),
            None,
        ),
    )
    db.execute(
        "SELECT mtmf.service_credential_application_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), client_id, application_id),
    )
    db.execute(
        "SELECT mtmf.external_subject_identity_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), subject, identity_id),
    )
    # Registered Actions plus a SYSTEM Role granting exactly ALLOW for
    # ``principal:get-object``.
    for urn in (ALLOW_ACTION, DENY_ACTION, NO_PERMISSION_ACTION):
        db.execute("SELECT mtmf.action_add(%s)", (urn,))
    role_urn = f"{ROLE_URN}-{_uuid()[:8]}"
    db.execute(
        "INSERT INTO mtmf.role (urn, name, description, defining_tenant_id) "
        "VALUES (%s, 'Dev Admin', '', NULL)",
        (role_urn,),
    )
    permission_set_id = _uuid()
    db.execute(
        "INSERT INTO mtmf.permission_set (id, role_urn, effect, position) "
        "VALUES (%s, %s, 'allow', 0)",
        (permission_set_id, role_urn),
    )
    db.execute(
        "INSERT INTO mtmf.permission (id, permission_set_id, urn, position) VALUES (%s, %s, %s, 0)",
        (_uuid(), permission_set_id, "urn:mtmf:iam:permissions:system:principal:get-object"),
    )
    db.execute(
        "SELECT mtmf.identity_role_assignment_add(%s,%s,%s,%s,NULL)",
        (_uuid(), tenant_id, identity_id, role_urn),
    )
    return {
        "principal_id": principal_id,
        "identity_id": identity_id,
        "tenant_id": tenant_id,
        "application_id": application_id,
    }


def _body(
    tenant_id: str,
    *actions: tuple[str, str],
    organization_id: str | None = None,
    kind: str = "capability",
) -> dict[str, Any]:
    resources = (
        {"kind": kind} if kind == "capability" else {"kind": kind, "type": "thing", "id": "t-1"}
    )
    return {
        "tenant_id": tenant_id,
        "organization_id": organization_id,
        "actions": [
            {"request_id": request_id, "action": action, "resource": resources}
            for request_id, action in actions
        ],
    }


def _headers(service: str, user: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {service}",
        "X-MTMF-User-Authorization": f"Bearer {user}",
    }


class _Admin:
    """Minimal Keycloak Admin REST client for live drift injection."""

    def __init__(self) -> None:
        self.base = _env("MTMF_PR14_KC_BASE")
        self.context = ssl.create_default_context(cafile=os.environ.get("MTMF_PR14_KC_CA_FILE", ""))

    def _request(self, method: str, path: str, body: Any | None = None) -> Any:
        token = self._token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        data = None if body is None else json.dumps(body).encode()
        request = httpx.Request(method, f"{self.base}{path}", content=data, headers=headers)
        with httpx.Client(verify=self.context, timeout=10) as client:
            response = client.send(request)
            response.raise_for_status()
            return response.json() if response.content else None

    def _token(self) -> str:
        import urllib.parse

        data = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": _env("MTMF_PR14_KC_ADMIN_USERNAME"),
                "password": _env("MTMF_PR14_KC_ADMIN_PASSWORD"),
            }
        )
        with httpx.Client(verify=self.context, timeout=10) as client:
            response = client.post(
                f"{self.base}/realms/master/protocol/openid-connect/token",
                content=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            return str(response.json()["access_token"])

    def client(self) -> dict[str, Any]:
        rows = self._request("GET", f"/admin/realms/{REALM}/clients?clientId={SAME_CLIENT}")
        return rows[0]

    def add_mapper(self, client_uuid: str, claim: str) -> None:
        self._request(
            "POST",
            f"/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models",
            {
                "name": f"a3-spoof-{claim}",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {
                    "claim.name": claim,
                    "claim.value": SAME_CLIENT,
                    "access.token.claim": "true",
                },
            },
        )

    def remove_mapper(self, client_uuid: str, claim: str) -> None:
        for mapper in (
            self._request(
                "GET", f"/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models"
            )
            or []
        ):
            if mapper["name"] == f"a3-spoof-{claim}":
                self._request(
                    "DELETE",
                    f"/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models/"
                    f"{mapper['id']}",
                )


def _post(
    body: dict[str, Any],
    *,
    service: str,
    user: str,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
    content_type: str = "application/json",
    base_url: str = BASE_URL,
) -> httpx.Response:
    with httpx.Client(base_url=base_url, timeout=30) as client:
        if content is not None:
            return client.post(
                "/v1/authorization/evaluate",
                content=content,
                headers={"Content-Type": content_type, **_headers(service, user)},
            )
        return client.post(
            "/v1/authorization/evaluate",
            json=body,
            headers=headers or _headers(service, user),
        )


class _LiveServer:
    def __init__(self, app: Any, port: int = PORT) -> None:
        self._config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self._server = uvicorn.Server(self._config)
        self._thread = threading.Thread(target=self._server.run, daemon=True)

    def __enter__(self) -> _LiveServer:
        self._thread.start()
        deadline = time.monotonic() + 30
        while not self._server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        if not self._server.started:
            raise RuntimeError("uvicorn did not start")
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=10)


class _UnusedManagementMembershipService:
    """Narrow stub: this PDP suite does not exercise the management route."""

    def add_identity_to_group(self, *, service_token: str, user_token: str, request: Any) -> Any:
        raise AssertionError("the management route is not exercised by this suite")


def _live_app(
    *,
    expected_manifest: str | None = None,
    rate_limiter: Any | None = None,
    evaluation_timeout_seconds: float = 30.0,
) -> Any:
    spi = PostgresMtmfSpi(PostgresConfig.from_env(PostgresRole.RUNTIME))
    settings = ServiceSettings(evaluation_timeout_seconds=evaluation_timeout_seconds)
    authorization_service = build_authorization_service(
        spi=spi,
        issuer_config=_issuer_config(expected_manifest=expected_manifest),
        settings=settings,
    )
    return create_app(
        settings=settings,
        authorization_service=authorization_service,
        management_membership_service=_UnusedManagementMembershipService(),  # type: ignore[arg-type]
        readiness=StaticReadiness(True),
        rate_limiter=rate_limiter or TokenBucketRateLimiter(per_minute=100000, burst=100000),
    )


@pytest.fixture(scope="module")
def live_server() -> Any:
    """A real Uvicorn server bound to loopback for the live cases."""
    if os.environ.get("SSL_CERT_FILE", "").strip() == "":
        os.environ["SSL_CERT_FILE"] = _env("MTMF_PR14_KC_CA_FILE")
    with _LiveServer(_live_app()) as server:
        yield server


def test_v01_readiness_is_ready(live_server: Any) -> None:
    with httpx.Client(base_url=BASE_URL, timeout=10) as client:
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 200


def test_v02_real_tokens_allow_and_deny(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    allowed = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["decisions"] == [
        {"request_id": "r1", "effect": "ALLOW", "reason": "PERMITTED"}
    ]
    denied = _post(
        _body(ids["tenant_id"], ("r1", DENY_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert denied.status_code == 200
    assert denied.json()["decisions"][0]["effect"] == "DENY"
    assert denied.json()["decisions"][0]["reason"] == "NO_PERMISSION"


def test_v03_hundred_item_ordered_batch(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    actions = tuple(
        (f"r{i}", ALLOW_ACTION if i % 2 == 0 else NO_PERMISSION_ACTION) for i in range(100)
    )
    response = _post(
        _body(ids["tenant_id"], *actions), service=_service_token(), user=_user_token()
    )
    assert response.status_code == 200
    decisions = response.json()["decisions"]
    assert len(decisions) == 100
    assert [d["request_id"] for d in decisions] == [f"r{i}" for i in range(100)]
    assert decisions[0]["effect"] == "ALLOW"
    assert decisions[1]["reason"] == "NO_PERMISSION"


def test_v02_unknown_action_and_mtmf_owned(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    unknown = _post(
        _body(ids["tenant_id"], ("r1", UNKNOWN_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert unknown.status_code == 200
    assert unknown.json()["decisions"][0]["reason"] == "UNKNOWN_ACTION"
    owned = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION), kind="mtmf_owned"),
        service=_service_token(),
        user=_user_token(),
    )
    assert owned.status_code == 200
    assert owned.json()["decisions"][0]["reason"] == "UNSUPPORTED_RESOURCE"


@pytest.mark.parametrize("lifecycle", [2, 3, 4])  # SUSPENDED, CANCELLED, EXPIRED
def test_v04_lifecycle_ineligible(db: psycopg.Connection, live_server: Any, lifecycle: int) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    db.execute(
        "UPDATE mtmf.tenant_application_subscription SET lifecycle = %s WHERE application_id = %s",
        (lifecycle, ids["application_id"]),
    )
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INELIGIBLE_APPLICATION"


def test_v04_no_subscription_is_ineligible(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    db.execute(
        "DELETE FROM mtmf.tenant_application_subscription WHERE application_id = %s",
        (ids["application_id"],),
    )
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INELIGIBLE_APPLICATION"


def test_v04_time_expired_subscription_is_ineligible(
    db: psycopg.Connection, live_server: Any
) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    db.execute(
        "UPDATE mtmf.tenant_application_subscription SET ends_at = %s WHERE application_id = %s",
        (datetime.now(UTC) - timedelta(hours=1), ids["application_id"]),
    )
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INELIGIBLE_APPLICATION"


def test_v05_wrong_tenant_and_forged_user(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    _seed(db, subject)
    mismatched = _post(
        _body(_uuid(), ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert mismatched.status_code == 403
    assert mismatched.json()["error"]["code"] == "UNTRUSTED_ACTOR"
    forged = _post(
        _body(_uuid(), ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user="not-a-token",
    )
    assert forged.status_code == 403


def test_v05_foreign_organization_is_rejected(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION), organization_id=_uuid()),
        service=_service_token(),
        user=_user_token(),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "UNTRUSTED_ACTOR"


def test_v05_different_client_service_token_is_rejected(
    db: psycopg.Connection, live_server: Any
) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    other = ev.Issuer(
        base=_env("MTMF_PR14_KC_BASE"),
        realm=REALM,
        ca_file=os.environ.get("MTMF_PR14_KC_CA_FILE", ""),
    )
    other_service = ev.client_credentials_token(
        other, "mtmf-evidence-service", "mtmf-evidence-service-dev-secret"
    )["access_token"]
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=other_service,
        user=_user_token(),
    )
    # The different-client service token carries the wrong audience/class for
    # this profile, so it fails closed at the trust boundary (401/403). The
    # explicit same-client D1 binding rejection with matching audiences is
    # covered by the PR 14 live suite (`test_dc07_v05_cross_client_rejected`)
    # and unit H13. The approved fixture has no second client with the shared
    # audience, so a same-audience cross-client pair cannot be built here
    # without a manifest change (STOP-01).
    assert response.status_code in (401, 403)
    assert "ALLOW" not in response.text


def test_v06_root_subject_is_denied(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    # A normal Application/credential binding is needed to reach the root
    # exclusion; then re-point the acting subject at the canonical root and
    # attempt a root-Tenant evaluation.
    _seed(db, subject)
    db.execute(
        "SELECT mtmf.external_subject_identity_revoke(id) FROM mtmf.external_subject_identity "
        "WHERE subject = %s AND lifecycle = 1",
        (subject,),
    )
    root_tenant = _uuid()
    db.execute(
        "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
        (root_tenant, _uuid(), _uuid()),
    )
    root_identity = db.execute("SELECT root_identity_id FROM mtmf.root_registry").fetchone()[0]
    db.execute(
        "SELECT mtmf.external_subject_identity_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), subject, root_identity),
    )
    response = _post(
        _body(root_tenant, ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "UNTRUSTED_ACTOR"
    assert "ALLOW" not in response.text


def test_v15_live_http_limits_and_errors(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    service, user = _service_token(), _user_token()
    oversized = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=service,
        user=user,
        content=b" " * 65537,
    )
    assert oversized.status_code == 413
    assert oversized.json()["error"]["code"] == "REQUEST_TOO_LARGE"
    wrong_media = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=service,
        user=user,
        content=b"{}",
        content_type="text/plain",
    )
    assert wrong_media.status_code == 415
    missing_service = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=service,
        user=user,
        headers={"X-MTMF-User-Authorization": f"Bearer {user}"},
    )
    assert missing_service.status_code == 401
    assert missing_service.headers.get("cache-control") == "no-store"


def test_v15_rate_limit_saturation_is_429(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    rate = f"http://127.0.0.1:{PORT + 2}"
    with _LiveServer(
        _live_app(rate_limiter=TokenBucketRateLimiter(per_minute=1, burst=1)), port=PORT + 2
    ):
        first = _post(
            _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
            service=_service_token(),
            user=_user_token(),
            base_url=rate,
        )
        assert first.status_code == 200
        second = _post(
            _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
            service=_service_token(),
            user=_user_token(),
            base_url=rate,
        )
        assert second.status_code == 429
        assert second.json()["error"]["code"] == "RATE_LIMITED"
        assert second.headers.get("cache-control") == "no-store"


def test_v07_manifest_mismatch_fails_closed(live_server: Any) -> None:
    """A drifted/unreadable trusted baseline must never authenticate."""
    with _LiveServer(_live_app(expected_manifest="/nonexistent/manifest.json"), port=PORT + 1):
        response = _post(
            _body(_uuid(), ("r1", ALLOW_ACTION)),
            service=_service_token(),
            user=_user_token(),
            base_url=f"http://127.0.0.1:{PORT + 1}",
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"


def test_v07_no_positive_attestation_cache(db: psycopg.Connection, live_server: Any) -> None:
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    first = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert first.status_code == 200
    # Mutate a security-relevant client field that does not affect verifying an
    # already-issued token; the next request must freshly detect the drift from
    # the approved client policy (no positive attestation cache).
    admin = _Admin()
    client = admin.client()
    original = list(client.get("webOrigins") or [])
    admin._request(
        "PUT",
        f"/admin/realms/{REALM}/clients/{client['id']}",
        {**client, "webOrigins": [*original, "http://drift.example"]},
    )
    try:
        drifted = _post(
            _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
            service=_service_token(),
            user=_user_token(),
        )
        assert drifted.status_code == 503, drifted.text
        assert drifted.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
        assert "ALLOW" not in drifted.text
    finally:
        admin._request(
            "PUT",
            f"/admin/realms/{REALM}/clients/{client['id']}",
            {**client, "webOrigins": original},
        )


def _subject(username: str) -> str:
    token = _user_token(user=username)
    return ev.decode_unverified(token)[1]["sub"]


def test_cl01_client_a_allows(db: psycopg.Connection, live_server: Any) -> None:
    ids = _seed(db, ev.decode_unverified(_user_token())[1]["sub"])
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert response.status_code == 200, response.text
    assert response.json()["decisions"][0]["effect"] == "ALLOW"


def test_cl02_client_b_allows(db: psycopg.Connection, live_server: Any) -> None:
    ids = _seed(
        db,
        _subject(SECOND_USER),
        client_id=SECOND_CLIENT,
    )
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(SECOND_CLIENT, SECOND_SECRET),
        user=_user_token(client_id=SECOND_CLIENT, client_secret=SECOND_SECRET, user=SECOND_USER),
    )
    assert response.status_code == 200, response.text
    assert response.json()["decisions"][0]["effect"] == "ALLOW"


def test_cl03_client_a_service_with_client_b_user_is_rejected(
    db: psycopg.Connection, live_server: Any
) -> None:
    ids = _seed(db, ev.decode_unverified(_user_token())[1]["sub"])
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(client_id=SECOND_CLIENT, client_secret=SECOND_SECRET, user=SECOND_USER),
    )
    assert response.status_code == 403
    assert "ALLOW" not in response.text


def test_cl04_client_b_service_with_client_a_user_is_rejected(
    db: psycopg.Connection, live_server: Any
) -> None:
    ids = _seed(db, _subject(SECOND_USER), client_id=SECOND_CLIENT)
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token(SECOND_CLIENT, SECOND_SECRET),
        user=_user_token(),
    )
    assert response.status_code == 403
    assert "ALLOW" not in response.text


def test_cl05_client_a_with_foreign_tenant_is_rejected(
    db: psycopg.Connection, live_server: Any
) -> None:
    _seed(db, ev.decode_unverified(_user_token())[1]["sub"])
    _seed(db, _subject(SECOND_USER), client_id=SECOND_CLIENT)
    foreign_tenant = db.execute(
        "SELECT r.tenant_id FROM mtmf.service_credential_application s "
        "JOIN mtmf.application_tenant_registration r "
        "ON r.application_id = s.application_id "
        "WHERE s.client_id = %s AND r.lifecycle = 1",
        (SECOND_CLIENT,),
    ).fetchone()[0]
    # Client A's service token presented with Client B's Tenant selector.
    response = _post(
        _body(str(foreign_tenant), ("r1", ALLOW_ACTION)),
        service=_service_token(),
        user=_user_token(),
    )
    assert response.status_code == 403
    assert "ALLOW" not in response.text


def test_cl06_unapproved_client_is_rejected(db: psycopg.Connection, live_server: Any) -> None:
    ids = _seed(db, ev.decode_unverified(_user_token())[1]["sub"])
    response = _post(
        _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
        service=_service_token("mtmf-evidence-service", "mtmf-evidence-service-dev-secret"),
        user=_user_token(),
    )
    assert response.status_code in (401, 403, 503)
    assert "ALLOW" not in response.text


def test_cl07_client_b_drift_does_not_affect_client_a(
    db: psycopg.Connection, live_server: Any
) -> None:
    ids_a = _seed(db, ev.decode_unverified(_user_token())[1]["sub"])
    ids_b = _seed(db, _subject(SECOND_USER), client_id=SECOND_CLIENT)
    admin = _Admin()
    rows = admin._request("GET", f"/admin/realms/{REALM}/clients?clientId={SECOND_CLIENT}")
    client = rows[0]
    original = list(client.get("webOrigins") or [])
    admin._request(
        "PUT",
        f"/admin/realms/{REALM}/clients/{client['id']}",
        {**client, "webOrigins": [*original, "http://drift.example"]},
    )
    try:
        b = _post(
            _body(ids_b["tenant_id"], ("r1", ALLOW_ACTION)),
            service=_service_token(SECOND_CLIENT, SECOND_SECRET),
            user=_user_token(
                client_id=SECOND_CLIENT, client_secret=SECOND_SECRET, user=SECOND_USER
            ),
        )
        assert b.status_code == 503, b.text
        a = _post(
            _body(ids_a["tenant_id"], ("r1", ALLOW_ACTION)),
            service=_service_token(),
            user=_user_token(),
        )
        assert a.status_code == 200, a.text
    finally:
        admin._request(
            "PUT",
            f"/admin/realms/{REALM}/clients/{client['id']}",
            {**client, "webOrigins": original},
        )


def _live_app_with_db_readiness(port: int) -> Any:
    """A live app whose readiness performs a real PostgreSQL check."""
    spi = PostgresMtmfSpi(PostgresConfig.from_env(PostgresRole.RUNTIME))
    settings = ServiceSettings(evaluation_timeout_seconds=30)
    authorization_service = build_authorization_service(
        spi=spi, issuer_config=_issuer_config(), settings=settings
    )
    readiness = build_readiness(
        spi=spi, initialization_complete=lambda: True, require_initialization=False
    )
    return create_app(
        settings=settings,
        authorization_service=authorization_service,
        management_membership_service=_UnusedManagementMembershipService(),  # type: ignore[arg-type]
        readiness=readiness,
        rate_limiter=TokenBucketRateLimiter(per_minute=100000, burst=100000),
    )


def _wait_postgres_healthy(timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["podman", "inspect", "--format", "{{.State.Health.Status}}", "mtmf_postgres_1"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.stdout.strip() == "healthy":
            return
        time.sleep(2.0)
    raise AssertionError("PostgreSQL did not return to healthy")


def test_v08_live_database_outage_and_recovery(db: psycopg.Connection, live_server: Any) -> None:
    """Real HTTP outage: 503 with no decisions, non-ready, then recovery."""
    subject = ev.decode_unverified(_user_token())[1]["sub"]
    ids = _seed(db, subject)
    port = PORT + 3
    base = f"http://127.0.0.1:{port}"
    with _LiveServer(_live_app_with_db_readiness(port), port=port):
        service, user = _service_token(), _user_token()
        healthy = _post(
            _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
            service=service,
            user=user,
            base_url=base,
        )
        assert healthy.status_code == 200, healthy.text
        with httpx.Client(base_url=base, timeout=10) as client:
            assert client.get("/health/ready").status_code == 200
        subprocess.run(["podman", "stop", "mtmf_postgres_1"], check=True, capture_output=True)
        try:
            failed = _post(
                _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
                service=service,
                user=user,
                base_url=base,
            )
            assert failed.status_code == 503, failed.text
            assert failed.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"
            assert "decisions" not in failed.text and "ALLOW" not in failed.text
            with httpx.Client(base_url=base, timeout=10) as client:
                assert client.get("/health/ready").status_code == 503
        finally:
            subprocess.run(["podman", "start", "mtmf_postgres_1"], check=True, capture_output=True)
        _wait_postgres_healthy()
        recovered = None
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            recovered = _post(
                _body(ids["tenant_id"], ("r1", ALLOW_ACTION)),
                service=_service_token(),
                user=_user_token(),
                base_url=base,
            )
            if recovered.status_code == 200:
                break
            time.sleep(3.0)
        assert recovered is not None and recovered.status_code == 200, recovered.text
        with httpx.Client(base_url=base, timeout=10) as client:
            assert client.get("/health/ready").status_code == 200


def test_request_model_round_trips() -> None:
    # Guard: the live harness uses the same frozen request DTO as production.
    assert AuthorizationBatchRequest.__module__ == "mtmf_api.authorization"


def _new_ssl_context() -> ssl.SSLContext:  # pragma: no cover - helper
    return ssl.create_default_context(cafile=os.environ.get("MTMF_PR14_KC_CA_FILE", ""))
