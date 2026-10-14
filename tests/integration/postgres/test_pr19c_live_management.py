"""PR 19C live acceptance: real Keycloak -> real Uvicorn -> real PostgreSQL.

Opt-in and authoritative only when ``MTMF_PR19C_LIVE=1`` and the canonical
``mtmf-dev`` Keycloak issuer, the real PostgreSQL role topology and the
v012-audited schema are available. A real Uvicorn server is bound to
loopback and driven with genuine issuer-signed service and acting-user
access tokens. Without the flag the module is skipped.

Environment (same shape as the PR 14/17 live suites):
``MTMF_PR19C_KC_BASE``/``MTMF_PR14_KC_BASE``,
``MTMF_PR19C_CA_FILE``/``MTMF_PR14_KC_CA_FILE``, and the acceptance admin/user
passwords (``MTMF_PR19C_*`` or ``MTMF_PR14_KC_*``), plus the ``MTMF_RUNTIME_*``
configuration.

Tokens, secrets and admin credentials are never printed or persisted.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest
import uvicorn

from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresMtmfSpi,
    PostgresRole,
)
from mtmf_service.app import create_app
from mtmf_service.authentication.config import IssuerConfig
from mtmf_service.composition import build_dependencies
from mtmf_service.rate_limit import TokenBucketRateLimiter
from mtmf_service.readiness import StaticReadiness
from mtmf_service.settings import ServiceSettings

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR19C_LIVE") != "1",
    reason="live PR 19C management acceptance is opt-in (set MTMF_PR19C_LIVE=1)",
)

REALM = os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-dev")
SAME_CLIENT = "mtmf-evidence-same-client"
SAME_SECRET = "mtmf-evidence-same-client-dev-secret"
SHARED_AUDIENCE = "mtmf-same-client-api"
STEWARD_USER = "mtmf-user-bob"
NON_STEWARD_USER = "mtmf-user-carol"
PORT = 28012
BASE_URL = f"http://127.0.0.1:{PORT}"
ROUTE = "/v1/management/identity-group-memberships"
TENANT_ADMIN_URN = "urn:mtmf:iam:roles:system:tenant-administrator"

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


def _kc_base() -> str:
    return os.environ.get("MTMF_PR19C_KC_BASE", "").strip() or _env("MTMF_PR14_KC_BASE")


def _ca_file() -> str:
    return os.environ.get("MTMF_PR19C_CA_FILE", "").strip() or _env("MTMF_PR14_KC_CA_FILE")


def _admin_user() -> str:
    return os.environ.get("MTMF_PR19C_ADMIN_USERNAME", "").strip() or _env(
        "MTMF_PR14_KC_ADMIN_USERNAME"
    )


def _admin_password() -> str:
    return os.environ.get("MTMF_PR19C_ADMIN_PASSWORD", "").strip() or _env(
        "MTMF_PR14_KC_ADMIN_PASSWORD"
    )


def _user_password() -> str:
    return os.environ.get("MTMF_PR19C_USER_PASSWORD", "").strip() or _env(
        "MTMF_PR14_KC_USER_PASSWORD"
    )


def _uuid() -> str:
    import uuid

    return str(uuid.uuid4())


def _issuer_str() -> str:
    return f"{_kc_base()}/realms/{REALM}"


def _issuer_config() -> IssuerConfig:
    base = _kc_base()
    issuer = f"{base}/realms/{REALM}"
    return IssuerConfig(
        issuer=issuer,
        service_audience=SHARED_AUDIENCE,
        user_audience=SHARED_AUDIENCE,
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
        expected_manifest_path="dev/keycloak/expected-realm-security.json",
        admin_base_url=base,
        admin_realm=REALM,
        attestation_client_id="mtmf-attestation-reader",
        attestation_client_secret="mtmf-attestation-reader-dev-secret",
        allow_shared_audience=True,
    )


def _keycloak_issuer() -> Any:
    return ev.Issuer(
        base=_kc_base(),
        realm=REALM,
        ca_file=_ca_file(),
    )


def _service_token() -> str:
    return str(
        ev.client_credentials_token(_keycloak_issuer(), SAME_CLIENT, SAME_SECRET)["access_token"]
    )


def _user_token(user: str) -> str:
    token = ev.authorization_code_token(
        _keycloak_issuer(),
        SAME_CLIENT,
        SAME_SECRET,
        user,
        _user_password(),
        "http://127.0.0.1:28400/callback",
        28400,
    )
    return str(token["access_token"])


def _subject(token: str) -> str:
    return str(ev.decode_unverified(token)[1]["sub"])


def _seed(
    db: psycopg.Connection, *, steward_subject: str, non_steward_subject: str
) -> dict[str, str]:
    """Provision the PR 19C live fixture through the authorized primitives."""
    principal, steward, non_steward, target = (_uuid() for _ in range(4))
    tenant, other_tenant, group = (_uuid() for _ in range(3))
    application = _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s,'P',2)", (principal,)
    )
    for identity, name in ((steward, "Steward"), (non_steward, "Other"), (target, "Target")):
        db.execute(
            "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
            "VALUES (%s,%s,%s,2,2)",
            (identity, principal, name),
        )
    db.execute(
        "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s,'T',2,%s,1,2), (%s,'O',2,%s,1,2)",
        (tenant, steward, other_tenant, steward),
    )
    db.execute("INSERT INTO mtmf.principal_tenant_membership VALUES (%s,%s)", (principal, tenant))
    for identity in (steward, non_steward, target):
        db.execute("INSERT INTO mtmf.identity_tenant_membership VALUES (%s,%s)", (identity, tenant))
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s,%s,'G',2)",
        (group, tenant),
    )
    db.execute("INSERT INTO mtmf.group_tenant_membership VALUES (%s,%s)", (group, tenant))
    db.execute(
        "INSERT INTO mtmf.identity_role_assignment (id, tenant_id, identity_id, role_urn) "
        "VALUES (%s,%s,%s,%s)",
        (_uuid(), tenant, steward, TENANT_ADMIN_URN),
    )
    db.execute(
        "INSERT INTO mtmf.stewardship_designation "
        "(tenant_id, steward_principal_id, designated_identity_id, version) VALUES (%s,%s,%s,1)",
        (tenant, principal, steward),
    )
    db.execute(
        "SELECT mtmf.application_add(%s,%s,'A',%s,1::smallint,'{}'::jsonb)",
        (application, f"app-{_uuid()[:8]}", steward),
    )
    db.execute(
        "SELECT mtmf.application_tenant_registration_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), application, tenant, steward),
    )
    from datetime import UTC, datetime, timedelta

    db.execute(
        "SELECT mtmf.tenant_application_subscription_add(%s,%s,%s,%s,1::smallint,%s,%s,now())",
        (
            _uuid(),
            application,
            tenant,
            steward,
            datetime.now(UTC) - timedelta(days=1),
            None,
        ),
    )
    db.execute(
        "SELECT mtmf.service_credential_application_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), SAME_CLIENT, application),
    )
    db.execute(
        "SELECT mtmf.external_subject_identity_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), steward_subject, steward),
    )
    db.execute(
        "SELECT mtmf.external_subject_identity_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), non_steward_subject, non_steward),
    )
    return {
        "tenant": tenant,
        "other_tenant": other_tenant,
        "steward": steward,
        "non_steward": non_steward,
        "target": target,
        "group": group,
        "application": application,
    }


class _LiveServer:
    def __init__(self, app: Any, *, port: int) -> None:
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


def _live_app() -> Any:
    if os.environ.get("SSL_CERT_FILE", "").strip() == "":
        os.environ["SSL_CERT_FILE"] = _ca_file()
    spi = PostgresMtmfSpi(PostgresConfig.from_env(PostgresRole.RUNTIME))
    settings = ServiceSettings(evaluation_timeout_seconds=30)
    dependencies = build_dependencies(
        spi=spi,
        issuer_config=_issuer_config(),
        settings=settings,
        initialization_complete=lambda: True,
        require_initialization=False,
    )
    return create_app(
        settings=settings,
        authorization_service=dependencies.authorization_service,
        management_membership_service=dependencies.management_membership_service,
        readiness=StaticReadiness(True),
        rate_limiter=TokenBucketRateLimiter(per_minute=100000, burst=100000),
        admission=dependencies.admission,
        telemetry=dependencies.telemetry,
    )


@pytest.fixture(scope="module")
def live_server() -> Any:
    with _LiveServer(_live_app(), port=PORT):
        yield


def _post(
    *, service: str, user: str, ids: dict[str, str], group: str | None = None
) -> httpx.Response:
    body = {
        "tenant_id": ids["tenant"],
        "identity_id": ids["target"],
        "group_id": group or ids["group"],
    }
    return httpx.post(
        f"{BASE_URL}{ROUTE}",
        json=body,
        headers={
            "Authorization": f"Bearer {service}",
            "X-MTMF-User-Authorization": f"Bearer {user}",
        },
        timeout=30,
    )


def _membership_count(db: psycopg.Connection, ids: dict[str, str]) -> int:
    return int(
        db.execute(
            "SELECT count(*) FROM mtmf.identity_group_membership "
            "WHERE identity_id = %s AND group_id = %s",
            (ids["target"], ids["group"]),
        ).fetchone()[0]
    )


def _audit_count(db: psycopg.Connection) -> int:
    return int(db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0])


def test_h01_h02_live_created_then_authorized_no_op(
    db: psycopg.Connection, live_server: Any
) -> None:
    ids = _seed(
        db,
        steward_subject=_subject(_user_token(STEWARD_USER)),
        non_steward_subject=_subject(_user_token(NON_STEWARD_USER)),
    )
    created = _post(service=_service_token(), user=_user_token(STEWARD_USER), ids=ids)
    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store"
    assert created.json() == {
        "tenant_id": ids["tenant"],
        "identity_id": ids["target"],
        "group_id": ids["group"],
        "created": True,
    }
    assert _membership_count(db, ids) == 1
    assert _audit_count(db) == 1
    audit = db.execute(
        "SELECT actor_identity_id, action_urn, target_kind, target_id, "
        "subject_identity_id, outcome FROM mtmf.security_mutation_audit"
    ).fetchone()
    assert str(audit[0]) == ids["steward"]
    assert audit[1] == "urn:mtmf:iam:actions:system:identity-group-membership:add-object"
    assert audit[2] == "identity_group_membership"
    assert str(audit[3]) == ids["group"]
    assert str(audit[4]) == ids["target"]
    assert audit[5] == "CREATED"

    repeated = _post(service=_service_token(), user=_user_token(STEWARD_USER), ids=ids)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["created"] is False
    assert _membership_count(db, ids) == 1
    assert _audit_count(db) == 1


def test_h03_non_steward_actor_is_opaque_forbidden(
    db: psycopg.Connection, live_server: Any
) -> None:
    ids = _seed(
        db,
        steward_subject=_subject(_user_token(STEWARD_USER)),
        non_steward_subject=_subject(_user_token(NON_STEWARD_USER)),
    )
    response = _post(service=_service_token(), user=_user_token(NON_STEWARD_USER), ids=ids)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert _membership_count(db, ids) == 0
    assert _audit_count(db) == 0


def test_h04_cross_tenant_target_is_denied_without_disclosure(
    db: psycopg.Connection, live_server: Any
) -> None:
    ids = _seed(
        db,
        steward_subject=_subject(_user_token(STEWARD_USER)),
        non_steward_subject=_subject(_user_token(NON_STEWARD_USER)),
    )
    # A Group bound to a different Tenant: the lock helper rejects it opaquely.
    other_group = _uuid()
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s,%s,'O',2)",
        (other_group, ids["other_tenant"]),
    )
    db.execute(
        "INSERT INTO mtmf.group_tenant_membership VALUES (%s,%s)",
        (other_group, ids["other_tenant"]),
    )
    response = _post(
        service=_service_token(), user=_user_token(STEWARD_USER), ids=ids, group=other_group
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert _audit_count(db) == 0


def test_h05_invalid_or_wrong_slot_tokens_never_succeed(
    db: psycopg.Connection, live_server: Any
) -> None:
    ids = _seed(
        db,
        steward_subject=_subject(_user_token(STEWARD_USER)),
        non_steward_subject=_subject(_user_token(NON_STEWARD_USER)),
    )
    body = {"tenant_id": ids["tenant"], "identity_id": ids["target"], "group_id": ids["group"]}
    missing_user = httpx.post(
        f"{BASE_URL}{ROUTE}",
        json=body,
        headers={"Authorization": f"Bearer {_service_token()}"},
        timeout=30,
    )
    assert missing_user.status_code in (401, 403), missing_user.text
    service_as_user = httpx.post(
        f"{BASE_URL}{ROUTE}",
        json=body,
        headers={
            "Authorization": f"Bearer {_service_token()}",
            "X-MTMF-User-Authorization": f"Bearer {_service_token()}",
        },
        timeout=30,
    )
    assert service_as_user.status_code in (401, 403), service_as_user.text
    assert _membership_count(db, ids) == 0
    assert _audit_count(db) == 0
