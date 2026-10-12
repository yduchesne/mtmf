"""Live DC07 acceptance: real Keycloak tokens -> shipped composition -> real PostgreSQL.

Opt-in and authoritative only when ``MTMF_PR14_LIVE=1`` and the isolated
Keycloak fixture plus the real PostgreSQL role topology are available. Without
the flag the module is skipped so the deterministic ``--integration`` gate does
not require live Keycloak. With the flag set there are no skips. Tokens,
secrets and admin credentials are never printed or persisted.
"""

from __future__ import annotations

import importlib.util
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest

from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.authentication.contracts import AuthenticationError, AuthenticationFailure
from mtmf_core.domain.identity import DomainId
from mtmf_core.persistence.postgres import PostgresMtmfSpi
from mtmf_service.authentication.composition import build_actor_context_service
from mtmf_service.authentication.config import IssuerConfig

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR14_LIVE") != "1",
    reason="live Keycloak+PostgreSQL acceptance is opt-in (set MTMF_PR14_LIVE=1)",
)

REALM = "mtmf-pr14-dev"
SHARED_AUDIENCE = "mtmf-same-client-api"
SAME_CLIENT = "mtmf-evidence-same-client"
SAME_SECRET = "mtmf-evidence-same-client-dev-secret"
OTHER_CLIENT = "mtmf-evidence-service"
OTHER_SECRET = "mtmf-evidence-service-dev-secret"
USER = "mtmf-user-bob"

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


class Admin:
    """Minimal Admin REST client for the isolated live fixture."""

    def __init__(self) -> None:
        self.base = _env("MTMF_PR14_KC_BASE")
        self.ctx = ssl.create_default_context(cafile=os.environ.get("MTMF_PR14_KC_CA_FILE", ""))
        self.headers = {"Content-Type": "application/json"}
        self._opener = urllib.request.build_opener()

    def _open(self, request: urllib.request.Request) -> Any:
        if urllib.parse.urlparse(request.full_url).scheme not in ("http", "https"):
            raise RuntimeError("unsupported live fixture URL scheme")
        return self._opener.open(request, context=self.ctx)

    def _token(self) -> str:
        data = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": _env("MTMF_PR14_KC_ADMIN_USERNAME"),
                "password": _env("MTMF_PR14_KC_ADMIN_PASSWORD"),
            }
        ).encode()
        with self._open(
            urllib.request.Request(
                f"{self.base}/realms/master/protocol/openid-connect/token", data=data
            )
        ) as response:
            return json.loads(response.read())["access_token"]

    def request(self, method: str, path: str, body: Any | None = None) -> Any:
        headers = {**self.headers, "Authorization": f"Bearer {self._token()}"}
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=None if body is None else json.dumps(body).encode(),
            method=method,
            headers=headers,
        )
        with self._open(request) as response:
            payload = response.read()
        return json.loads(payload) if payload else None

    def client(self) -> dict[str, Any]:
        rows = self.request("GET", f"/admin/realms/{REALM}/clients?clientId={SAME_CLIENT}")
        return rows[0]

    def add_mapper(self, uuid_value: str, claim: str) -> None:
        self.request(
            "POST",
            f"/admin/realms/{REALM}/clients/{uuid_value}/protocol-mappers/models",
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

    def remove_mapper(self, uuid_value: str, claim: str) -> None:
        for mapper in (
            self.request(
                "GET", f"/admin/realms/{REALM}/clients/{uuid_value}/protocol-mappers/models"
            )
            or []
        ):
            if mapper["name"] == f"a3-spoof-{claim}":
                self.request(
                    "DELETE",
                    f"/admin/realms/{REALM}/clients/{uuid_value}/protocol-mappers/models/{mapper['id']}",
                )


def _seed(db: psycopg.Connection, subject: str) -> dict[str, str]:
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
        (_uuid(), _issuer_str(), SAME_CLIENT, application_id),
    )
    db.execute(
        "SELECT mtmf.external_subject_identity_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), subject, identity_id),
    )
    return {
        "principal_id": principal_id,
        "identity_id": identity_id,
        "tenant_id": tenant_id,
        "application_id": application_id,
    }


def _issuer() -> ev.Issuer:
    return ev.Issuer(
        base=_env("MTMF_PR14_KC_BASE"),
        realm=REALM,
        ca_file=os.environ.get("MTMF_PR14_KC_CA_FILE", ""),
    )


def _service_token() -> dict[str, Any]:
    return ev.client_credentials_token(_issuer(), SAME_CLIENT, SAME_SECRET)


def _user_token() -> dict[str, Any]:
    return ev.authorization_code_token(
        _issuer(),
        SAME_CLIENT,
        SAME_SECRET,
        USER,
        _env("MTMF_PR14_KC_USER_PASSWORD"),
        "http://127.0.0.1:28400/callback",
        28400,
    )


def _config(
    *, service_audience: str = SHARED_AUDIENCE, user_audience: str = SHARED_AUDIENCE
) -> IssuerConfig:
    base = _env("MTMF_PR14_KC_BASE")
    issuer = f"{base}/realms/{REALM}"
    return IssuerConfig(
        issuer=issuer,
        service_audience=service_audience,
        user_audience=user_audience,
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
        expected_manifest_path="dev/keycloak/expected-config-manifest.json",
        admin_base_url=base,
        admin_realm=REALM,
        admin_username=_env("MTMF_PR14_KC_ADMIN_USERNAME"),
        admin_password=_env("MTMF_PR14_KC_ADMIN_PASSWORD"),
        allow_shared_audience=(service_audience == user_audience),
    )


def _compose(spi: PostgresMtmfSpi, *args: Any, **kwargs: Any) -> AuthenticatedActorContextService:
    return build_actor_context_service(spi, _config(*args, **kwargs))


def _resolve(
    service: AuthenticatedActorContextService,
    service_token: dict[str, Any],
    user_token: dict[str, Any],
    tenant_id: str,
) -> Any:
    return service.resolve(
        service_token=service_token["access_token"],
        user_token=user_token["access_token"],
        tenant_id=DomainId.from_str(tenant_id),
    )


def test_dc07_v01_positive_real_tokens_and_postgres(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    service_token, user_token = _service_token(), _user_token()
    subject = ev.decode_unverified(user_token["access_token"])[1]["sub"]
    ids = _seed(db, subject)
    context = _resolve(_compose(postgres_spi), service_token, user_token, ids["tenant_id"])
    assert str(context.application_id) == ids["application_id"]
    assert str(context.identity_id) == ids["identity_id"]
    assert str(context.principal_id) == ids["principal_id"]
    assert str(context.tenant_id) == ids["tenant_id"]


def test_dc07_v04_wrong_slot_tokens_rejected(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    service_token, user_token = _service_token(), _user_token()
    subject = ev.decode_unverified(user_token["access_token"])[1]["sub"]
    ids = _seed(db, subject)
    composite = _compose(postgres_spi)
    with pytest.raises(AuthenticationError) as service_in_user:
        _resolve(composite, service_token, service_token, ids["tenant_id"])
    assert service_in_user.value.failure is AuthenticationFailure.WRONG_TOKEN_CLASS
    with pytest.raises(AuthenticationError) as user_in_service:
        _resolve(composite, user_token, user_token, ids["tenant_id"])
    assert user_in_service.value.failure is AuthenticationFailure.WRONG_TOKEN_CLASS


def test_dc07_v05_cross_client_rejected(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    other_service = ev.client_credentials_token(_issuer(), OTHER_CLIENT, OTHER_SECRET)
    user_token = _user_token()
    subject = ev.decode_unverified(user_token["access_token"])[1]["sub"]
    ids = _seed(db, subject)
    composite = _compose(
        postgres_spi, service_audience="mtmf-service-api", user_audience=SHARED_AUDIENCE
    )
    with pytest.raises(AuthenticationError) as exc:
        _resolve(composite, other_service, user_token, ids["tenant_id"])
    assert exc.value.failure is AuthenticationFailure.CROSS_CLIENT


def test_dc07_v07_missing_service_binding_rejected(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    service_token, user_token = _service_token(), _user_token()
    subject = ev.decode_unverified(user_token["access_token"])[1]["sub"]
    ids = _seed(db, subject)
    db.execute(
        "UPDATE mtmf.service_credential_application SET lifecycle = 2 WHERE client_id = %s",
        (SAME_CLIENT,),
    )
    with pytest.raises(AuthenticationError) as exc:
        _resolve(_compose(postgres_spi), service_token, user_token, ids["tenant_id"])
    assert exc.value.failure is AuthenticationFailure.UNKNOWN_APPLICATION


def test_dc07_v08_missing_subject_binding_rejected(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    service_token, user_token = _service_token(), _user_token()
    subject = ev.decode_unverified(user_token["access_token"])[1]["sub"]
    ids = _seed(db, subject)
    db.execute(
        "UPDATE mtmf.external_subject_identity SET lifecycle = 2 WHERE subject = %s", (subject,)
    )
    with pytest.raises(AuthenticationError) as exc:
        _resolve(_compose(postgres_spi), service_token, user_token, ids["tenant_id"])
    assert exc.value.failure is AuthenticationFailure.UNKNOWN_SUBJECT


def test_dc07_v15_mapper_drift_blocks_and_restores(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    service_token, user_token = _service_token(), _user_token()
    subject = ev.decode_unverified(user_token["access_token"])[1]["sub"]
    ids = _seed(db, subject)
    composite = _compose(postgres_spi)
    _resolve(composite, service_token, user_token, ids["tenant_id"])  # positive
    admin = Admin()
    client = admin.client()
    admin.add_mapper(client["id"], "client_id")
    try:
        with pytest.raises(AuthenticationError) as exc:
            _resolve(composite, service_token, user_token, ids["tenant_id"])
        assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT
    finally:
        admin.remove_mapper(client["id"], "client_id")
    _resolve(composite, service_token, user_token, ids["tenant_id"])  # restored
