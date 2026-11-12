"""Live PR 23 pre-Tenant subject acceptance with real Keycloak tokens.

Opt-in and authoritative only when ``MTMF_PR14_LIVE=1`` and the isolated
Keycloak fixture plus the real PostgreSQL role topology are available. Without
the flag this module is skipped so the deterministic ``--integration`` gate
does not require live Keycloak. With the flag set there are no skips.

The test constructs the pre-Tenant verifier from the SAME approved
``IssuerConfig``/attestor/verifier components used by the PR 14 actor-context
composition. It targets the isolated Keycloak fixture configured with the
approved ``mtmf-dev`` realm, which reproduces the committed
``expected-realm-security.json`` / ``expected-client-policy.json`` trust
configuration. It never fabricates a ``VerifiedAccessToken`` and never uses
``decode_unverified`` to authenticate the application; the unverified decode is
used only to seed a privileged fixture binding for L02.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import psycopg
import pytest

from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.application.pre_tenant_subject import PreTenantSubjectVerificationService
from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    IssuerProfile,
)
from mtmf_core.domain.identity import DomainId
from mtmf_core.persistence.postgres import PostgresMtmfSpi
from mtmf_service.authentication.attestation import (
    BaselineConfigurationAttestor,
    HttpAdminRestReader,
)
from mtmf_service.authentication.composition import build_actor_context_service
from mtmf_service.authentication.config import IssuerConfig
from mtmf_service.authentication.jwt_verifier import JwksKeyProvider, PyJWTTokenVerifier

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR14_LIVE") != "1",
    reason="live Keycloak+PostgreSQL acceptance is opt-in (set MTMF_PR14_LIVE=1)",
)

REALM = os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-dev")
SHARED_AUDIENCE = "mtmf-same-client-api"
SAME_CLIENT = "mtmf-evidence-same-client"
SAME_SECRET = "mtmf-evidence-same-client-dev-secret"
OTHER_CLIENT = "mtmf-evidence-service"
OTHER_SECRET = "mtmf-evidence-service-dev-secret"
USER = "mtmf-user-bob"

_EVIDENCE = Path(__file__).resolve().parents[3] / "scripts" / "pr14-keycloak-evidence.py"
_spec = importlib.util.spec_from_file_location("pr23_keycloak_evidence", _EVIDENCE)
assert _spec is not None and _spec.loader is not None
ev = importlib.util.module_from_spec(_spec)
sys.modules["pr23_keycloak_evidence"] = ev
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


def _issuer() -> Any:
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
        expected_manifest_path="dev/keycloak/expected-realm-security.json",
        admin_base_url=base,
        admin_realm=REALM,
        attestation_client_id="mtmf-attestation-reader",
        attestation_client_secret="mtmf-attestation-reader-dev-secret",
        allow_shared_audience=(service_audience == user_audience),
    )


def _pre_tenant(spi: PostgresMtmfSpi, config: IssuerConfig) -> PreTenantSubjectVerificationService:
    """Construct the PR 23 verifier from the approved PR 14 components."""
    algorithms = frozenset({config.algorithm})
    service_profile = IssuerProfile(
        issuer=config.issuer,
        audience=config.service_audience,
        jwks_uri=config.jwks_uri,
        algorithms=algorithms,
    )
    user_profile = IssuerProfile(
        issuer=config.issuer,
        audience=config.user_audience,
        jwks_uri=config.jwks_uri,
        algorithms=algorithms,
    )
    key_provider = JwksKeyProvider(
        config.jwks_uri,
        timeout=config.transport_timeout_seconds,
        max_bytes=config.max_jwks_bytes,
        cache_seconds=config.jwks_cache_seconds,
        min_refresh_seconds=config.jwks_min_refresh_seconds,
    )
    verifier = PyJWTTokenVerifier(key_provider, max_token_bytes=config.max_token_bytes)
    reader = HttpAdminRestReader(
        config.admin_base_url,
        config.admin_realm,
        config.attestation_client_id,
        config.attestation_client_secret,
        timeout=config.transport_timeout_seconds,
        max_bytes=config.max_jwks_bytes,
    )
    attestor = BaselineConfigurationAttestor(
        reader,
        config.admin_realm,
        config.expected_manifest_path,
        config.expected_client_policy_path,
    )
    return PreTenantSubjectVerificationService(
        spi=spi,
        attestor=attestor,
        service_verifier=verifier,
        service_profile=service_profile,
        user_verifier=verifier,
        user_profile=user_profile,
    )


def _bootstrap_root(db: psycopg.Connection) -> None:
    db.execute(
        "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
        (_uuid(), _uuid(), _uuid()),
    )


def _seed_application_owner(db: psycopg.Connection) -> dict[str, str]:
    principal, identity, application = _uuid(), _uuid(), _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (principal,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', 2, 2)",
        (identity, principal),
    )
    added = db.execute(
        "SELECT mtmf.application_add(%s, %s, 'Application', %s, 1::smallint, '{}'::jsonb)",
        (application, f"app-{_uuid()[:8]}", identity),
    ).fetchone()[0]
    assert added is True
    db.execute(
        "SELECT mtmf.service_credential_application_add(%s, %s, %s, %s, 1::smallint, now())",
        (_uuid(), _issuer_str(), SAME_CLIENT, application),
    )
    return {"principal": principal, "identity": identity, "application": application}


def _bind_subject(db: psycopg.Connection, subject: str, identity: str) -> None:
    db.execute(
        "SELECT mtmf.external_subject_identity_add(%s, %s, %s, %s, 1::smallint, now())",
        (_uuid(), _issuer_str(), subject, identity),
    )


def _verify(
    service: PreTenantSubjectVerificationService,
    service_token: dict[str, Any],
    user_token: dict[str, Any],
):
    return service.verify(
        service_token=service_token["access_token"],
        user_token=user_token["access_token"],
    )


def test_pr23_l01_valid_tokens_without_identity_binding_or_tenant(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    _bootstrap_root(db)
    seeded = _seed_application_owner(db)
    service_token, user_token = _service_token(), _user_token()
    result = _verify(_pre_tenant(postgres_spi, _config()), service_token, user_token)
    assert str(result.application_id) == seeded["application"]
    assert result.service_credential.client_id == SAME_CLIENT
    assert result.external_subject.subject
    assert result.existing_identity_id is None
    assert result.existing_principal_id is None
    assert result.verified_at.tzinfo is not None
    assert result.user_token_expires_at.tzinfo is not None
    # No Tenant/Identity/Principal side effects from a read-only verification.
    assert db.execute("SELECT count(*) FROM mtmf.tenant").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.external_subject_identity").fetchone()[0] == 0


def test_pr23_l02_existing_global_binding_returns_exact_identity_without_tenant(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    _bootstrap_root(db)
    seeded = _seed_application_owner(db)
    user_token = _user_token()
    # Privileged fixture seeding only; never an authentication source.
    subject = ev.decode_unverified(user_token["access_token"])[1]["sub"]
    _bind_subject(db, subject, seeded["identity"])
    result = _verify(_pre_tenant(postgres_spi, _config()), _service_token(), user_token)
    assert str(result.existing_identity_id) == seeded["identity"]
    assert str(result.existing_principal_id) == seeded["principal"]
    # Still no Tenant or membership requirement.
    assert db.execute("SELECT count(*) FROM mtmf.tenant").fetchone()[0] == 1


def test_pr23_l03_wrong_classes_and_cross_client_reject_without_mutation(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    _bootstrap_root(db)
    _seed_application_owner(db)
    service_token, user_token = _service_token(), _user_token()
    verifier = _pre_tenant(postgres_spi, _config())

    with pytest.raises(AuthenticationError) as wrong_service:
        verifier.verify(
            service_token=user_token["access_token"], user_token=user_token["access_token"]
        )
    assert wrong_service.value.failure is AuthenticationFailure.WRONG_TOKEN_CLASS
    with pytest.raises(AuthenticationError) as wrong_user:
        verifier.verify(
            service_token=service_token["access_token"], user_token=service_token["access_token"]
        )
    assert wrong_user.value.failure is AuthenticationFailure.WRONG_TOKEN_CLASS

    other_service = ev.client_credentials_token(_issuer(), OTHER_CLIENT, OTHER_SECRET)
    cross = _pre_tenant(
        postgres_spi,
        _config(service_audience="mtmf-service-api", user_audience=SHARED_AUDIENCE),
    )
    with pytest.raises(AuthenticationError) as cross_client:
        _verify(cross, other_service, user_token)
    assert cross_client.value.failure is AuthenticationFailure.CROSS_CLIENT

    assert db.execute("SELECT count(*) FROM mtmf.tenant").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.external_subject_identity").fetchone()[0] == 0


def test_pr23_l04_ordinary_actor_resolution_still_requires_a_tenant(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    _bootstrap_root(db)
    seeded = _seed_application_owner(db)
    service_token, user_token = _service_token(), _user_token()
    subject = ev.decode_unverified(user_token["access_token"])[1]["sub"]
    _bind_subject(db, subject, seeded["identity"])
    actor_service: AuthenticatedActorContextService = build_actor_context_service(
        postgres_spi, _config()
    )
    with pytest.raises(AuthenticationError) as exc:
        actor_service.resolve(
            service_token=service_token["access_token"],
            user_token=user_token["access_token"],
            tenant_id=DomainId.generate(),
        )
    assert exc.value.failure is AuthenticationFailure.INELIGIBLE_TENANT
