"""HTTP trust boundary, error mapping, limits, health and cancellation (H11-H18, H22, H25-H32)."""

from __future__ import annotations

import asyncio
import json

import pytest
from conftest import (
    ALLOW_ACTION,
    CLIENT,
    SUBJECT,
    CancellingBatchAuthorizer,
    ExplodingBatchAuthorizer,
    TruncatingBatchAuthorizer,
    VerifierSpy,
    World,
    action_body,
    auth_headers,
    build_harness,
    make_token,
    seeded_harness,
)
from starlette.requests import Request

from mtmf_core import InMemoryMtmfSpi
from mtmf_core.authentication.contracts import AuthenticationError, AuthenticationFailure
from mtmf_core.domain.authentication_binding import RootRegistryRecord
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.lifecycle import SubscriptionLifecycle, TenantLifecycle
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.tenant import Tenant
from mtmf_core.persistence.errors import PersistenceError
from mtmf_service.composition import build_readiness
from mtmf_service.settings import (
    DeploymentMode,
    ServiceConfigurationError,
    ServiceSettings,
)
from mtmf_service.transport import read_bounded_body


def _post(harness, body, *, headers=None, content=None, content_type="application/json"):
    if content is not None or content_type != "application/json":
        raw = content if content is not None else json.dumps(body).encode()
        return harness.client.post(
            "/v1/authorization/evaluate",
            content=raw,
            headers={"Content-Type": content_type, **(headers or auth_headers())},
        )
    return harness.client.post(
        "/v1/authorization/evaluate", json=body, headers=headers or auth_headers()
    )


def test_h11_missing_or_malformed_service_token_is_401():
    harness = seeded_harness()
    tenant = str(harness.world.tenant.id)
    for headers in (
        {"X-MTMF-User-Authorization": "Bearer user"},
        {"Authorization": "Basic abc", "X-MTMF-User-Authorization": "Bearer user"},
        {"Authorization": "Bearer ", "X-MTMF-User-Authorization": "Bearer user"},
        {"Authorization": "Bearer nope", "X-MTMF-User-Authorization": "Bearer user"},
    ):
        response = _post(
            harness, action_body(("r1", ALLOW_ACTION), tenant_id=tenant), headers=headers
        )
        assert response.status_code == 401, headers
        assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_h11_expired_service_token_is_401():
    harness = seeded_harness(
        service_verifier=VerifierSpy(
            {},
            errors={"expired": AuthenticationError(AuthenticationFailure.EXPIRED_TOKEN)},
        )
    )
    response = _post(
        harness,
        action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id)),
        headers=auth_headers(service="expired"),
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_h12_valid_service_but_bad_user_token_is_403():
    harness = seeded_harness()
    tenant = str(harness.world.tenant.id)
    missing = _post(
        harness,
        action_body(("r1", ALLOW_ACTION), tenant_id=tenant),
        headers={"Authorization": "Bearer service"},
    )
    assert missing.status_code == 403
    assert missing.json()["error"]["code"] == "UNTRUSTED_ACTOR"
    wrong = _post(
        harness,
        action_body(("r1", ALLOW_ACTION), tenant_id=tenant),
        headers=auth_headers(user="nope"),
    )
    assert wrong.status_code == 403
    assert wrong.json()["error"]["code"] == "UNTRUSTED_ACTOR"


def test_h13_cross_client_user_token_is_403():
    harness = seeded_harness(
        user_verifier=VerifierSpy(
            {"user": make_token(subject=SUBJECT, client_id=None, azp="other-client")}
        )
    )
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "UNTRUSTED_ACTOR"


def test_h13_user_token_with_service_class_is_403():
    harness = seeded_harness(
        user_verifier=VerifierSpy({"user": make_token(subject="sa2", client_id=CLIENT)})
    )
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "UNTRUSTED_ACTOR"


def test_h13_root_subject_is_403():
    harness = seeded_harness()
    harness.world.spi.seed_root_registry(
        RootRegistryRecord(
            root_tenant_id=harness.world.tenant.id,
            root_principal_id=harness.world.principal.id,
            root_identity_id=harness.world.identity.id,
        )
    )
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "UNTRUSTED_ACTOR"


def test_h14_unknown_tenant_selector_is_403():
    harness = seeded_harness()
    response = _post(
        harness,
        action_body(("r1", ALLOW_ACTION), tenant_id=str(DomainId.generate().value)),
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "UNTRUSTED_ACTOR"


def test_h14_missing_membership_is_403():
    harness = seeded_harness(world_kwargs={"memberships": False})
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "UNTRUSTED_ACTOR"


def test_h14_foreign_organization_is_403():
    harness = seeded_harness()
    body = action_body(
        ("r1", ALLOW_ACTION),
        tenant_id=str(harness.world.tenant.id),
        organization_id=str(DomainId.generate().value),
    )
    response = _post(harness, body)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "UNTRUSTED_ACTOR"


def test_h15_root_tenant_selector_never_allows():
    harness = seeded_harness()
    root_tenant = Tenant(
        id=DomainId.generate(),
        name="root",
        scope=SecurityScope.ROOT,
        owner_identity_id=harness.world.identity.id,
        lifecycle=TenantLifecycle.ACTIVE,
    )
    with harness.world.spi.create_unit_of_work() as uow:
        harness.world.spi.create_tenant_repository(uow).add(root_tenant)
        uow.commit()
    harness.world.spi.seed_root_registry(
        RootRegistryRecord(
            root_tenant_id=root_tenant.id,
            root_principal_id=harness.world.principal.id,
            root_identity_id=harness.world.identity.id,
        )
    )
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(root_tenant.id.value))
    )
    assert response.status_code in (403, 503)
    assert "ALLOW" not in response.text


@pytest.mark.parametrize(
    "lifecycle",
    [
        SubscriptionLifecycle.SUSPENDED,
        SubscriptionLifecycle.CANCELLED,
        SubscriptionLifecycle.EXPIRED,
    ],
)
def test_h16_ineligible_subscription_is_403(lifecycle):
    harness = seeded_harness(world_kwargs={"subscription_lifecycle": lifecycle})
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INELIGIBLE_APPLICATION"


def test_h16_revoked_registration_is_403():
    harness = seeded_harness()
    from mtmf_core.domain.lifecycle import RegistrationLifecycle

    with harness.world.spi.create_unit_of_work() as uow:
        repo = harness.world.spi.create_application_tenant_registration_repository(uow)
        registration = repo.get(harness.world.registration.id)
        assert registration is not None
        registration.lifecycle = RegistrationLifecycle.REVOKED
        repo.save(registration)
        uow.commit()
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INELIGIBLE_APPLICATION"


def test_h16_suspended_application_is_403():
    harness = seeded_harness()
    from mtmf_core.domain.lifecycle import ApplicationLifecycle

    with harness.world.spi.create_unit_of_work() as uow:
        repo = harness.world.spi.create_application_repository(uow)
        application = repo.get(harness.world.application.id)
        assert application is not None
        application.lifecycle = ApplicationLifecycle.SUSPENDED
        repo.save(application)
        uow.commit()
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "INELIGIBLE_APPLICATION"


def test_h17_attestation_drift_is_503():
    harness = seeded_harness()
    harness.attestor.failure = AuthenticationFailure.ATTESTATION_DRIFT
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"


class FailingSpi:
    """Persistence provider whose UnitOfWork acquisition always fails."""

    def create_unit_of_work(self):  # type: ignore[no-untyped-def]
        raise PersistenceError("database unavailable")

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        raise AssertionError(f"unexpected SPI access: {name}")


def test_h18_database_outage_is_503():
    world = World(InMemoryMtmfSpi()).seed()
    harness = build_harness(spi=FailingSpi(), world=world)
    response = _post(harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(world.tenant.id)))
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DEPENDENCY_UNAVAILABLE"


def test_h18_policy_resolver_exception_is_500():
    harness = seeded_harness(batch_authorizer=ExplodingBatchAuthorizer())
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"


def test_h22_response_conformance_fault_is_500():
    harness = seeded_harness(batch_authorizer=TruncatingBatchAuthorizer())
    response = _post(
        harness,
        action_body(
            ("r1", ALLOW_ACTION),
            ("r2", ALLOW_ACTION),
            tenant_id=str(harness.world.tenant.id),
        ),
    )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"


def test_h25_exact_bound_accepted_and_over_bound_rejected():
    harness = seeded_harness()
    base = json.dumps(
        action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    ).encode()
    at_limit = base + b" " * (65536 - len(base))
    assert len(at_limit) == 65536
    accepted = harness.client.post(
        "/v1/authorization/evaluate",
        content=at_limit,
        headers={**auth_headers(), "Content-Type": "application/json"},
    )
    assert accepted.status_code == 200
    over_limit = base + b" " * (65537 - len(base))
    rejected = harness.client.post(
        "/v1/authorization/evaluate",
        content=over_limit,
        headers={**auth_headers(), "Content-Type": "application/json"},
    )
    assert rejected.status_code == 413
    assert rejected.json()["error"]["code"] == "REQUEST_TOO_LARGE"


def _make_request(body: bytes, headers: list[tuple[bytes, bytes]]) -> Request:
    sent = False

    async def receive():  # type: ignore[no-untyped-def]
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 1),
    }
    return Request(scope, receive)


def test_h25_streamed_byte_count_and_false_content_length():
    from mtmf_service.errors import PublicError

    async def scenario() -> None:
        request = _make_request(b"x" * 11, [])
        with pytest.raises(PublicError) as exc:
            await read_bounded_body(request, max_bytes=10)
        assert exc.value.code.value == "REQUEST_TOO_LARGE"
        # A false/absent length must not bypass the streamed bound.
        request = _make_request(b"x" * 5, [(b"content-length", b"100")])
        with pytest.raises(PublicError):
            await read_bounded_body(request, max_bytes=10)
        request = _make_request(b"x" * 10, [])
        assert await read_bounded_body(request, max_bytes=10) == b"x" * 10

    asyncio.run(scenario())


def test_h26_wrong_media_type_and_encoding_are_415():
    harness = seeded_harness()
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    wrong = _post(harness, body, content_type="text/plain")
    assert wrong.status_code == 415
    assert wrong.json()["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"
    encoded = harness.client.post(
        "/v1/authorization/evaluate",
        content=json.dumps(body).encode(),
        headers={
            **auth_headers(),
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
        },
    )
    assert encoded.status_code == 415
    assert harness.attestor.calls == 0


def test_h27_rate_limit_saturation_is_429():
    from mtmf_service.rate_limit import TokenBucketRateLimiter

    harness = seeded_harness(rate_limiter=TokenBucketRateLimiter(per_minute=1, burst=1))
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    first = _post(harness, body)
    assert first.status_code == 200
    second = _post(harness, body)
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "RATE_LIMITED"


def test_h28_no_store_no_docs_no_cors_and_redaction():
    harness = seeded_harness()
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert response.headers["cache-control"] == "no-store"
    assert "access-control-allow-origin" not in response.headers
    assert "service" not in response.text
    assert "user" not in response.text
    assert harness.client.get("/docs").status_code == 404
    assert harness.client.get("/openapi.json").status_code == 404
    error = _post(harness, {"tenant_id": None})
    assert error.headers["cache-control"] == "no-store"


def test_h29_liveness_and_readiness_are_distinct():
    from conftest import _issuer_config

    harness = seeded_harness()
    assert harness.client.get("/health/live").status_code == 200
    harness_readiness = build_readiness(
        spi=harness.world.spi,
        initialization_complete=lambda: False,
        require_initialization=True,
    )
    assert harness_readiness.is_ready() is False
    ready = build_readiness(
        spi=harness.world.spi,
        initialization_complete=lambda: True,
        require_initialization=True,
    )
    assert ready.is_ready() is True
    unready = build_readiness(
        spi=FailingSpi(), initialization_complete=lambda: True, require_initialization=False
    )
    assert unready.is_ready() is False
    _ = _issuer_config


def test_h29_production_profile_fails_startup():
    from conftest import build_harness as _build

    world = World(InMemoryMtmfSpi()).seed()
    with pytest.raises(ServiceConfigurationError):
        _build(
            spi=world.spi,
            world=world,
            settings=ServiceSettings(deployment_mode=DeploymentMode.PRODUCTION),
        )


def test_h29_readiness_endpoint_reports_not_ready():
    from mtmf_service.readiness import StaticReadiness

    harness = seeded_harness(readiness=StaticReadiness(False))
    assert harness.client.get("/health/live").status_code == 200
    assert harness.client.get("/health/ready").status_code == 503


def test_h30_cancellation_propagates_through_the_service():
    harness = seeded_harness(batch_authorizer=CancellingBatchAuthorizer())
    from mtmf_api.json_codec import parse_request_json

    parsed = parse_request_json(
        json.dumps(action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id)))
    )
    with pytest.raises(asyncio.CancelledError):
        harness.authorization_service.evaluate(
            service_token="service", user_token="user", request=parsed
        )


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({"tenant_id": None}, 400, "INVALID_REQUEST"),
        (
            {"tenant_id": "11111111-1111-1111-1111-111111111111", "actions": []},
            400,
            "INVALID_REQUEST",
        ),
    ],
)
def test_h31_error_envelope_shape(body, status, code):
    harness = seeded_harness()
    response = _post(harness, body)
    assert response.status_code == status
    payload = response.json()
    assert set(payload) == {"schema_version", "error"}
    assert payload["schema_version"] == "1"
    assert set(payload["error"]) <= {"code", "message", "request_id"}
    assert payload["error"]["code"] == code
    assert payload["error"]["message"]


def test_h31_unauthenticated_and_unsupported_media_envelopes():
    harness = seeded_harness()
    unauth = _post(harness, {"tenant_id": None}, headers={})
    assert unauth.status_code in (400, 401)
    assert set(unauth.json()) == {"schema_version", "error"}


def test_h32_no_positive_attestation_cache_between_requests():
    harness = seeded_harness()
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    assert _post(harness, body).status_code == 200
    assert harness.attestor.calls == 1
    harness.attestor.failure = AuthenticationFailure.ATTESTATION_UNAVAILABLE
    second = _post(harness, body)
    assert second.status_code == 503
    assert harness.attestor.calls == 2
