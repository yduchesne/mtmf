"""Authenticated batch transport tests (CL-U14..CL-U26, CL-U40, CL-U41, CL-U42)."""

from __future__ import annotations

import json
from collections.abc import Callable
from uuid import UUID

import httpx
import pytest
from client_helpers import (
    ACTION_ALLOW,
    ACTION_DENY,
    APP_ID,
    ORGANIZATION_ID,
    OTHER_TENANT_ID,
    SERVICE_TOKEN,
    USER_TOKEN,
    FakeServer,
    StaticSecret,
    build_client,
    conforming_allow,
    conforming_by_request_id,
    error_envelope,
    json_response,
    make_config,
    make_context,
    make_request,
    make_response,
    response_body,
)

from mtmf_api import ERROR_MESSAGES, ActionDecision, ApiErrorCode, AuthorizationBatchResponse
from mtmf_api.authorization import (
    AuthorizationBatchRequest,
    AuthorizationEffect,
    DecisionReason,
)
from mtmf_api.json_codec import serialize_request
from mtmf_client import (
    ActorContextError,
    AuthorizationDenied,
    ClientAuthenticationError,
    ClientClosedError,
    DependencyUnavailableError,
    MtmfClientError,
    RemoteAuthenticationError,
    RemoteEligibilityError,
    RemoteProtocolError,
    is_allowed,
)


def test_cl_u14_exact_headers_and_no_credentials_in_body() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    request = make_request()
    try:
        client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    headers = server.last_evaluate.headers
    assert headers["authorization"] == f"Bearer {SERVICE_TOKEN}"
    assert headers["x-mtmf-user-authorization"] == f"Bearer {USER_TOKEN}"
    assert headers["content-type"] == "application/json"
    assert headers["accept"] == "application/json"
    body = server.last_evaluate.content.decode("utf-8")
    assert body == serialize_request(request)
    assert USER_TOKEN not in body
    assert SERVICE_TOKEN not in body
    assert str(APP_ID) not in body


@pytest.mark.parametrize(
    ("token", "context"),
    [
        ("   ", None),
        ("", None),
    ],
)
def test_cl_u15_missing_user_token_is_rejected_before_post(token: str, context: object) -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ActorContextError):
            client.evaluate(
                make_request(),
                user_access_token=token,
                context=make_context(),
            )
    finally:
        client.close()
    assert server.evaluate_calls == 0
    assert server.token_calls == 0


def test_cl_u15_wrong_context_and_tenant_are_rejected_before_post() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ActorContextError):
            client.evaluate(
                make_request(),
                user_access_token=USER_TOKEN,
                context=make_context(application_id=UUID("99999999-9999-4999-8999-999999999999")),
            )
        with pytest.raises(ActorContextError):
            client.evaluate(
                make_request(tenant_id=OTHER_TENANT_ID),
                user_access_token=USER_TOKEN,
                context=make_context(),
            )
        with pytest.raises(ActorContextError):
            client.evaluate(
                make_request(organization_id=ORGANIZATION_ID),
                user_access_token=USER_TOKEN,
                context=make_context(),
            )
        with pytest.raises(ActorContextError):
            client.evaluate(
                make_request(),
                user_access_token=USER_TOKEN,
                context=object(),  # type: ignore[arg-type]
            )
        with pytest.raises(ActorContextError):
            client.evaluate(
                object(),  # type: ignore[arg-type]
                user_access_token=USER_TOKEN,
                context=make_context(),
            )
    finally:
        client.close()
    assert server.evaluate_calls == 0


def test_cl_u16_exact_json_preserves_order_and_duplicates() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    request = make_request(
        ("first", ACTION_ALLOW, None),
        ("second", ACTION_ALLOW, None),
        ("third", ACTION_DENY, None),
    )
    try:
        client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    parsed = json.loads(server.last_evaluate.content.decode("utf-8"))
    assert [item["request_id"] for item in parsed["actions"]] == ["first", "second", "third"]
    assert parsed["actions"][0] == parsed["actions"][1] | {"request_id": "first"}


def test_cl_u16_hundred_action_bound_is_preserved() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    request = make_request(
        *[(f"req-{index}", ACTION_ALLOW, None) for index in range(100)],
    )
    try:
        client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    parsed = json.loads(server.last_evaluate.content.decode("utf-8"))
    assert len(parsed["actions"]) == 100
    assert [item["request_id"] for item in parsed["actions"]] == [
        f"req-{index}" for index in range(100)
    ]


def test_cl_u17_mixed_allow_deny_creates_one_snapshot() -> None:
    server = FakeServer(
        evaluate_response=conforming_by_request_id(
            {
                "allow": (AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
                "deny": (AuthorizationEffect.DENY, DecisionReason.NO_PERMISSION),
            }
        )
    )
    client, _, _ = build_client(server)
    request = make_request(
        ("allow", ACTION_ALLOW, None),
        ("deny", ACTION_DENY, None),
    )
    try:
        snapshot = client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert snapshot.decision_count == 2
    assert is_allowed(snapshot, context=make_context(), request_id="allow") is True
    assert is_allowed(snapshot, context=make_context(), request_id="deny") is False


def _respond_with(
    request: AuthorizationBatchRequest, response: AuthorizationBatchResponse
) -> object:
    return lambda _: json_response(response_body(response))


def test_cl_u18_reordered_decisions_are_rejected() -> None:
    request = make_request(("a", ACTION_ALLOW, None), ("b", ACTION_DENY, None))
    good = make_response(request)
    reordered = AuthorizationBatchResponse(
        tenant_id=good.tenant_id,
        organization_id=good.organization_id,
        issued_at=good.issued_at,
        expires_at=good.expires_at,
        decisions=tuple(reversed(good.decisions)),
    )
    server = FakeServer(evaluate_response=_respond_with(request, reordered))
    client, _, _ = build_client(server)
    try:
        with pytest.raises(RemoteProtocolError):
            client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.evaluate_calls == 1


def test_cl_u18_omitted_or_added_decisions_are_rejected() -> None:
    request = make_request(("a", ACTION_ALLOW, None), ("b", ACTION_DENY, None))
    good = make_response(request)
    omitted = AuthorizationBatchResponse(
        tenant_id=good.tenant_id,
        organization_id=good.organization_id,
        issued_at=good.issued_at,
        expires_at=good.expires_at,
        decisions=good.decisions[:-1],
    )
    added = AuthorizationBatchResponse(
        tenant_id=good.tenant_id,
        organization_id=good.organization_id,
        issued_at=good.issued_at,
        expires_at=good.expires_at,
        decisions=(
            *good.decisions,
            ActionDecision(
                request_id="extra",
                effect=AuthorizationEffect.ALLOW,
                reason=DecisionReason.PERMITTED,
            ),
        ),
    )
    for response in (omitted, added):
        server = FakeServer(evaluate_response=_respond_with(request, response))
        client, _, _ = build_client(server)
        try:
            with pytest.raises(RemoteProtocolError):
                client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
        finally:
            client.close()


def test_cl_u19_tenant_and_organization_mismatch_are_rejected() -> None:
    request = make_request()
    wrong_tenant = make_response(request, tenant_id=OTHER_TENANT_ID)
    server = FakeServer(evaluate_response=_respond_with(request, wrong_tenant))
    client, _, _ = build_client(server)
    try:
        with pytest.raises(RemoteProtocolError):
            client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()

    request_org = make_request(organization_id=ORGANIZATION_ID)
    good_org = make_response(request_org)
    wrong_org = AuthorizationBatchResponse(
        tenant_id=good_org.tenant_id,
        organization_id=None,
        issued_at=good_org.issued_at,
        expires_at=good_org.expires_at,
        decisions=good_org.decisions,
    )
    server = FakeServer(evaluate_response=_respond_with(request_org, wrong_org))
    client, _, _ = build_client(server)
    try:
        with pytest.raises(RemoteProtocolError):
            client.evaluate(
                request_org,
                user_access_token=USER_TOKEN,
                context=make_context(organization_id=ORGANIZATION_ID),
            )
    finally:
        client.close()


def test_cl_u20_malformed_duplicate_and_unknown_field_json_are_rejected() -> None:
    request = make_request()
    valid = response_body(make_response(request))
    mapping = json.loads(valid)
    unknown = json.dumps({**mapping, "extra": 1})
    duplicate = valid[:-1] + ',"issued_at":"2026-10-13T12:00:00Z"}'
    bodies = ["{", unknown, duplicate, ""]
    for body in bodies:
        server = FakeServer(evaluate_response=lambda _, b=body: json_response(b))
        client, _, _ = build_client(server)
        try:
            with pytest.raises(RemoteProtocolError):
                client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
        finally:
            client.close()


def test_cl_u21_bad_effect_reason_version_timestamp_are_rejected() -> None:
    request = make_request()
    mapping = json.loads(response_body(make_response(request)))

    bad_effect = json.loads(json.dumps(mapping))
    bad_effect["decisions"][0]["effect"] = "MAYBE"
    bad_reason = json.loads(json.dumps(mapping))
    bad_reason["decisions"][0]["reason"] = "NO_PERMISSION"
    bad_version = json.loads(json.dumps(mapping))
    bad_version["schema_version"] = "2"
    bad_timestamp = json.loads(json.dumps(mapping))
    bad_timestamp["issued_at"] = "2026-10-13T12:00:00+00:00"

    for mutated in (bad_effect, bad_reason, bad_version, bad_timestamp):
        body = json.dumps(mutated)
        server = FakeServer(evaluate_response=lambda _, b=body: json_response(b))
        client, _, _ = build_client(server)
        try:
            with pytest.raises(RemoteProtocolError):
                client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
        finally:
            client.close()


_ERROR_CASES = [
    (401, ApiErrorCode.UNAUTHENTICATED, RemoteAuthenticationError),
    (403, ApiErrorCode.UNTRUSTED_ACTOR, RemoteEligibilityError),
    (403, ApiErrorCode.INELIGIBLE_APPLICATION, RemoteEligibilityError),
    (429, ApiErrorCode.RATE_LIMITED, DependencyUnavailableError),
    (503, ApiErrorCode.DEPENDENCY_UNAVAILABLE, DependencyUnavailableError),
    (500, ApiErrorCode.INTERNAL_ERROR, DependencyUnavailableError),
    (400, ApiErrorCode.INVALID_REQUEST, RemoteProtocolError),
    (413, ApiErrorCode.REQUEST_TOO_LARGE, RemoteProtocolError),
    (415, ApiErrorCode.UNSUPPORTED_MEDIA_TYPE, RemoteProtocolError),
]


@pytest.mark.parametrize(("status", "code", "expected"), _ERROR_CASES)
def test_cl_u22_error_envelopes_map_to_typed_failures(
    status: int,
    code: ApiErrorCode,
    expected: type[Exception],
) -> None:
    body = error_envelope(code.value, ERROR_MESSAGES[code])
    server = FakeServer(
        evaluate_response=lambda _: json_response(body, status_code=status),
    )
    client, _, _ = build_client(server)
    try:
        with pytest.raises(expected):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.evaluate_calls == 1


@pytest.mark.parametrize(
    "response",
    [
        lambda _: json_response("{not json", status_code=401),
        lambda _: json_response("{}", status_code=403),
        lambda _: json_response("", status_code=503),
        lambda _: json_response("{}", status_code=500, content_type="text/html"),
    ],
)
def test_cl_u23_malformed_or_unexpected_non_200_is_protocol_failure(
    response: Callable[[httpx.Request], httpx.Response],
) -> None:
    server = FakeServer(evaluate_response=response)
    client, _, _ = build_client(server)
    try:
        with pytest.raises(RemoteProtocolError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()


@pytest.mark.parametrize(
    "response",
    [
        lambda _: json_response(
            error_envelope(
                ApiErrorCode.UNAUTHENTICATED.value, ERROR_MESSAGES[ApiErrorCode.UNAUTHENTICATED]
            ),
            status_code=401,
        ),
        lambda _: json_response(
            error_envelope(
                ApiErrorCode.UNTRUSTED_ACTOR.value, ERROR_MESSAGES[ApiErrorCode.UNTRUSTED_ACTOR]
            ),
            status_code=403,
        ),
        lambda _: json_response("{}", status_code=503),
        lambda _: (_ for _ in ()).throw(httpx.ReadTimeout("simulated")),
    ],
)
def test_cl_u25_no_authorization_retry_for_ambiguous_failures(
    response: Callable[[httpx.Request], httpx.Response],
) -> None:
    server = FakeServer(evaluate_response=response)
    client, _, _ = build_client(server)
    try:
        with pytest.raises(MtmfClientError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.evaluate_calls == 1
    assert server.token_calls == 1


def test_cl_u41_oversized_response_is_rejected() -> None:
    request = make_request()
    huge = response_body(make_response(request)) + ("x" * 5000)
    server = FakeServer(evaluate_response=lambda _: json_response(huge))
    client, _, _ = build_client(server, config=make_config(max_response_bytes=256))
    try:
        with pytest.raises(RemoteProtocolError):
            client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()


def test_cl_u41_wrong_content_type_is_rejected() -> None:
    request = make_request()
    server = FakeServer(
        evaluate_response=lambda _: json_response(
            response_body(make_response(request)),
            content_type="text/plain",
        )
    )
    client, _, _ = build_client(server)
    try:
        with pytest.raises(RemoteProtocolError):
            client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()


def test_cl_u41_redirect_is_not_followed() -> None:
    server = FakeServer(
        evaluate_response=lambda _: httpx.Response(
            status_code=302,
            headers={"location": "https://attacker.example/collect"},
        )
    )
    client, _, _ = build_client(server)
    try:
        with pytest.raises(RemoteProtocolError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.evaluate_calls == 1
    assert server.token_calls == 1


def test_cl_u42_close_and_context_manager_lifecycle() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    with build_client(server)[0] as client:
        assert client.closed is False
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    assert client.closed is True
    with pytest.raises(ClientClosedError):
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    with pytest.raises(ClientClosedError):
        client.is_allowed(None, context=make_context())
    client.close()  # idempotent


def test_cl_u40_tokens_and_secrets_are_redacted_from_failures() -> None:
    secret = "super-secret-value"
    server = FakeServer(
        evaluate_response=lambda _: json_response(
            error_envelope(
                ApiErrorCode.UNAUTHENTICATED.value,
                ERROR_MESSAGES[ApiErrorCode.UNAUTHENTICATED],
            ),
            status_code=401,
        ),
    )
    config = make_config(secret_provider=StaticSecret(secret))
    client, _, _ = build_client(server, config=config)
    try:
        with pytest.raises(RemoteAuthenticationError) as excinfo:
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    message = f"{excinfo.value!s} {excinfo.value!r}"
    assert secret not in message
    assert USER_TOKEN not in message
    assert SERVICE_TOKEN not in message
    assert secret not in repr(config)


def test_cl_u42_token_failure_is_redacted() -> None:
    secret = "another-secret-value"
    server = FakeServer(
        token_response=lambda _: json_response("{}", status_code=500),
        evaluate_response=conforming_allow,
    )
    client, _, _ = build_client(server, config=make_config(secret_provider=StaticSecret(secret)))
    try:
        with pytest.raises(ClientAuthenticationError) as excinfo:
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert secret not in f"{excinfo.value!s} {excinfo.value!r}"


def test_module_helpers_default_deny_on_none() -> None:
    context = make_context()
    assert is_allowed(None, context=context) is False
    with pytest.raises(AuthorizationDenied):
        from mtmf_client import require

        require(None, context=context)
