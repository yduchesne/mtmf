"""OAuth 2.0 Client Credentials service-token manager tests (CL-U05..CL-U13, CL-U43)."""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qsl

import httpx
import pytest
from client_helpers import (
    SERVICE_TOKEN,
    USER_TOKEN,
    FakeServer,
    build_client,
    conforming_allow,
    json_response,
    make_config,
    make_context,
    make_request,
    token_body,
)

from mtmf_client import ClientAuthenticationError

CLIENT_ID = "mtmf-evidence-same-client"
CLIENT_SECRET = "service-client-secret"


def _form(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode("utf-8")))


def test_cl_u05_first_grant_uses_exact_client_credentials_request() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    try:
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.token_calls == 1
    request = server.last_token
    assert request.method == "POST"
    assert str(request.url) == make_config().token_endpoint
    assert request.headers["content-type"].startswith("application/x-www-form-urlencoded")
    form = _form(request)
    assert form["grant_type"] == "client_credentials"
    assert form["client_id"] == CLIENT_ID
    assert form["client_secret"] == CLIENT_SECRET
    assert "scope" not in form
    assert "audience" not in form
    assert "refresh_token" not in form
    assert "refresh_token" not in request.content.decode()


def test_cl_u06_scope_and_audience_only_when_configured() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    client, _, _ = build_client(
        server,
        config=make_config(scope="mtmf.service", audience="mtmf-service-api"),
    )
    try:
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    form = _form(server.last_token)
    assert form["scope"] == "mtmf.service"
    assert form["audience"] == "mtmf-service-api"


def test_cl_u07_unexpired_token_is_reused() -> None:
    server = FakeServer(evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    try:
        for _ in range(3):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.token_calls == 1
    assert server.evaluate_calls == 3


def test_cl_u08_proactive_renewal_at_threshold_without_refresh_token() -> None:
    counter = {"n": 0}

    def token_handler(_: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        return json_response(token_body(access_token=f"token-{counter['n']}", expires_in=300))

    server = FakeServer(token_response=token_handler, evaluate_response=conforming_allow)
    client, _, clock = build_client(server)
    try:
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
        clock.advance_monotonic(200)
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
        assert server.token_calls == 1
        clock.advance_monotonic(200)  # past 300s lifetime minus 5s leeway
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.token_calls == 2
    assert counter["n"] == 2


def test_cl_u09_concurrent_evaluation_triggers_single_flight_renewal() -> None:
    calls = {"token": 0}
    lock = threading.Lock()

    def token_handler(_: httpx.Request) -> httpx.Response:
        with lock:
            calls["token"] += 1
        time.sleep(0.1)
        return json_response(token_body())

    server = FakeServer(token_response=token_handler, evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [
                pool.submit(
                    client.evaluate,
                    make_request(),
                    user_access_token=USER_TOKEN,
                    context=make_context(),
                )
                for _ in range(8)
            ]
            for future in futures:
                future.result()
    finally:
        client.close()
    assert calls["token"] == 1
    assert server.token_calls == 1
    assert server.evaluate_calls == 8


@pytest.mark.parametrize("status", [500, 429, 503])
def test_cl_u10_token_endpoint_failure_is_typed_and_no_authorization_post(status: int) -> None:
    server = FakeServer(
        token_response=lambda _: json_response("{}", status_code=status),
        evaluate_response=conforming_allow,
    )
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.evaluate_calls == 0


def test_cl_u10_token_endpoint_timeout_is_typed() -> None:
    def boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("simulated token timeout")

    server = FakeServer(token_response=boom, evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.evaluate_calls == 0


@pytest.mark.parametrize(
    "body",
    [
        "{not json",
        '{"access_token":"a","access_token":"b","token_type":"Bearer","expires_in":300}',
        "[]",
        '"a string"',
        "null",
    ],
)
def test_cl_u11_malformed_token_json_is_rejected(body: str) -> None:
    server = FakeServer(
        token_response=lambda _: json_response(body),
        evaluate_response=conforming_allow,
    )
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()


def test_cl_u11_oversized_token_reply_is_rejected() -> None:
    server = FakeServer(
        token_response=lambda _: json_response(token_body(access_token="x" * 100)),
        evaluate_response=conforming_allow,
    )
    client, _, _ = build_client(server, config=make_config(max_response_bytes=32))
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()


def test_cl_u11_no_token_retained_after_failure() -> None:
    state = {"n": 0}

    def token_handler(_: httpx.Request) -> httpx.Response:
        state["n"] += 1
        if state["n"] == 1:
            return json_response("{not json")
        return json_response(token_body())

    server = FakeServer(token_response=token_handler, evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.token_calls == 2


@pytest.mark.parametrize(
    "payload",
    [
        {"access_token": "", "token_type": "Bearer", "expires_in": 300},
        {"access_token": "t", "token_type": "MAC", "expires_in": 300},
        {"access_token": "t", "expires_in": 300},
        {"access_token": "t", "token_type": "Bearer"},
        {"access_token": "t", "token_type": "Bearer", "expires_in": 0},
        {"access_token": "t", "token_type": "Bearer", "expires_in": -5},
        {"access_token": "t", "token_type": "Bearer", "expires_in": "abc"},
        {"access_token": "t", "token_type": "Bearer", "expires_in": True},
    ],
)
def test_cl_u12_invalid_token_fields_are_rejected(payload: dict[str, object]) -> None:
    body = json.dumps(payload)
    server = FakeServer(
        token_response=lambda _: json_response(body),
        evaluate_response=conforming_allow,
    )
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()


def test_cl_u11_non_finite_token_number_is_rejected() -> None:
    server = FakeServer(
        token_response=lambda _: json_response(
            '{"access_token":"t","token_type":"Bearer","expires_in":NaN}'
        ),
        evaluate_response=conforming_allow,
    )
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()


def test_cl_u10_unexpected_token_content_type_is_rejected() -> None:
    server = FakeServer(
        token_response=lambda _: json_response(token_body(), content_type="text/html"),
        evaluate_response=conforming_allow,
    )
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()


def test_cl_u13_token_endpoint_redirect_is_not_followed() -> None:
    def redirect(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=302,
            headers={"location": "https://attacker.example/steal"},
        )

    server = FakeServer(token_response=redirect, evaluate_response=conforming_allow)
    client, _, _ = build_client(server)
    try:
        with pytest.raises(ClientAuthenticationError):
            client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client.close()
    assert server.token_calls == 1
    assert server.evaluate_calls == 0


def test_cl_u43_service_token_cache_is_isolated_per_client() -> None:
    def token_for(value: str) -> object:
        return lambda _: json_response(token_body(access_token=value))

    server_a = FakeServer(token_response=token_for("token-A"), evaluate_response=conforming_allow)
    server_b = FakeServer(token_response=token_for("token-B"), evaluate_response=conforming_allow)
    client_a, _, _ = build_client(server_a)
    client_b, _, _ = build_client(server_b)
    try:
        client_a.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
        client_b.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
    finally:
        client_a.close()
        client_b.close()
    assert server_a.last_evaluate.headers["authorization"] == "Bearer token-A"
    assert server_b.last_evaluate.headers["authorization"] == "Bearer token-B"
    assert server_a.token_calls == 1
    assert server_b.token_calls == 1
    assert SERVICE_TOKEN != "token-A"
