"""Scoped snapshot and PEP helper tests (CL-U27..CL-U39, CL-U44, CL-U45).

Every helper call now supplies the exact evaluated Action and ResourceTarget;
``request_id`` is only a correlation discriminator.
"""

from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import httpx
import pytest
from client_helpers import (
    ACTION_ALLOW,
    ACTION_DENY,
    APP_ID,
    ORGANIZATION_ID,
    OTHER_APP_ID,
    OTHER_TENANT_ID,
    PRINCIPAL_ID,
    TENANT_ID,
    USER_TOKEN,
    FakeServer,
    application_owned,
    build_client,
    capability,
    conforming_allow,
    conforming_by_request_id,
    json_response,
    make_config,
    make_context,
    make_request,
    make_response,
    response_body,
)

from mtmf_api.authorization import AuthorizationEffect, DecisionReason
from mtmf_api.json_codec import parse_request_json
from mtmf_client import (
    AuthorizationDenied,
    AuthorizationSnapshot,
    RemoteProtocolError,
    is_allowed,
    require,
)


def _check(snapshot: object, **overrides: object) -> bool:
    """Call the module helper with an explicit capability target by default."""
    values: dict[str, object] = {
        "context": make_context(),
        "action": ACTION_ALLOW,
        "resource": capability(),
    }
    values.update(overrides)
    return bool(is_allowed(snapshot, **values))  # type: ignore[arg-type]


def _respond_with_lifetime(seconds: float) -> object:
    def _handler(request: httpx.Request) -> httpx.Response:
        parsed = parse_request_json(request.content)
        return json_response(
            response_body(make_response(parsed, lifetime=timedelta(seconds=seconds)))
        )

    return _handler


def _issue(request: object, *, config: object = None, context: object = None) -> tuple:
    server = FakeServer(evaluate_response=conforming_allow)
    client, resolved_config, clock = build_client(server, config=config)
    snapshot = client.evaluate(
        request,
        user_access_token=USER_TOKEN,
        context=context if context is not None else make_context(),
    )
    return client, snapshot, clock, server, resolved_config


def test_cl_u27_exact_allow_occurrence_is_allowed() -> None:
    request = make_request(("req-1", ACTION_ALLOW, None))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert _check(snapshot, request_id="req-1") is True
        assert _check(snapshot) is True
        require(
            snapshot,
            context=make_context(),
            action=ACTION_ALLOW,
            resource=capability(),
            request_id="req-1",
        )
        client.require(
            snapshot,
            context=make_context(),
            action=ACTION_ALLOW,
            resource=capability(),
            request_id="req-1",
        )
        assert (
            client.is_allowed(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=capability(),
                request_id="req-1",
            )
            is True
        )
    finally:
        client.close()


def test_cl_u28_deny_unknown_and_absent_occurrence_deny() -> None:
    request = make_request(
        ("allow", ACTION_ALLOW, None),
        ("deny", ACTION_DENY, None),
    )
    server = FakeServer(
        evaluate_response=conforming_by_request_id(
            {
                "allow": (AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
                "deny": (AuthorizationEffect.DENY, DecisionReason.EXPLICIT_DENY),
            }
        )
    )
    client, _, _ = build_client(server)
    try:
        snapshot = client.evaluate(request, user_access_token=USER_TOKEN, context=make_context())
        assert _check(snapshot, action=ACTION_DENY, request_id="deny") is False
        assert _check(snapshot, action=ACTION_ALLOW, request_id="missing") is False
        # An Action that was never requested is never allowed.
        assert (
            _check(snapshot, action="urn:mtmf:iam:actions:system:unrequested:get-object") is False
        )
        with pytest.raises(AuthorizationDenied):
            require(
                snapshot,
                context=make_context(),
                action=ACTION_DENY,
                resource=capability(),
                request_id="deny",
            )
    finally:
        client.close()


def test_cl_u29_duplicate_semantic_occurrences_require_request_id() -> None:
    request = make_request(
        ("a", ACTION_ALLOW, capability()),
        ("b", ACTION_ALLOW, capability()),
    )
    client, snapshot, _, _, _ = _issue(request)
    try:
        # Two identical Action/resource occurrences are ambiguous without id.
        assert _check(snapshot) is False
        assert _check(snapshot, request_id="a") is True
        assert _check(snapshot, request_id="b") is True
        with pytest.raises(AuthorizationDenied):
            require(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=capability(),
            )
    finally:
        client.close()


def test_cl_u30_cross_application_and_cross_client_replay_deny() -> None:
    request = make_request()
    client_a, snapshot, _, _, _ = _issue(request)
    server_b = FakeServer(evaluate_response=conforming_allow)
    client_b, _, _ = build_client(server_b)
    try:
        assert (
            _check(
                snapshot,
                context=make_context(application_id=OTHER_APP_ID),
                request_id="req-1",
            )
            is False
        )
        assert (
            client_b.is_allowed(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=capability(),
                request_id="req-1",
            )
            is False
        )
        with pytest.raises(AuthorizationDenied):
            client_b.require(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=capability(),
                request_id="req-1",
            )
    finally:
        client_a.close()
        client_b.close()


def test_cl_u31_cross_actor_and_session_replay_deny() -> None:
    client, snapshot, _, _, _ = _issue(make_request())
    try:
        assert (
            _check(snapshot, context=make_context(actor_key="other"), request_id="req-1") is False
        )
        assert (
            _check(snapshot, context=make_context(session_key="other"), request_id="req-1") is False
        )
        assert (
            _check(
                snapshot,
                context=make_context(principal_id=UUID("99999999-9999-4999-8999-999999999999")),
                request_id="req-1",
            )
            is False
        )
    finally:
        client.close()


def test_cl_u32_cross_tenant_and_organization_replay_deny() -> None:
    client, snapshot, _, _, _ = _issue(make_request())
    try:
        assert (
            _check(snapshot, context=make_context(tenant_id=OTHER_TENANT_ID), request_id="req-1")
            is False
        )
        assert (
            _check(
                snapshot,
                context=make_context(organization_id=ORGANIZATION_ID),
                request_id="req-1",
            )
            is False
        )
    finally:
        client.close()


def test_cl_u33_cross_resource_replay_denies() -> None:
    request = make_request(("req-1", ACTION_ALLOW, application_owned("row-1")))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert _check(snapshot, resource=application_owned("row-2")) is False
        assert _check(snapshot, resource=capability()) is False
        assert _check(snapshot, request_id="req-1", resource=application_owned("row-2")) is False
    finally:
        client.close()


def test_cl_u34_capability_allow_cannot_be_used_for_an_object() -> None:
    request = make_request(("req-1", ACTION_ALLOW, capability()))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert _check(snapshot, resource=application_owned("row-1")) is False
    finally:
        client.close()


def test_cl_u35_monotonic_expiry_boundary() -> None:
    server = FakeServer(evaluate_response=_respond_with_lifetime(10))
    client, _, clock = build_client(server, config=make_config(max_snapshot_ttl_seconds=300))
    try:
        snapshot = client.evaluate(
            make_request(), user_access_token=USER_TOKEN, context=make_context()
        )
        clock.advance_monotonic(9.999)
        assert _check(snapshot, request_id="req-1") is True
        clock.advance_monotonic(0.001)
        assert _check(snapshot, request_id="req-1") is False
    finally:
        client.close()


def test_cl_u36_future_issued_and_already_expired_are_rejected() -> None:
    clock_server = FakeServer(evaluate_response=conforming_allow)
    client, _, clock = build_client(clock_server)

    def future(request: httpx.Request) -> httpx.Response:
        parsed = parse_request_json(request.content)
        return json_response(
            response_body(make_response(parsed, issued_at=clock.wall + timedelta(seconds=1000)))
        )

    def expired(request: httpx.Request) -> httpx.Response:
        parsed = parse_request_json(request.content)
        return json_response(
            response_body(
                make_response(
                    parsed,
                    issued_at=clock.wall - timedelta(seconds=1000),
                    lifetime=timedelta(seconds=10),
                )
            )
        )

    try:
        for handler in (future, expired):
            server = FakeServer(evaluate_response=handler)
            inner, _, _ = build_client(server)
            try:
                with pytest.raises(RemoteProtocolError):
                    inner.evaluate(
                        make_request(), user_access_token=USER_TOKEN, context=make_context()
                    )
            finally:
                inner.close()
    finally:
        client.close()


def test_cl_u36_wall_clock_uncertainty_and_jumps() -> None:
    server = FakeServer(evaluate_response=_respond_with_lifetime(6))
    config = make_config(clock_uncertainty_seconds=5.0, max_snapshot_ttl_seconds=300)
    client, _, clock = build_client(server, config=config)
    try:
        snapshot = client.evaluate(
            make_request(), user_access_token=USER_TOKEN, context=make_context()
        )
        # 6s server lifetime minus 5s uncertainty leaves only 1s.
        clock.advance_monotonic(1.1)
        assert _check(snapshot, request_id="req-1") is False
    finally:
        client.close()


def test_cl_u36_post_issue_wall_jumps_do_not_change_monotonic_validity() -> None:
    client, snapshot, clock, _, _ = _issue(make_request())
    try:
        clock.advance_wall(10_000)
        assert _check(snapshot, request_id="req-1") is True
        clock.advance_wall(-20_000)
        assert _check(snapshot, request_id="req-1") is True
    finally:
        client.close()


def test_cl_u37_no_extension_and_universal_sensitive_cap() -> None:
    # Server lifetime longer than the universal 15s cap: capped at 15s.
    client, snapshot, clock, _, _ = _issue(make_request())
    try:
        clock.advance_monotonic(15.1)
        assert _check(snapshot, request_id="req-1") is False
    finally:
        client.close()

    # Server lifetime shorter than any cap is never extended to 60s.
    server = FakeServer(evaluate_response=_respond_with_lifetime(1))
    client, _, clock = build_client(server, config=make_config(max_snapshot_ttl_seconds=300))
    try:
        snapshot = client.evaluate(
            make_request(), user_access_token=USER_TOKEN, context=make_context()
        )
        clock.advance_monotonic(1.1)
        assert _check(snapshot, request_id="req-1") is False
    finally:
        client.close()


def test_cl_u38_token_renewal_does_not_extend_snapshot() -> None:
    counter = {"n": 0}

    def token_handler(_: httpx.Request) -> httpx.Response:
        from client_helpers import token_body

        counter["n"] += 1
        return json_response(token_body(access_token=f"t{counter['n']}", expires_in=2))

    server = FakeServer(token_response=token_handler, evaluate_response=conforming_allow)
    client, _, clock = build_client(server)
    try:
        snapshot = client.evaluate(
            make_request(), user_access_token=USER_TOKEN, context=make_context()
        )
        original_expiry = snapshot.expires_at
        clock.advance_monotonic(3)
        client.evaluate(make_request(), user_access_token=USER_TOKEN, context=make_context())
        assert server.token_calls == 2
        assert snapshot.expires_at == original_expiry
        # The original snapshot is still bounded by its own original deadline.
        clock.advance_monotonic(12.1)
        assert _check(snapshot, request_id="req-1") is False
    finally:
        client.close()


def test_cl_u39_helpers_never_call_the_network() -> None:
    client, snapshot, _, server, _ = _issue(make_request())
    try:
        before_token = server.token_calls
        before_evaluate = server.evaluate_calls
        _check(snapshot, request_id="req-1")
        require(
            snapshot,
            context=make_context(),
            action=ACTION_ALLOW,
            resource=capability(),
            request_id="req-1",
        )
        client.is_allowed(
            snapshot,
            context=make_context(),
            action=ACTION_ALLOW,
            resource=capability(),
            request_id="req-1",
        )
        client.require(
            snapshot,
            context=make_context(),
            action=ACTION_ALLOW,
            resource=capability(),
            request_id="req-1",
        )
        assert server.token_calls == before_token
        assert server.evaluate_calls == before_evaluate
    finally:
        client.close()


def test_cl_u44_monotonic_rollback_denies() -> None:
    client, snapshot, clock, _, _ = _issue(make_request())
    try:
        clock.mono = 0.0
        assert _check(snapshot, request_id="req-1") is False
        with pytest.raises(AuthorizationDenied):
            require(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=capability(),
                request_id="req-1",
            )
    finally:
        client.close()


def test_cl_u45_tampered_snapshot_is_never_accepted() -> None:
    client, snapshot, _, _, _ = _issue(make_request())
    try:
        # A hand-built object with a foreign provenance marker is rejected.
        object.__setattr__(snapshot, "_provenance", object())
        assert _check(snapshot, request_id="req-1") is False
        assert (
            client.is_allowed(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=capability(),
                request_id="req-1",
            )
            is False
        )
    finally:
        client.close()


def test_cl_u45_non_snapshot_objects_deny() -> None:
    assert _check(object()) is False  # type: ignore[arg-type]
    assert isinstance(make_config(), object)
    assert not isinstance(object(), AuthorizationSnapshot)


def test_snapshot_repr_is_redacted() -> None:
    client, snapshot, _, _, _ = _issue(make_request())
    try:
        text = repr(snapshot)
        assert USER_TOKEN not in text
        assert "AuthorizationSnapshot(" in text
        assert str(PRINCIPAL_ID) not in text
    finally:
        client.close()


def test_snapshot_properties_and_context_validation() -> None:
    from datetime import UTC, datetime

    from mtmf_client import ActorContextError

    request = make_request(organization_id=ORGANIZATION_ID)
    client, snapshot, _, _, _ = _issue(
        request, context=make_context(organization_id=ORGANIZATION_ID)
    )
    try:
        assert snapshot.tenant_id == TENANT_ID
        assert snapshot.organization_id == ORGANIZATION_ID
        assert snapshot.application_id == APP_ID
        assert snapshot.decision_count == 1
        assert snapshot.issued_at == datetime(2026, 10, 13, 12, 0, 0, tzinfo=UTC)
        assert snapshot.expires_at > snapshot.issued_at
        # Non-context and malformed runtime arguments fail closed.
        assert (
            is_allowed(
                snapshot,
                context=object(),  # type: ignore[arg-type]
                action=ACTION_ALLOW,
                resource=capability(),
                request_id="req-1",
            )
            is False
        )
        assert (
            _check(
                snapshot,
                context=make_context(organization_id=ORGANIZATION_ID),
                request_id=123,  # type: ignore[arg-type]
            )
            is False
        )
        assert (
            is_allowed(
                snapshot,
                context=make_context(organization_id=ORGANIZATION_ID),
                action=ACTION_ALLOW,
                resource=object(),  # type: ignore[arg-type]
                request_id="req-1",
            )
            is False
        )
    finally:
        client.close()

    with pytest.raises(ActorContextError):
        make_context(actor_key="")
    with pytest.raises(ActorContextError):
        make_context(session_key="   ")
    with pytest.raises(ActorContextError):
        make_context(tenant_id=UUID(int=0))
    with pytest.raises(ActorContextError):
        make_context(principal_id=UUID(int=0))
    with pytest.raises(ActorContextError):
        make_context(application_id=UUID(int=0))


def test_snapshot_direct_construction_is_guarded() -> None:
    from mtmf_client.snapshot import _Provenance

    request = make_request()
    response = make_response(request)
    context = make_context()
    provenance = _Provenance()
    kwargs = {
        "issued_monotonic": 0.0,
        "deadline_monotonic": 1.0,
        "monotonic_clock": lambda: 0.0,
        "provenance": provenance,
    }
    with pytest.raises(ValueError):
        AuthorizationSnapshot(request=object(), response=response, context=context, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        AuthorizationSnapshot(request=request, response=response, context=object(), **kwargs)  # type: ignore[arg-type]
    mismatch = make_response(make_request(("a", ACTION_ALLOW, None), ("b", ACTION_DENY, None)))
    with pytest.raises(ValueError):
        AuthorizationSnapshot(request=request, response=mismatch, context=context, **kwargs)
    with pytest.raises(ValueError):
        AuthorizationSnapshot(
            request=request,
            response=response,
            context=context,
            issued_monotonic=0.0,
            deadline_monotonic=1.0,
            monotonic_clock=lambda: 0.0,
            provenance=object(),  # type: ignore[arg-type]
        )
