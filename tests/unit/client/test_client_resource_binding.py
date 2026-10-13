"""Explicit Action/ResourceTarget binding tests (PR 18 Fixup 1, FX-U01..FX-U26).

Every local authorization decision must identify the exact Action and
ResourceTarget for the object or capability being checked; ``request_id`` is
only a correlation discriminator. These tests exercise the real public
``mtmf_client`` helpers and client-bound methods.
"""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from client_helpers import (
    ACTION_ALLOW,
    ACTION_DENY,
    ORGANIZATION_ID,
    OTHER_APP_ID,
    OTHER_TENANT_ID,
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

from mtmf_api.authorization import (
    AuthorizationEffect,
    DecisionReason,
    ResourceKind,
    ResourceTarget,
)
from mtmf_api.json_codec import parse_request_json
from mtmf_client import (
    AuthorizationDenied,
    is_allowed,
    require,
)

ROW_42 = application_owned("row-42")
ROW_43 = application_owned("row-43")
MTMF_T1 = ResourceTarget(kind=ResourceKind.MTMF_OWNED, resource_type="thing", resource_id="t-1")
MTMF_T2 = ResourceTarget(kind=ResourceKind.MTMF_OWNED, resource_type="ting", resource_id="t-2")


def _issue(
    request: object,
    *,
    context: object = None,
    server: FakeServer | None = None,
    config: object = None,
    clock: object = None,
) -> tuple:
    server = server or FakeServer(evaluate_response=conforming_allow)
    client, resolved_config, resolved_clock = build_client(server, config=config, clock=clock)
    snapshot = client.evaluate(
        request,
        user_access_token=USER_TOKEN,
        context=context if context is not None else make_context(),
    )
    return client, snapshot, resolved_clock, server, resolved_config


def _allow(snapshot: object, **overrides: object) -> bool:
    values: dict[str, object] = {
        "context": make_context(),
        "action": ACTION_ALLOW,
        "resource": capability(),
    }
    values.update(overrides)
    return bool(is_allowed(snapshot, **values))  # type: ignore[arg-type]


# -- FX-U01..FX-U07: exact binding and ambiguity -----------------------------


def test_fx_u01_exact_allow_returns_and_require_passes() -> None:
    request = make_request(("check-1", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert (
            is_allowed(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=ROW_42,
                request_id="check-1",
            )
            is True
        )
        require(
            snapshot,
            context=make_context(),
            action=ACTION_ALLOW,
            resource=ROW_42,
            request_id="check-1",
        )
    finally:
        client.close()


def test_fx_u02_request_id_with_wrong_resource_denies() -> None:
    request = make_request(("check-1", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert (
            is_allowed(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=ROW_43,
                request_id="check-1",
            )
            is False
        )
        with pytest.raises(AuthorizationDenied):
            require(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=ROW_43,
                request_id="check-1",
            )
    finally:
        client.close()


def test_fx_u03_same_resource_wrong_action_denies() -> None:
    request = make_request(("check-1", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert (
            is_allowed(
                snapshot,
                context=make_context(),
                action=ACTION_DENY,
                resource=ROW_42,
                request_id="check-1",
            )
            is False
        )
    finally:
        client.close()


def test_fx_u04_unique_action_resource_without_request_id_allows() -> None:
    request = make_request(("check-1", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42) is True
    finally:
        client.close()


def test_fx_u05_duplicate_action_resource_without_request_id_denies() -> None:
    request = make_request(("a", ACTION_ALLOW, ROW_42), ("b", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42) is False
    finally:
        client.close()


def test_fx_u06_duplicate_occurrences_explicit_allow_id_allows_only_exact() -> None:
    request = make_request(("a", ACTION_ALLOW, ROW_42), ("b", ACTION_DENY, ROW_42))
    server = FakeServer(
        evaluate_response=conforming_by_request_id(
            {
                "a": (AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
                "b": (AuthorizationEffect.DENY, DecisionReason.EXPLICIT_DENY),
            }
        )
    )
    client, snapshot, _, _, _ = _issue(request, server=server)
    try:
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42, request_id="a") is True
        # The wrong Action with the right id denies.
        assert _allow(snapshot, action=ACTION_DENY, resource=ROW_42, request_id="a") is False
        # A missing id denies.
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42, request_id="missing") is False
    finally:
        client.close()


def test_fx_u07_duplicate_occurrences_explicit_deny_id_denies() -> None:
    request = make_request(("a", ACTION_ALLOW, ROW_42), ("b", ACTION_DENY, ROW_42))
    server = FakeServer(
        evaluate_response=conforming_by_request_id(
            {
                "a": (AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
                "b": (AuthorizationEffect.DENY, DecisionReason.EXPLICIT_DENY),
            }
        )
    )
    client, snapshot, _, _, _ = _issue(request, server=server)
    try:
        assert _allow(snapshot, action=ACTION_DENY, resource=ROW_42, request_id="b") is False
        with pytest.raises(AuthorizationDenied):
            require(
                snapshot,
                context=make_context(),
                action=ACTION_DENY,
                resource=ROW_42,
                request_id="b",
            )
    finally:
        client.close()


# -- FX-U08..FX-U11: required arguments --------------------------------------


def test_fx_u08_request_id_only_module_helpers_raise_type_error() -> None:
    request = make_request(("check-1", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        with pytest.raises(TypeError):
            is_allowed(snapshot, context=make_context(), request_id="check-1")  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            require(snapshot, context=make_context(), request_id="check-1")  # type: ignore[call-arg]
    finally:
        client.close()


def test_fx_u09_request_id_and_action_only_module_helpers_raise_type_error() -> None:
    request = make_request(("check-1", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        with pytest.raises(TypeError):
            is_allowed(  # type: ignore[call-arg]
                snapshot, context=make_context(), action=ACTION_ALLOW, request_id="check-1"
            )
        with pytest.raises(TypeError):
            require(  # type: ignore[call-arg]
                snapshot, context=make_context(), action=ACTION_ALLOW, request_id="check-1"
            )
    finally:
        client.close()


def test_fx_u10_action_only_module_helpers_raise_type_error() -> None:
    request = make_request(("check-1", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        with pytest.raises(TypeError):
            is_allowed(snapshot, context=make_context(), action=ACTION_ALLOW)  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            require(snapshot, context=make_context(), action=ACTION_ALLOW)  # type: ignore[call-arg]
    finally:
        client.close()


def test_fx_u11_client_methods_require_action_and_resource() -> None:
    request = make_request(("check-1", ACTION_ALLOW, ROW_42))
    client, snapshot, _, _, _ = _issue(request)
    try:
        with pytest.raises(TypeError):
            client.is_allowed(snapshot, context=make_context(), request_id="check-1")  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            client.require(snapshot, context=make_context(), request_id="check-1")  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            client.is_allowed(snapshot, context=make_context(), action=ACTION_ALLOW)  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            client.require(snapshot, context=make_context(), action=ACTION_ALLOW)  # type: ignore[call-arg]
    finally:
        client.close()


# -- FX-U12..FX-U15: target kind/type/id binding -----------------------------


def test_fx_u12_explicit_capability_matches_capability() -> None:
    request = make_request(("check-1", ACTION_ALLOW, capability()))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert (
            _allow(snapshot, action=ACTION_ALLOW, resource=capability(), request_id="check-1")
            is True
        )
    finally:
        client.close()


def test_fx_u13_capability_vs_application_owned_cross_use_denies() -> None:
    cap_client, cap_snapshot, _, _, _ = _issue(
        make_request(("check-1", ACTION_ALLOW, capability()))
    )
    row_client, row_snapshot, _, _, _ = _issue(make_request(("check-1", ACTION_ALLOW, ROW_42)))
    try:
        assert (
            _allow(cap_snapshot, action=ACTION_ALLOW, resource=ROW_42, request_id="check-1")
            is False
        )
        assert (
            _allow(row_snapshot, action=ACTION_ALLOW, resource=capability(), request_id="check-1")
            is False
        )
    finally:
        cap_client.close()
        row_client.close()


def test_fx_u14_different_application_owned_type_denies() -> None:
    request = make_request(
        (
            "check-1",
            ACTION_ALLOW,
            ResourceTarget(
                kind=ResourceKind.APPLICATION_OWNED, resource_type="document", resource_id="row-42"
            ),
        )
    )
    client, snapshot, _, _, _ = _issue(request)
    wrong_type = ResourceTarget(
        kind=ResourceKind.APPLICATION_OWNED, resource_type="invoice", resource_id="row-42"
    )
    try:
        assert (
            _allow(snapshot, action=ACTION_ALLOW, resource=wrong_type, request_id="check-1")
            is False
        )
    finally:
        client.close()


def test_fx_u15_different_mtmf_owned_type_or_id_denies() -> None:
    request = make_request(("check-1", ACTION_ALLOW, MTMF_T1))
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert (
            _allow(snapshot, action=ACTION_ALLOW, resource=MTMF_T2, request_id="check-1") is False
        )
        assert _allow(snapshot, action=ACTION_ALLOW, resource=MTMF_T1, request_id="check-1") is True
    finally:
        client.close()


# -- FX-U16..FX-U21: context, expiry, provenance, decisions ------------------


def test_fx_u16_wrong_context_denies() -> None:
    client, snapshot, _, _, _ = _issue(make_request(("check-1", ACTION_ALLOW, ROW_42)))
    try:
        for wrong in (
            make_context(actor_key="other"),
            make_context(session_key="other"),
            make_context(application_id=OTHER_APP_ID),
            make_context(tenant_id=OTHER_TENANT_ID),
            make_context(organization_id=ORGANIZATION_ID),
        ):
            assert _allow(snapshot, context=wrong, request_id="check-1") is False
    finally:
        client.close()


def test_fx_u17_expired_and_rollback_deny_without_http() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        parsed = parse_request_json(request.content)
        return json_response(response_body(make_response(parsed, lifetime=timedelta(seconds=1))))

    server = FakeServer(evaluate_response=handler)
    client, snapshot, clock, _, _ = _issue(
        make_request(("check-1", ACTION_ALLOW, ROW_42)),
        server=server,
        config=make_config(max_snapshot_ttl_seconds=300),
    )
    try:
        before = server.evaluate_calls
        clock.advance_monotonic(1.1)
        assert _allow(snapshot, request_id="check-1") is False
        clock.mono = 0.0
        assert _allow(snapshot, request_id="check-1") is False
        assert server.evaluate_calls == before
    finally:
        client.close()


def test_fx_u18_missing_snapshot_and_malformed_arguments_deny() -> None:
    client, snapshot, _, _, _ = _issue(make_request(("check-1", ACTION_ALLOW, ROW_42)))
    try:
        assert _allow(None) is False
        assert (
            is_allowed(  # type: ignore[arg-type]
                snapshot, context=make_context(), action=123, resource=ROW_42
            )
            is False
        )
        assert (
            is_allowed(  # type: ignore[arg-type]
                snapshot, context=make_context(), action=ACTION_ALLOW, resource=object()
            )
            is False
        )
        assert (
            is_allowed(  # type: ignore[arg-type]
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=ROW_42,
                request_id=123,
            )
            is False
        )
        assert (
            is_allowed(  # type: ignore[arg-type]
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=ROW_42,
                request_id="",
            )
            is False
        )
    finally:
        client.close()


def test_fx_u19_wrong_client_provenance_denies_client_methods() -> None:
    client_a, snapshot, _, _, _ = _issue(make_request(("check-1", ACTION_ALLOW, ROW_42)))
    client_b, _, _ = build_client(FakeServer(evaluate_response=conforming_allow))
    try:
        assert (
            client_b.is_allowed(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=ROW_42,
                request_id="check-1",
            )
            is False
        )
        with pytest.raises(AuthorizationDenied):
            client_b.require(
                snapshot,
                context=make_context(),
                action=ACTION_ALLOW,
                resource=ROW_42,
                request_id="check-1",
            )
    finally:
        client_a.close()
        client_b.close()


def test_fx_u20_unknown_action_and_policy_deny() -> None:
    request = make_request(
        ("allow", ACTION_ALLOW, capability()),
        ("deny", ACTION_DENY, capability()),
    )
    server = FakeServer(
        evaluate_response=conforming_by_request_id(
            {
                "allow": (AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
                "deny": (AuthorizationEffect.DENY, DecisionReason.UNKNOWN_ACTION),
            }
        )
    )
    client, snapshot, _, _, _ = _issue(request, server=server)
    try:
        assert (
            _allow(snapshot, action=ACTION_DENY, resource=capability(), request_id="deny") is False
        )
        assert (
            _allow(
                snapshot,
                action="urn:mtmf:iam:actions:system:not-registered:get-object",
                resource=capability(),
            )
            is False
        )
    finally:
        client.close()


def test_fx_u21_require_matches_is_allowed_for_every_case() -> None:
    request = make_request(
        ("allow", ACTION_ALLOW, ROW_42),
        ("deny", ACTION_DENY, ROW_42),
    )
    server = FakeServer(
        evaluate_response=conforming_by_request_id(
            {
                "allow": (AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
                "deny": (AuthorizationEffect.DENY, DecisionReason.EXPLICIT_DENY),
            }
        )
    )
    client, snapshot, _, _, _ = _issue(request, server=server)
    try:
        cases = [
            ("allow", ACTION_ALLOW, ROW_42, True),
            ("allow", ACTION_ALLOW, ROW_43, False),
            ("deny", ACTION_DENY, ROW_42, False),
            ("missing", ACTION_ALLOW, ROW_42, False),
        ]
        for request_id, action, resource, expected in cases:
            allowed = is_allowed(
                snapshot,
                context=make_context(),
                action=action,
                resource=resource,
                request_id=request_id,
            )
            assert allowed is expected
            if expected:
                require(
                    snapshot,
                    context=make_context(),
                    action=action,
                    resource=resource,
                    request_id=request_id,
                )
            else:
                with pytest.raises(AuthorizationDenied):
                    require(
                        snapshot,
                        context=make_context(),
                        action=action,
                        resource=resource,
                        request_id=request_id,
                    )
    finally:
        client.close()


# -- FX-U22..FX-U26: resource independence, no I/O, renewal ------------------


def test_fx_u22_after_positive_decision_wrong_resource_with_same_id_denies() -> None:
    client, snapshot, _, server, _ = _issue(make_request(("check-1", ACTION_ALLOW, ROW_42)))
    try:
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42, request_id="check-1") is True
        before = server.evaluate_calls
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_43, request_id="check-1") is False
        assert server.evaluate_calls == before
    finally:
        client.close()


def test_fx_u23_two_resources_same_action_lookup_returns_only_supplied() -> None:
    request = make_request(
        ("r42", ACTION_ALLOW, ROW_42),
        ("r43", ACTION_ALLOW, ROW_43),
    )
    client, snapshot, _, _, _ = _issue(request)
    try:
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_43) is True
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42) is True
        # The supplied resource selects its own occurrence, never the other.
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_43, request_id="r42") is False
    finally:
        client.close()


def test_fx_u24_repeated_local_checks_never_touch_the_network() -> None:
    client, snapshot, _, server, _ = _issue(make_request(("check-1", ACTION_ALLOW, ROW_42)))
    try:
        before_token = server.token_calls
        before_evaluate = server.evaluate_calls
        for _ in range(50):
            _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42, request_id="check-1")
            _allow(snapshot, action=ACTION_ALLOW, resource=ROW_43, request_id="check-1")
        assert server.token_calls == before_token
        assert server.evaluate_calls == before_evaluate
    finally:
        client.close()


def test_fx_u25_caller_must_supply_the_current_object_target() -> None:
    # The library cannot know which object the handler actually touched; it
    # enforces only that the supplied Action/ResourceTarget was ALLOW. A
    # handler that wrongly reuses row-42 would pass, so the PEP must derive
    # the target from the actual object. The explicit row-43 check denies.
    client, snapshot, _, _, _ = _issue(make_request(("check-1", ACTION_ALLOW, ROW_42)))
    try:
        require(
            snapshot,
            context=make_context(),
            action=ACTION_ALLOW,
            resource=ROW_42,
            request_id="check-1",
        )
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_43) is False
    finally:
        client.close()


def test_fx_u26_token_renewal_preserves_original_snapshot_deadline() -> None:
    counter = {"n": 0}

    def token_handler(_: httpx.Request) -> httpx.Response:
        from client_helpers import token_body

        counter["n"] += 1
        return json_response(token_body(access_token=f"t{counter['n']}", expires_in=2))

    lifetime = timedelta(seconds=10)

    def evaluate_handler(request: httpx.Request) -> httpx.Response:
        parsed = parse_request_json(request.content)
        return json_response(response_body(make_response(parsed, lifetime=lifetime)))

    server = FakeServer(token_response=token_handler, evaluate_response=evaluate_handler)
    client, snapshot, clock, _, _ = _issue(
        make_request(("check-1", ACTION_ALLOW, ROW_42)),
        server=server,
        config=make_config(max_snapshot_ttl_seconds=300),
    )
    try:
        original_expiry = snapshot.expires_at
        clock.advance_monotonic(3)
        client.evaluate(
            make_request(("check-2", ACTION_ALLOW, ROW_42)),
            user_access_token=USER_TOKEN,
            context=make_context(),
        )
        assert server.token_calls == 2
        assert snapshot.expires_at == original_expiry
        # Still valid just before the original 10s deadline...
        clock.advance_monotonic(6.9)
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42, request_id="check-1") is True
        # ...and denied immediately after it, proving no extension on renewal.
        clock.advance_monotonic(0.2)
        assert _allow(snapshot, action=ACTION_ALLOW, resource=ROW_42, request_id="check-1") is False
    finally:
        client.close()
