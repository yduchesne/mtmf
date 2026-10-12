"""Strict JSON codec tests (plan matrix A06, A09, A10, A23, A28)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mtmf_api import (
    ActionDecision,
    ApiContractValidationError,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    parse_error_json,
    parse_request_json,
    parse_response_json,
    serialize_error,
    serialize_request,
    serialize_response,
)


def test_a06_unknown_syntactically_valid_action_parses(read_fixture: object) -> None:
    request = parse_request_json(read_fixture("request_unknown_action.json"))  # type: ignore[operator]
    assert request.actions[0].action.endswith("frobnicate-all")


def test_a06_unknown_action_deny_response_parses(read_fixture: object) -> None:
    response = parse_response_json(read_fixture("response_unknown_action.json"))  # type: ignore[operator]
    assert response.decisions[0].effect.value == "DENY"
    assert response.decisions[0].reason.value == "UNKNOWN_ACTION"


def test_a09_duplicate_keys_rejected_including_nested(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(read_fixture("invalid_duplicate_key.json"))  # type: ignore[operator]
    nested = (
        '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"actions":[{"request_id":"check-1","action":"'
        "urn:mtmf:iam:actions:system:document:read-object"
        '","resource":{"kind":"capability","kind":"capability"}}]}'
    )
    with pytest.raises(ApiContractValidationError):
        parse_request_json(nested)


@pytest.mark.parametrize(
    "payload",
    [
        "[]",
        "null",
        '"a string"',
        "42",
        "true",
    ],
)
def test_a10_non_object_top_level_rejected(payload: str) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(payload)


@pytest.mark.parametrize(
    "payload",
    [
        "{",
        '{"tenant_id": }',
        '{"tenant_id":"11111111-1111-4111-8111-111111111111","actions":null}',
        '{"tenant_id":"11111111-1111-4111-8111-111111111111","actions":"read"}',
    ],
)
def test_a10_malformed_or_wrong_shaped_payloads_rejected(payload: str) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(payload)


def test_a10_non_finite_numbers_rejected() -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json('{"tenant_id": NaN, "actions": []}')


def test_request_does_not_carry_schema_version() -> None:
    request = parse_request_json(
        '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"actions":[{"request_id":"check-1",'
        '"action":"urn:mtmf:iam:actions:system:document:read-object",'
        '"resource":{"kind":"capability"}}]}'
    )
    assert "schema_version" not in serialize_request(request)


def test_oversized_bytes_payload_rejected() -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(b"{}{" + b" " * (70 * 1024))


def test_non_utf8_bytes_rejected() -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(b"\xff\xfe\x00")


def test_non_bytes_or_str_payload_is_a_type_error() -> None:
    with pytest.raises(TypeError):
        parse_request_json(42)  # type: ignore[arg-type]


def test_a28_request_round_trip_is_stable(
    valid_request: AuthorizationBatchRequest,
) -> None:
    first = serialize_request(valid_request)
    second = serialize_request(parse_request_json(first))
    assert first == second


def test_a28_response_round_trip_is_stable(
    valid_response: AuthorizationBatchResponse,
) -> None:
    first = serialize_response(valid_response)
    second = serialize_response(parse_response_json(first))
    assert first == second


def test_a28_error_round_trip_is_stable() -> None:
    from mtmf_api import ApiErrorCode, ApiErrorResponse

    error = ApiErrorResponse.for_code(ApiErrorCode.INVALID_REQUEST, request_id="req-trace-123")
    first = serialize_error(error)
    assert serialize_error(parse_error_json(first)) == first


@given(st.binary(max_size=512))
def test_a23_parser_never_crashes_uncontrolled(payload: bytes) -> None:
    try:
        result = parse_request_json(payload)
    except ApiContractValidationError:
        return
    assert isinstance(result, AuthorizationBatchRequest)


@given(st.text(max_size=512))
def test_a23_text_parser_never_crashes_uncontrolled(payload: str) -> None:
    try:
        parse_request_json(payload)
    except ApiContractValidationError:
        return


def test_timestamp_semantic_invalid_rejected() -> None:
    payload = (
        '{"schema_version":"1","tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"organization_id":null,"issued_at":"2026-13-11T20:00:00Z",'
        '"expires_at":"2026-13-11T20:01:00Z",'
        '"decisions":[{"request_id":"check-1","effect":"ALLOW","reason":"PERMITTED"}]}'
    )
    with pytest.raises(ApiContractValidationError):
        parse_response_json(payload)


def test_microsecond_timestamps_round_trip() -> None:
    issued = datetime(2026, 10, 11, 20, 0, 0, 123456, tzinfo=UTC)
    response = AuthorizationBatchResponse(
        tenant_id=UUID("11111111-1111-4111-8111-111111111111"),
        organization_id=None,
        issued_at=issued,
        expires_at=issued + timedelta(seconds=60),
        decisions=(ActionDecision("check-1", AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),),
    )
    payload = serialize_response(response)
    assert ".123456Z" in payload
    assert parse_response_json(payload) == response


@pytest.mark.parametrize(
    "payload",
    [
        # action entry missing resource
        '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"actions":[{"request_id":"check-1",'
        '"action":"urn:mtmf:iam:actions:system:document:read-object"}]}',
        # response missing decisions
        '{"schema_version":"1","tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"organization_id":null,"issued_at":"2026-10-11T20:00:00Z",'
        '"expires_at":"2026-10-11T20:01:00Z"}',
        # error body missing message
        '{"schema_version":"1","error":{"code":"INVALID_REQUEST"}}',
    ],
)
def test_missing_required_fields_rejected(payload: str) -> None:
    for parser in (parse_request_json, parse_response_json, parse_error_json):
        with pytest.raises(ApiContractValidationError):
            parser(payload)
