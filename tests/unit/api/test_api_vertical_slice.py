"""Detached contract vertical slice (plan Part 4).

A checked-in JSON fixture flows through the *shipped* parser, an
independently constructed detached response, the public serializer, the
strict response parser, the pure conformance check, and finally the
consumer-visible ordered decisions. No HTTP, database, policy engine, or
``mtmf-core`` is exercised; the constructed response is test data, not
evidence of a production policy decision.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mtmf_api import (
    ApiContractValidationError,
    ApiErrorCode,
    ApiErrorResponse,
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
    validate_response_for_request,
)

ISSUED_AT = datetime(2026, 10, 11, 20, 0, 0, tzinfo=UTC)


def test_vertical_slice_end_to_end(read_fixture: object) -> None:
    request_bytes = read_fixture("request_duplicate_actions.json").encode("utf-8")  # type: ignore[operator]

    request: AuthorizationBatchRequest = parse_request_json(request_bytes)
    assert [action.request_id for action in request.actions] == ["check-1", "check-2"]

    # The response is test data constructed independently of any engine.
    response = AuthorizationBatchResponse(
        tenant_id=request.tenant_id,
        organization_id=request.organization_id,
        issued_at=ISSUED_AT,
        expires_at=ISSUED_AT + timedelta(seconds=60),
        decisions=(
            # Duplicate equivalent inputs produce equivalent outcomes.
            parse_response_json(read_fixture("response_duplicate_identical.json")).decisions[0],  # type: ignore[operator]
            parse_response_json(read_fixture("response_duplicate_identical.json")).decisions[1],  # type: ignore[operator]
        ),
    )

    payload = serialize_response(response)
    reparsed = parse_response_json(payload)
    validate_response_for_request(request, reparsed)

    visible = [(d.request_id, d.effect.name, d.reason.name) for d in reparsed.decisions]
    assert visible == [
        ("check-1", "ALLOW", "PERMITTED"),
        ("check-2", "ALLOW", "PERMITTED"),
    ]
    # Round-tripping the request proves the parser/serializer agree.
    assert parse_request_json(serialize_request(request)) == request


def test_vertical_slice_invalid_envelope_fails_closed(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(read_fixture("invalid_unknown_field.json"))  # type: ignore[operator]


def test_vertical_slice_unknown_action_is_a_per_item_deny(read_fixture: object) -> None:
    request = parse_request_json(read_fixture("request_unknown_action.json"))  # type: ignore[operator]
    response = parse_response_json(read_fixture("response_unknown_action.json"))  # type: ignore[operator]
    validate_response_for_request(request, response)
    decision = response.decisions[0]
    assert decision.effect is AuthorizationEffect.DENY
    assert decision.reason is DecisionReason.UNKNOWN_ACTION


def test_vertical_slice_dependency_error_is_an_envelope_not_partial_decisions(
    read_fixture: object,
) -> None:
    error = parse_error_json(read_fixture("error_dependency_unavailable.json"))  # type: ignore[operator]
    assert error.code is ApiErrorCode.DEPENDENCY_UNAVAILABLE
    payload = serialize_error(error)
    assert "decisions" not in payload
    assert parse_error_json(payload) == error

    # Passing an error envelope to the response parser must fail closed.
    with pytest.raises(ApiContractValidationError):
        parse_response_json(payload)


def test_vertical_slice_error_dto_cannot_carry_decisions() -> None:
    error = ApiErrorResponse.for_code(ApiErrorCode.INTERNAL_ERROR)
    assert not hasattr(error, "decisions")
    assert not hasattr(error, "effect")
