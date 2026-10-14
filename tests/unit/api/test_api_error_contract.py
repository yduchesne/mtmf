"""Stable public error catalog tests (plan matrix A21, A22)."""

from __future__ import annotations

import pytest

from mtmf_api import (
    ERROR_HTTP_STATUS,
    ERROR_MESSAGES,
    ApiContractValidationError,
    ApiErrorCode,
    ApiErrorResponse,
    parse_error_json,
    serialize_error,
)

EXPECTED_HTTP_STATUS = {
    ApiErrorCode.INVALID_REQUEST: 400,
    ApiErrorCode.UNAUTHENTICATED: 401,
    ApiErrorCode.UNTRUSTED_ACTOR: 403,
    ApiErrorCode.INELIGIBLE_APPLICATION: 403,
    ApiErrorCode.FORBIDDEN: 403,
    ApiErrorCode.REQUEST_TOO_LARGE: 413,
    ApiErrorCode.UNSUPPORTED_MEDIA_TYPE: 415,
    ApiErrorCode.RATE_LIMITED: 429,
    ApiErrorCode.DEPENDENCY_UNAVAILABLE: 503,
    ApiErrorCode.INTERNAL_ERROR: 500,
}


@pytest.mark.parametrize("code", list(ApiErrorCode))
def test_a21_every_reserved_error_round_trips(code: ApiErrorCode) -> None:
    error = ApiErrorResponse.for_code(code)
    payload = serialize_error(error)
    parsed = parse_error_json(payload)
    assert parsed == error
    assert parsed.message == ERROR_MESSAGES[code]
    assert parsed.http_status == EXPECTED_HTTP_STATUS[code]


def test_a21_error_fixtures_match_the_catalog(read_fixture: object) -> None:
    for code in ApiErrorCode:
        name = f"error_{code.value.lower()}.json"
        parsed = parse_error_json(read_fixture(name))  # type: ignore[operator]
        assert parsed.code is code
        assert parsed.message == ERROR_MESSAGES[code]


def test_a21_optional_request_id_round_trips(read_fixture: object) -> None:
    parsed = parse_error_json(read_fixture("error_with_request_id.json"))  # type: ignore[operator]
    assert parsed.request_id == "req-trace-123"
    assert parse_error_json(serialize_error(parsed)) == parsed


def test_a21_http_status_table_is_complete() -> None:
    assert set(ERROR_HTTP_STATUS) == set(ApiErrorCode)
    assert dict(ERROR_HTTP_STATUS) == EXPECTED_HTTP_STATUS


def test_a22_unknown_error_code_rejected(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_error_json(read_fixture("invalid_error_code.json"))  # type: ignore[operator]


def test_a22_secret_or_stack_field_rejected(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_error_json(read_fixture("invalid_error_secret_field.json"))  # type: ignore[operator]


def test_a22_message_must_match_static_catalog() -> None:
    payload = (
        '{"schema_version":"1","error":{"code":"INVALID_REQUEST",'
        '"message":"leaked internal detail"}}'
    )
    with pytest.raises(ApiContractValidationError):
        parse_error_json(payload)


def test_message_cannot_be_forged_through_the_dto() -> None:
    with pytest.raises(ApiContractValidationError):
        ApiErrorResponse(
            code=ApiErrorCode.INTERNAL_ERROR,
            message="Traceback ...",
        )


def test_error_envelope_unknown_field_rejected() -> None:
    payload = (
        '{"schema_version":"1","error":{"code":"INVALID_REQUEST",'
        '"message":"Request validation failed","details":{"sql":"select 1"}}}'
    )
    with pytest.raises(ApiContractValidationError):
        parse_error_json(payload)


def test_error_requires_known_schema_version() -> None:
    payload = (
        '{"schema_version":"2","error":{"code":"INVALID_REQUEST",'
        '"message":"Request validation failed"}}'
    )
    with pytest.raises(ApiContractValidationError):
        parse_error_json(payload)


def test_error_code_must_be_an_enum_value() -> None:
    with pytest.raises(ApiContractValidationError):
        ApiErrorResponse(
            code="INVALID_REQUEST",  # type: ignore[arg-type]
            message="Request validation failed",
        )


@pytest.mark.parametrize("request_id", [1, "", "x" * 257, "bad\x01"])
def test_error_request_id_strictness(request_id: object) -> None:
    with pytest.raises(ApiContractValidationError):
        ApiErrorResponse(
            code=ApiErrorCode.INVALID_REQUEST,
            message=ERROR_MESSAGES[ApiErrorCode.INVALID_REQUEST],
            request_id=request_id,  # type: ignore[arg-type]
        )
