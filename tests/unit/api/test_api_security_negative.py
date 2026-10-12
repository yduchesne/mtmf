"""Security-focused negative assertions for the detached contract.

These tests exercise the *security* invariants of the DTO boundary, not
merely happy-path shape: no caller-supplied identity is authority, no
missing/unknown value defaults to ALLOW, and no internal detail leaks
through the public error catalog.
"""

from __future__ import annotations

import pytest

from mtmf_api import (
    ERROR_MESSAGES,
    ApiContractValidationError,
    ApiErrorCode,
    ApiErrorResponse,
    AuthorizationBatchRequest,
    parse_error_json,
    parse_request_json,
    serialize_error,
)

_IDENTITY_FIELDS = (
    "application_id",
    "principal_id",
    "identity_id",
    "client_id",
    "service_token",
    "user_token",
    "is_root",
    "roles",
    "permissions",
    "allowed",
)


@pytest.mark.parametrize("field", _IDENTITY_FIELDS)
def test_no_caller_supplied_identity_is_accepted(field: str) -> None:
    payload = (
        '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"actions":[{"request_id":"check-1",'
        '"action":"urn:mtmf:iam:actions:system:document:read-object",'
        '"resource":{"kind":"capability"}}],'
        f'"{field}":"forged"}}'
    )
    with pytest.raises(ApiContractValidationError):
        parse_request_json(payload)


def test_request_dto_exposes_no_identity_authority() -> None:
    fields = set(AuthorizationBatchRequest.__dataclass_fields__)
    assert fields == {"tenant_id", "organization_id", "actions"}
    for field in _IDENTITY_FIELDS:
        assert field not in fields


def test_no_missing_or_unknown_decision_defaults_to_allow() -> None:
    # A response with an unknown effect/reason never becomes ALLOW.
    payload = (
        '{"schema_version":"1","tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"organization_id":null,"issued_at":"2026-10-11T20:00:00Z",'
        '"expires_at":"2026-10-11T20:01:00Z",'
        '"decisions":[{"request_id":"check-1","effect":"UNKNOWN","reason":"PERMITTED"}]}'
    )
    with pytest.raises(ApiContractValidationError):
        from mtmf_api import parse_response_json

        parse_response_json(payload)

    # A decision that omits the effect entirely never becomes ALLOW.
    missing = (
        '{"schema_version":"1","tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"organization_id":null,"issued_at":"2026-10-11T20:00:00Z",'
        '"expires_at":"2026-10-11T20:01:00Z",'
        '"decisions":[{"request_id":"check-1","reason":"PERMITTED"}]}'
    )
    with pytest.raises(ApiContractValidationError):
        from mtmf_api import parse_response_json as prs

        prs(missing)


@pytest.mark.parametrize("code", list(ApiErrorCode))
def test_error_messages_disclose_no_internal_detail(code: ApiErrorCode) -> None:
    message = ERROR_MESSAGES[code]
    lowered = message.lower()
    for forbidden in ("traceback", "sql", "select ", "token", "secret", "jwks", "password"):
        assert forbidden not in lowered


def test_error_serialization_has_no_extra_keys() -> None:
    import json

    payload = serialize_error(ApiErrorResponse.for_code(ApiErrorCode.INVALID_REQUEST))
    body = json.loads(payload)
    assert set(body) == {"schema_version", "error"}
    assert set(body["error"]) == {"code", "message"}


def test_error_parser_rejects_sql_or_policy_detail() -> None:
    payload = (
        '{"schema_version":"1","error":{"code":"INTERNAL_ERROR",'
        '"message":"An unexpected internal error occurred","matched_policy":"role-x"}}'
    )
    with pytest.raises(ApiContractValidationError):
        parse_error_json(payload)
