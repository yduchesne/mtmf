"""Detached DTO validation tests (plan matrix A01-A05, A07, A11-A20, A28)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from mtmf_api import (
    SNAPSHOT_MAX_TTL,
    ActionDecision,
    ActionRequest,
    ApiContractValidationError,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    ResourceKind,
    ResourceTarget,
    parse_request_json,
    serialize_request,
    serialize_response,
    validate_action_urn,
)

ACTION = "urn:mtmf:iam:actions:system:document:read-object"
TENANT = UUID("11111111-1111-4111-8111-111111111111")
ORGANIZATION = UUID("22222222-2222-4222-8222-222222222222")


def _action(request_id: str, *, action: str = ACTION) -> ActionRequest:
    return ActionRequest(
        request_id=request_id,
        action=action,
        resource=ResourceTarget(kind=ResourceKind.CAPABILITY),
    )


def _request(
    *actions: ActionRequest, organization: UUID | None = None
) -> AuthorizationBatchRequest:
    return AuthorizationBatchRequest(
        tenant_id=TENANT,
        organization_id=organization,
        actions=actions,
    )


def _response(*decisions: ActionDecision, ttl_seconds: int = 60) -> AuthorizationBatchResponse:
    issued = datetime(2026, 10, 11, 20, 0, 0, tzinfo=UTC)
    return AuthorizationBatchResponse(
        tenant_id=TENANT,
        organization_id=None,
        issued_at=issued,
        expires_at=issued + timedelta(seconds=ttl_seconds),
        decisions=decisions,
    )


# --- A01/A02: valid Tenant and Organization batches -----------------------
def test_a01_minimal_valid_request_round_trips(read_fixture: object) -> None:
    request = parse_request_json(read_fixture("request_minimal.json"))  # type: ignore[operator]
    assert request.tenant_id == TENANT
    assert request.organization_id is None
    assert len(request.actions) == 1
    canonical = serialize_request(request)
    assert serialize_request(parse_request_json(canonical)) == canonical


def test_a02_organization_selector_is_preserved(read_fixture: object) -> None:
    request = parse_request_json(read_fixture("request_organization.json"))  # type: ignore[operator]
    assert request.organization_id == ORGANIZATION
    assert "22222222-2222-4222-8222-222222222222" in serialize_request(request)


# --- A03: batch bounds ----------------------------------------------------
def test_a03_one_and_one_hundred_entries_accepted() -> None:
    assert len(_request(_action("check-1")).actions) == 1
    many = tuple(_action(f"check-{index}") for index in range(100))
    assert len(_request(*many).actions) == 100


def test_a03_zero_and_101_entries_rejected() -> None:
    with pytest.raises(ApiContractValidationError):
        _request()
    with pytest.raises(ApiContractValidationError):
        _request(*(_action(f"check-{index}") for index in range(101)))


# --- A04/A05: duplicate actions and duplicate correlation ids -------------
def test_a04_duplicate_actions_with_distinct_ids_are_retained(read_fixture: object) -> None:
    request = parse_request_json(read_fixture("request_duplicate_actions.json"))  # type: ignore[operator]
    assert [action.request_id for action in request.actions] == ["check-1", "check-2"]
    assert request.actions[0].action == request.actions[1].action


def test_a05_duplicate_request_id_is_rejected() -> None:
    with pytest.raises(ApiContractValidationError):
        _request(_action("check-1"), _action("check-1"))


# --- A06/A07: exact Action grammar, no wildcards --------------------------
def test_action_urn_grammar_mirrors_core() -> None:
    assert validate_action_urn(ACTION) == ACTION
    for bad in (
        "document.read",
        "urn:mtmf:iam:actions:system:document:*",
        "urn:mtmf:iam:actions:system:document:read-*",
        "urn:mtmf:iam:actions:tenant:1111:document:read-object",
        "urn:mtmf:iam:permissions:system:document:read-object",
        "urn:mtmf:iam:actions:system:document:read",
        "urn:mtmf:iam:actions:system:document",
        "urn:mtmf:iam:actions:system::read-object",
        "urn:mtmf:iam:actions:system:document:-object",
    ):
        with pytest.raises(ApiContractValidationError):
            validate_action_urn(bad)


def test_a07_wildcard_action_is_rejected(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(read_fixture("invalid_wildcard_action.json"))  # type: ignore[operator]


# --- A08/A11: identity authority and UUIDs --------------------------------
def test_a08_unknown_identity_fields_are_rejected(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(read_fixture("invalid_unknown_field.json"))  # type: ignore[operator]


def test_a11_nil_and_uppercase_uuid_rejected(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(read_fixture("invalid_nil_uuid.json"))  # type: ignore[operator]
    with pytest.raises(ApiContractValidationError):
        parse_request_json(read_fixture("invalid_uppercase_uuid.json"))  # type: ignore[operator]


def test_a11_wrong_types_rejected() -> None:
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchRequest(
            tenant_id="not-a-uuid",  # type: ignore[arg-type]
            organization_id=None,
            actions=(_action("check-1"),),
        )
    with pytest.raises(ApiContractValidationError):
        parse_request_json('{"tenant_id": 7, "actions": []}')


# --- A12/A13/A14: resource union ------------------------------------------
def test_a12_capability_with_id_rejected(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(read_fixture("invalid_resource_extra_field.json"))  # type: ignore[operator]


def test_a12_unknown_resource_kind_rejected() -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(
            '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
            '"actions":[{"request_id":"check-1","action":"' + ACTION + '",'
            '"resource":{"kind":"unowned"}}]}'
        )


def test_a13_application_owned_requires_type_and_id(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_request_json(read_fixture("invalid_application_owned_missing_type.json"))  # type: ignore[operator]


def test_a14_mtmf_owned_requires_qualifiers() -> None:
    request = parse_request_json(
        '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"actions":[{"request_id":"check-1",'
        '"action":"urn:mtmf:iam:actions:system:organization:get-object",'
        '"resource":{"kind":"mtmf_owned","type":"organization",'
        '"id":"22222222-2222-4222-8222-222222222222"}}]}'
    )
    resource = request.actions[0].resource
    assert resource.kind is ResourceKind.MTMF_OWNED
    assert resource.resource_type == "organization"
    with pytest.raises(ApiContractValidationError):
        parse_request_json(
            '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
            '"actions":[{"request_id":"check-1","action":"' + ACTION + '",'
            '"resource":{"kind":"mtmf_owned","type":"organization"}}]}'
        )


# --- A15/A16: decision effect/reason combinations -------------------------
def test_a15_allow_permitted_and_deny_no_permission_accepted() -> None:
    response = _response(
        ActionDecision("check-1", AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
        ActionDecision("check-2", AuthorizationEffect.DENY, DecisionReason.NO_PERMISSION),
    )
    assert [decision.effect for decision in response.decisions] == [
        AuthorizationEffect.ALLOW,
        AuthorizationEffect.DENY,
    ]


def test_a16_effect_reason_mismatches_rejected(read_fixture: object) -> None:
    for name in ("invalid_allow_reason.json", "invalid_deny_permitted.json"):
        with pytest.raises(ApiContractValidationError):
            from mtmf_api import parse_response_json

            parse_response_json(read_fixture(name))  # type: ignore[operator]


def test_a16_unknown_effect_and_reason_rejected() -> None:
    from mtmf_api import parse_response_json

    base = (
        '{"schema_version":"1","tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"organization_id":null,"issued_at":"2026-10-11T20:00:00Z",'
        '"expires_at":"2026-10-11T20:01:00Z","decisions":[%s]}'
    )
    for entry in (
        '{"request_id":"check-1","effect":"ABSTAIN","reason":"PERMITTED"}',
        '{"request_id":"check-1","effect":"ALLOW","reason":"UNKNOWN"}',
    ):
        with pytest.raises(ApiContractValidationError):
            parse_response_json(base % entry)


# --- A20: UTC timestamps and TTL bounds -----------------------------------
def test_a20_valid_ttl_accepted() -> None:
    assert _response(
        ActionDecision("check-1", AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
        ttl_seconds=300,
    )


@pytest.mark.parametrize("ttl_seconds", [0, -5, 301])
def test_a20_invalid_ttl_rejected(ttl_seconds: int) -> None:
    with pytest.raises(ApiContractValidationError):
        _response(
            ActionDecision("check-1", AuthorizationEffect.ALLOW, DecisionReason.PERMITTED),
            ttl_seconds=ttl_seconds,
        )


def test_a20_non_utc_timestamp_rejected(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        from mtmf_api import parse_response_json

        parse_response_json(read_fixture("invalid_bad_timestamp.json"))  # type: ignore[operator]


def test_a20_overlong_ttl_fixture_rejected(read_fixture: object) -> None:
    with pytest.raises(ApiContractValidationError):
        from mtmf_api import parse_response_json

        parse_response_json(read_fixture("invalid_overlong_ttl.json"))  # type: ignore[operator]


def test_max_ttl_constant_matches_approved_decision() -> None:
    assert timedelta(seconds=300) == SNAPSHOT_MAX_TTL


# --- A28: stable serialization --------------------------------------------
def test_a28_serialization_is_byte_identical(
    valid_request: AuthorizationBatchRequest,
    valid_response: AuthorizationBatchResponse,
) -> None:
    assert serialize_request(valid_request) == serialize_request(valid_request)
    assert serialize_response(valid_response) == serialize_response(valid_response)
