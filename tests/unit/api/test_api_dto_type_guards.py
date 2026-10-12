"""Constructor-level type/defensive validation tests (strictness guards).

These complement the matrix tests by exercising the rejection branches of
the DTO constructors and codec field parsers directly.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from mtmf_api import (
    ActionDecision,
    ActionRequest,
    ApiContractValidationError,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    ResourceKind,
    ResourceTarget,
    ensure_utc,
    parse_request_json,
    parse_response_json,
)

ACTION = "urn:mtmf:iam:actions:system:document:read-object"
TENANT = UUID("11111111-1111-4111-8111-111111111111")
ISSUED = datetime(2026, 10, 11, 20, 0, 0, tzinfo=UTC)


def _capability() -> ResourceTarget:
    return ResourceTarget(kind=ResourceKind.CAPABILITY)


def _allow() -> ActionDecision:
    return ActionDecision("check-1", AuthorizationEffect.ALLOW, DecisionReason.PERMITTED)


@pytest.mark.parametrize(
    "request_id",
    [1, "", "x" * 65, "chèck", "check\x01", "check 1"],
)
def test_request_id_strictness(request_id: object) -> None:
    with pytest.raises(ApiContractValidationError):
        ActionRequest(request_id=request_id, action=ACTION, resource=_capability())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "action",
    [
        1,
        ACTION + "x" * 300,
        "urn:mtmf:iam:actions:system:documént:read-object",
        "urn:mtmf:iam:actions:system:document:read object",
    ],
)
def test_action_strictness(action: object) -> None:
    with pytest.raises(ApiContractValidationError):
        ActionRequest(request_id="check-1", action=action, resource=_capability())  # type: ignore[arg-type]


def test_action_request_rejects_non_resource_target() -> None:
    with pytest.raises(ApiContractValidationError):
        ActionRequest(request_id="check-1", action=ACTION, resource="capability")  # type: ignore[arg-type]


def test_resource_target_type_guards() -> None:
    with pytest.raises(ApiContractValidationError):
        ResourceTarget(kind="capability")  # type: ignore[arg-type]
    with pytest.raises(ApiContractValidationError):
        ResourceTarget(kind=ResourceKind.CAPABILITY, resource_type="document")
    with pytest.raises(ApiContractValidationError):
        ResourceTarget(kind=ResourceKind.APPLICATION_OWNED, resource_type="document")
    with pytest.raises(ApiContractValidationError):
        ResourceTarget(kind=ResourceKind.MTMF_OWNED, resource_type="organization")


def test_batch_request_type_guards() -> None:
    action = ActionRequest("check-1", ACTION, _capability())
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchRequest(
            tenant_id=TENANT,
            organization_id=None,
            actions=[action],  # type: ignore[arg-type]
        )
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchRequest(
            tenant_id=TENANT,
            organization_id=None,
            actions=("not-an-action",),  # type: ignore[arg-type]
        )
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchRequest(
            tenant_id=TENANT,
            organization_id=UUID(int=0),
            actions=(action,),
        )


def test_decision_type_guards() -> None:
    with pytest.raises(ApiContractValidationError):
        ActionDecision("check-1", "ALLOW", DecisionReason.PERMITTED)  # type: ignore[arg-type]
    with pytest.raises(ApiContractValidationError):
        ActionDecision("check-1", AuthorizationEffect.ALLOW, "PERMITTED")  # type: ignore[arg-type]
    with pytest.raises(ApiContractValidationError):
        ActionDecision("check-1", AuthorizationEffect.ALLOW, DecisionReason.NO_PERMISSION)


def test_response_type_guards() -> None:
    expires = ISSUED + timedelta(seconds=60)
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchResponse(TENANT, None, ISSUED, expires, (_allow(),), schema_version="2")
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchResponse(TENANT, None, ISSUED, expires, ())
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchResponse(
            TENANT,
            None,
            ISSUED,
            expires,
            [_allow()],  # type: ignore[arg-type]
        )
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchResponse(
            TENANT,
            None,
            ISSUED,
            expires,
            ("not-a-decision",),  # type: ignore[arg-type]
        )
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchResponse(TENANT, None, "issued", expires, (_allow(),))  # type: ignore[arg-type]
    with pytest.raises(ApiContractValidationError):
        AuthorizationBatchResponse(
            TENANT,
            None,
            datetime(2026, 10, 11, 20, 0, 0),
            expires,
            (_allow(),),
        )


def test_ensure_utc_normalizes_and_validates() -> None:
    assert ensure_utc(ISSUED) == ISSUED
    with pytest.raises(ApiContractValidationError):
        ensure_utc(datetime(2026, 10, 11, 20, 0, 0))  # type: ignore[arg-type]


def test_nested_json_depth_is_bounded() -> None:
    payload = '{"a":' * 10 + "1" + "}" * 10
    with pytest.raises(ApiContractValidationError):
        parse_request_json(payload)


@pytest.mark.parametrize(
    "resource",
    [
        '{"kind":"application_owned","type":7,"id":"x"}',
        '{"kind":"application_owned","type":"x","id":7}',
    ],
)
def test_resource_field_type_guards_via_parser(resource: str) -> None:
    payload = (
        '{"tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"actions":[{"request_id":"check-1","action":"'
        + ACTION
        + '","resource":'
        + resource
        + "}]}"
    )
    with pytest.raises(ApiContractValidationError):
        parse_request_json(payload)


def test_response_timestamp_type_guard_via_parser() -> None:
    payload = (
        '{"schema_version":"1","tenant_id":"11111111-1111-4111-8111-111111111111",'
        '"organization_id":null,"issued_at":7,"expires_at":"2026-10-11T20:01:00Z",'
        '"decisions":[{"request_id":"check-1","effect":"ALLOW","reason":"PERMITTED"}]}'
    )
    with pytest.raises(ApiContractValidationError):
        parse_response_json(payload)
