"""Strict detached DTO/codec tests for the PR 19C management request."""

from __future__ import annotations

import json
from uuid import UUID

import pytest

from mtmf_api.errors import ApiContractValidationError
from mtmf_api.json_codec import (
    parse_membership_add_json,
    serialize_membership_add_response,
)
from mtmf_api.management import (
    IdentityGroupMembershipAddRequest,
    IdentityGroupMembershipAddResponse,
)

TENANT = "00000000-0000-4000-8000-000000000001"
IDENTITY = "00000000-0000-4000-8000-000000000002"
GROUP = "00000000-0000-4000-8000-000000000003"

_NIL = "00000000-0000-0000-0000-000000000000"


def _canonical() -> str:
    return json.dumps({"tenant_id": TENANT, "identity_id": IDENTITY, "group_id": GROUP})


def test_uh01_canonical_request_parses_to_detached_dto() -> None:
    request = parse_membership_add_json(_canonical())
    assert request == IdentityGroupMembershipAddRequest(
        tenant_id=UUID(TENANT), identity_id=UUID(IDENTITY), group_id=UUID(GROUP)
    )


def test_uh01_response_serializes_canonically() -> None:
    response = IdentityGroupMembershipAddResponse(
        tenant_id=UUID(TENANT), identity_id=UUID(IDENTITY), group_id=UUID(GROUP), created=True
    )
    assert serialize_membership_add_response(response) == (
        f'{{"tenant_id":"{TENANT}","identity_id":"{IDENTITY}","group_id":"{GROUP}","created":true}}'
    )


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps({"tenant_id": TENANT, "identity_id": IDENTITY}),
        json.dumps({"tenant_id": TENANT, "identity_id": IDENTITY, "group_id": GROUP, "x": 1}),
        (
            f'{{"tenant_id":"{TENANT}","identity_id":"{IDENTITY}",'
            f'"group_id":"{GROUP}","group_id":"{GROUP}"}}'
        ),
        json.dumps({"tenant_id": TENANT, "identity_id": IDENTITY, "group_id": "not-a-uuid"}),
        json.dumps(
            {
                "tenant_id": "ABCDEF01-0000-4000-8000-00000000000A",
                "identity_id": IDENTITY,
                "group_id": GROUP,
            }
        ),
        json.dumps({"tenant_id": _NIL, "identity_id": IDENTITY, "group_id": GROUP}),
        json.dumps({"tenant_id": 123, "identity_id": IDENTITY, "group_id": GROUP}),
        json.dumps({"tenant_id": TENANT, "identity_id": IDENTITY, "group_id": [GROUP]}),
        "[]",
        "not-json",
    ],
)
def test_uh02_uh03_invalid_request_rejected(raw: str) -> None:
    with pytest.raises(ApiContractValidationError):
        parse_membership_add_json(raw)


def test_uh03_invalid_utf8_rejected() -> None:
    with pytest.raises(ApiContractValidationError):
        parse_membership_add_json(b"\xff\xfe")
