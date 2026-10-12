"""Pure response-conformance tests (plan matrix A17-A19, A27)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from mtmf_api import (
    ActionDecision,
    ActionRequest,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    AuthorizationEffect,
    DecisionReason,
    ResourceKind,
    ResourceTarget,
    ResponseConformanceError,
    validate_response_for_request,
)
from mtmf_api import conformance as conformance_module

ACTION = "urn:mtmf:iam:actions:system:document:read-object"
TENANT = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT = UUID("33333333-3333-4333-8333-333333333333")
ORGANIZATION = UUID("22222222-2222-4222-8222-222222222222")
_ISSUED = datetime(2026, 10, 11, 20, 0, 0, tzinfo=UTC)


def _request(*request_ids: str, organization: UUID | None = None) -> AuthorizationBatchRequest:
    return AuthorizationBatchRequest(
        tenant_id=TENANT,
        organization_id=organization,
        actions=tuple(
            ActionRequest(
                request_id=request_id,
                action=ACTION,
                resource=ResourceTarget(kind=ResourceKind.CAPABILITY),
            )
            for request_id in request_ids
        ),
    )


def _response(
    *decisions: tuple[str, AuthorizationEffect, DecisionReason],
    tenant: UUID = TENANT,
    organization: UUID | None = None,
) -> AuthorizationBatchResponse:
    return AuthorizationBatchResponse(
        tenant_id=tenant,
        organization_id=organization,
        issued_at=_ISSUED,
        expires_at=_ISSUED + timedelta(seconds=60),
        decisions=tuple(
            ActionDecision(request_id=request_id, effect=effect, reason=reason)
            for request_id, effect, reason in decisions
        ),
    )


ALLOW = (AuthorizationEffect.ALLOW, DecisionReason.PERMITTED)
DENY = (AuthorizationEffect.DENY, DecisionReason.NO_PERMISSION)


def test_a17_duplicate_actions_correlate_distinctly() -> None:
    request = _request("check-1", "check-2")
    response = _response(("check-1", *ALLOW), ("check-2", *ALLOW))
    validate_response_for_request(request, response)


@pytest.mark.parametrize(
    "response",
    [
        _response(("check-1", *ALLOW)),  # missing
        _response(("check-1", *ALLOW), ("check-2", *ALLOW), ("check-3", *ALLOW)),  # extra
        _response(("check-2", *ALLOW), ("check-1", *ALLOW)),  # reordered
        _response(("check-1", *ALLOW), ("check-1", *ALLOW)),  # duplicate
        _response(("check-1", *ALLOW), ("unknown", *ALLOW)),  # mismatched id
    ],
)
def test_a18_decision_correlation_violations_rejected(
    response: AuthorizationBatchResponse,
) -> None:
    request = _request("check-1", "check-2")
    with pytest.raises(ResponseConformanceError):
        validate_response_for_request(request, response)


def test_a19_tenant_mismatch_rejected() -> None:
    request = _request("check-1")
    response = _response(("check-1", *ALLOW), tenant=OTHER_TENANT)
    with pytest.raises(ResponseConformanceError):
        validate_response_for_request(request, response)


def test_a19_organization_mismatch_rejected() -> None:
    request = _request("check-1", organization=ORGANIZATION)
    response = _response(("check-1", *ALLOW), organization=None)
    with pytest.raises(ResponseConformanceError):
        validate_response_for_request(request, response)


def test_a27_conformance_is_pure_and_cannot_mint_policy() -> None:
    request = _request("check-1")
    response = _response(("check-1", *ALLOW))
    assert validate_response_for_request(request, response) is None
    for forbidden in ("evaluate", "authorize", "ALLOW", "Policy", "Authorizer"):
        assert not hasattr(conformance_module, forbidden)
