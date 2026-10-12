"""Shared fixtures and helpers for the mtmf-api unit tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
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
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

ACTION = "urn:mtmf:iam:actions:system:document:read-object"
UNKNOWN_ACTION = "urn:mtmf:iam:actions:system:document:frobnicate-all"
TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
ORGANIZATION_ID = UUID("22222222-2222-4222-8222-222222222222")


@pytest.fixture
def read_fixture() -> object:
    """Return a loader for checked-in fixture text."""

    def _load(name: str) -> str:
        return (FIXTURE_DIR / name).read_text(encoding="utf-8")

    return _load


@pytest.fixture
def valid_request() -> AuthorizationBatchRequest:
    """A minimal detached request DTO."""
    return AuthorizationBatchRequest(
        tenant_id=TENANT_ID,
        organization_id=None,
        actions=(
            ActionRequest(
                request_id="check-1",
                action=ACTION,
                resource=ResourceTarget(kind=ResourceKind.CAPABILITY),
            ),
        ),
    )


@pytest.fixture
def valid_response() -> AuthorizationBatchResponse:
    """A minimal detached response DTO with a positive TTL."""
    issued = datetime(2026, 10, 11, 20, 0, 0, tzinfo=UTC)
    return AuthorizationBatchResponse(
        tenant_id=TENANT_ID,
        organization_id=None,
        issued_at=issued,
        expires_at=issued + timedelta(seconds=60),
        decisions=(
            ActionDecision(
                request_id="check-1",
                effect=AuthorizationEffect.ALLOW,
                reason=DecisionReason.PERMITTED,
            ),
        ),
    )
