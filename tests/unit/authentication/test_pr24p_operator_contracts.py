"""PR 24P operator contract validation tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from helpers import make_id

from mtmf_core.authentication.contracts import (
    ExternalSubjectKey,
    ServiceCredentialKey,
    VerifiedPreTenantSubject,
)
from mtmf_core.authentication.operator_contracts import (
    APPROVED_SYSTEM_OPERATOR_ROLE_URN,
    GlobalApplicationTarget,
    GlobalEntitlementTarget,
    SystemOperatorAssignmentFacts,
    VerifiedPreTenantAdmission,
    VerifiedSystemOperator,
)
from mtmf_core.domain.identity import DomainId


def _operator() -> VerifiedSystemOperator:
    now = datetime.now(UTC)
    return VerifiedSystemOperator(
        issuer="issuer",
        subject="subject",
        identity_id=make_id(),
        principal_id=make_id(),
        user_token_expires_at=now + timedelta(minutes=5),
        verified_at=now,
    )


def test_operator_rejects_service_class_and_nil_ids() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError):
        VerifiedSystemOperator("i", "s", make_id(), make_id(), now, now, "service")
    with pytest.raises(ValueError):
        VerifiedSystemOperator("i", "s", DomainId(UUID(int=0)), make_id(), now, now)


def test_targets_reject_nil_ids() -> None:
    with pytest.raises(ValueError):
        GlobalApplicationTarget(DomainId(UUID(int=0)))
    with pytest.raises(ValueError):
        GlobalEntitlementTarget(make_id(), DomainId(UUID(int=0)))


def test_assignment_requires_approved_active_role() -> None:
    operator = _operator()
    with pytest.raises(ValueError):
        SystemOperatorAssignmentFacts(
            make_id(), operator.identity_id, operator.principal_id, "other", 1
        )
    with pytest.raises(ValueError):
        SystemOperatorAssignmentFacts(
            make_id(),
            operator.identity_id,
            operator.principal_id,
            APPROVED_SYSTEM_OPERATOR_ROLE_URN,
            2,
        )
    facts = SystemOperatorAssignmentFacts(
        make_id(),
        operator.identity_id,
        operator.principal_id,
        APPROVED_SYSTEM_OPERATOR_ROLE_URN,
        1,
    )
    assert facts.role_urn == APPROVED_SYSTEM_OPERATOR_ROLE_URN


def test_admission_result_requires_entitlement_for_candidate() -> None:
    now = datetime.now(UTC)
    subject = VerifiedPreTenantSubject(
        application_id=make_id(),
        service_credential=ServiceCredentialKey("i", "c"),
        external_subject=ExternalSubjectKey("i", "s"),
        verified_at=now,
        user_token_expires_at=now + timedelta(minutes=1),
        existing_identity_id=None,
        existing_principal_id=None,
    )
    result = VerifiedPreTenantAdmission(subject, make_id(), True, now)
    assert result.eligible_for_first_tenant
    with pytest.raises(ValueError):
        VerifiedPreTenantAdmission(subject, None, True, now)
