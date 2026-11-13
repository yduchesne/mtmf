"""PR 24P admission mapping and fail-closed tests."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta

import pytest
from helpers import make_id

from mtmf_core.application.pre_tenant_admission import (
    AdmissionError,
    AdmissionFailure,
    AdmissionOutcome,
    PreTenantAdmissionService,
)
from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    ExternalSubjectKey,
    ServiceCredentialKey,
    VerifiedPreTenantSubject,
)


class _Verifier:
    def __init__(self, existing: bool = False, failure: bool = False) -> None:
        self._existing = existing
        self._failure = failure

    def verify(
        self, *, service_token: str, user_token: str, at: datetime
    ) -> VerifiedPreTenantSubject:
        if self._failure:
            raise AuthenticationError(AuthenticationFailure.INVALID_TOKEN)
        identity = make_id() if self._existing else None
        principal = make_id() if self._existing else None
        return VerifiedPreTenantSubject(
            application_id=make_id(),
            service_credential=ServiceCredentialKey("issuer", "client"),
            external_subject=ExternalSubjectKey("issuer", "subject"),
            verified_at=at,
            user_token_expires_at=at + timedelta(minutes=1),
            existing_identity_id=identity,
            existing_principal_id=principal,
        )


class _Reader:
    def __init__(self, payload: Mapping[str, object]) -> None:
        self.payload = payload

    def read(self, application_id: object, issuer: str, subject: str) -> Mapping[str, object]:
        return self.payload


def _payload(
    history: str, entitlement: str | None = None, quota: bool = False
) -> dict[str, object]:
    return {
        "v": 1,
        "subject_history": history,
        "entitlement_id": entitlement,
        "quota_available": quota,
    }


def test_candidate_and_existing_and_no_entitlement() -> None:
    service = PreTenantAdmissionService(
        verifier=_Verifier(), reader=_Reader(_payload("NEVER_SEEN", str(make_id()), True))
    )
    result = service.prepare(service_token="s", user_token="u")
    assert result.outcome is AdmissionOutcome.CANDIDATE
    assert result.eligible_for_first_tenant and result.entitlement_id is not None

    service = PreTenantAdmissionService(
        verifier=_Verifier(existing=True), reader=_Reader(_payload("ACTIVE"))
    )
    assert (
        service.prepare(service_token="s", user_token="u").outcome
        is AdmissionOutcome.EXISTING_SUBJECT
    )

    service = PreTenantAdmissionService(
        verifier=_Verifier(), reader=_Reader(_payload("NEVER_SEEN"))
    )
    assert (
        service.prepare(service_token="s", user_token="u").outcome
        is AdmissionOutcome.NO_ENTITLEMENT
    )


@pytest.mark.parametrize("history", ["REVOKED_ONLY", "CONFLICT"])
def test_revoked_or_conflict_history_is_opaque_conflict(history: str) -> None:
    service = PreTenantAdmissionService(verifier=_Verifier(), reader=_Reader(_payload(history)))
    with pytest.raises(AdmissionError) as exc:
        service.prepare(service_token="s", user_token="u")
    assert exc.value.failure is AdmissionFailure.CONFLICT


def test_existing_subject_with_never_seen_is_conflict_and_bad_payload_unavailable() -> None:
    service = PreTenantAdmissionService(
        verifier=_Verifier(existing=True), reader=_Reader(_payload("NEVER_SEEN"))
    )
    with pytest.raises(AdmissionError) as exc:
        service.prepare(service_token="s", user_token="u")
    assert exc.value.failure is AdmissionFailure.CONFLICT
    service = PreTenantAdmissionService(
        verifier=_Verifier(), reader=_Reader({"v": 1, "subject_history": "ACTIVE"})
    )
    with pytest.raises(AdmissionError) as exc:
        service.prepare(service_token="s", user_token="u")
    assert exc.value.failure is AdmissionFailure.UNAVAILABLE


def test_verification_failure_maps_without_reader_call() -> None:
    service = PreTenantAdmissionService(
        verifier=_Verifier(failure=True), reader=_Reader(_payload("ACTIVE"))
    )
    with pytest.raises(AdmissionError) as exc:
        service.prepare(service_token="s", user_token="u")
    assert exc.value.failure is AdmissionFailure.UNAUTHENTICATED
