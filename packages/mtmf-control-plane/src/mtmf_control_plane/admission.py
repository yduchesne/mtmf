"""Private test-only pre-Tenant admission handler."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from mtmf_core.application.pre_tenant_admission import (
    AdmissionError,
    AdmissionFailure,
    AdmissionReadPort,
    PreTenantAdmissionService,
)
from mtmf_core.authentication.contracts import AuthenticationError

from .protocol import ProtocolError, canonical_uuid, decode_admission_request

__all__ = ["AdmissionHandler"]


class _ReadAdapter(AdmissionReadPort):
    def __init__(self, database: Any) -> None:
        self._database = database

    def read(self, application_id: Any, issuer: str, subject: str) -> Mapping[str, object]:
        return cast(
            Mapping[str, object],
            self._database.admission_read(
                application_id=application_id.value, issuer=issuer, subject=subject
            ),
        )


class AdmissionHandler:
    """Handle only admission.prepare and return the bounded non-authorizing result."""

    def __init__(self, *, verifier: Any, database: Any) -> None:
        self._handler = PreTenantAdmissionService(verifier=verifier, reader=_ReadAdapter(database))

    def handle(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        request_id = payload.get("request_id")
        try:
            request = decode_admission_request(payload)
            result = self._handler.prepare(
                service_token=str(request.fields["service_access_token"]),
                user_token=str(request.fields["user_access_token"]),
            )
            return {
                "v": 1,
                "request_id": str(request.operation_id),
                "outcome": result.outcome.value,
                "eligible_for_first_tenant": result.eligible_for_first_tenant,
                "application_id": str(result.application_id),
                "entitlement_id": (
                    None if result.entitlement_id is None else str(result.entitlement_id)
                ),
            }
        except AdmissionError as exc:
            return _error(request_id, exc.failure.value)
        except AuthenticationError:
            return _error(request_id, AdmissionFailure.UNAUTHENTICATED.value)
        except ProtocolError, ValueError:
            return _error(request_id, AdmissionFailure.INVALID.value)
        except Exception:
            return _error(request_id, AdmissionFailure.UNAVAILABLE.value)


def _error(request_id: object, error: str) -> Mapping[str, Any]:
    try:
        value: str | None = str(canonical_uuid(request_id, "request_id"))
    except ProtocolError:
        value = None
    return {"v": 1, "request_id": value, "error": error}
