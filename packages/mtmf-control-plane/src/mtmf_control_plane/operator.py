"""Private operator command handler: one verified proof, one transaction."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

import psycopg

from mtmf_core.application.global_operator_authorization import (
    GlobalAuthorizationSnapshotError,
    parse_global_authorization_snapshot,
)
from mtmf_core.application.system_operator_verification import SystemOperatorVerificationService
from mtmf_core.authentication.contracts import AuthenticationError
from mtmf_core.authentication.operator_contracts import (
    GLOBAL_OPERATION_ACTIONS,
    GlobalApplicationTarget,
    GlobalEntitlementTarget,
)
from mtmf_core.authorization.authorizer import Authorizer
from mtmf_core.domain.action import Action
from mtmf_core.domain.iam_urn import ActionUrn

from .db import ControlDatabase, ControlDatabaseError
from .fingerprint import mutation_fingerprint
from .protocol import ProtocolError, canonical_uuid, decode_operator_request

__all__ = ["OperatorHandler"]


class OperatorHandler:
    """Handle exactly the approved operator operations."""

    def __init__(
        self,
        *,
        verifier: SystemOperatorVerificationService,
        database: ControlDatabase,
        authorizer: Authorizer | None = None,
    ) -> None:
        self._verifier = verifier
        self._database = database
        self._authorizer = authorizer or Authorizer()

    def handle(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        """Return one bounded response envelope or a safe error envelope."""
        request_id = payload.get("operation_id")
        try:
            request = decode_operator_request(payload)
            if request.operation == "health.private":
                return {"v": 1, "healthy": True}
            fields = request.fields
            operator = self._verifier.verify(str(fields["operator_access_token"]))
            application_id = canonical_uuid(fields["application_id"], "application_id")
            entitlement_id = canonical_uuid(fields["entitlement_id"], "entitlement_id")
            operation = request.operation
            action_urn = GLOBAL_OPERATION_ACTIONS[operation]
            action = Action(ActionUrn(action_urn))
            snapshot_entitlement = None if operation == "entitlement.grant" else entitlement_id
            with self._database.transaction() as connection:
                snapshot = self._database.snapshot(
                    connection,
                    identity_id=operator.identity_id.value,
                    principal_id=operator.principal_id.value,
                    issuer=operator.issuer,
                    subject=operator.subject,
                    application_id=application_id,
                    entitlement_id=snapshot_entitlement,
                )
                request_facts = parse_global_authorization_snapshot(
                    snapshot, operator=operator, action=action
                )
                decision = self._authorizer.authorize_global_system(request_facts)
                if not decision.allowed:
                    raise _DeniedError
                if operator.user_token_expires_at <= datetime.now(UTC):
                    raise _DeniedError
                if operation == "entitlement.grant":
                    target = request_facts.target
                    if not isinstance(target, GlobalApplicationTarget):
                        raise _DeniedError
                    quota = fields["quota_total"]
                    if not isinstance(quota, int):
                        raise ProtocolError("quota_total must be an integer")
                    fingerprint = mutation_fingerprint(
                        operation=operation,
                        identity_id=operator.identity_id.value,
                        principal_id=operator.principal_id.value,
                        issuer=operator.issuer,
                        subject=operator.subject,
                        application_id=application_id,
                        entitlement_id=entitlement_id,
                        quota_total=quota,
                        reason=str(fields["reason"]),
                    )
                    result = self._database.grant(
                        connection,
                        identity_id=operator.identity_id.value,
                        principal_id=operator.principal_id.value,
                        issuer=operator.issuer,
                        subject=operator.subject,
                        application_id=application_id,
                        entitlement_id=entitlement_id,
                        quota_total=quota,
                        reason=str(fields["reason"]),
                        operation_id=request.operation_id,
                        fingerprint=fingerprint,
                    )
                elif operation == "entitlement.revoke":
                    if not isinstance(request_facts.target, GlobalEntitlementTarget):
                        raise _DeniedError
                    fingerprint = mutation_fingerprint(
                        operation=operation,
                        identity_id=operator.identity_id.value,
                        principal_id=operator.principal_id.value,
                        issuer=operator.issuer,
                        subject=operator.subject,
                        application_id=application_id,
                        entitlement_id=entitlement_id,
                        quota_total=None,
                        reason=str(fields["reason"]),
                    )
                    result = self._database.revoke(
                        connection,
                        identity_id=operator.identity_id.value,
                        principal_id=operator.principal_id.value,
                        issuer=operator.issuer,
                        subject=operator.subject,
                        application_id=application_id,
                        entitlement_id=entitlement_id,
                        reason=str(fields["reason"]),
                        operation_id=request.operation_id,
                        fingerprint=fingerprint,
                    )
                elif operation == "entitlement.get":
                    if not isinstance(request_facts.target, GlobalEntitlementTarget):
                        raise _DeniedError
                    result = self._database.get(
                        connection,
                        identity_id=operator.identity_id.value,
                        principal_id=operator.principal_id.value,
                        issuer=operator.issuer,
                        subject=operator.subject,
                        application_id=application_id,
                        entitlement_id=entitlement_id,
                    )
                else:
                    raise ProtocolError("unsupported operation")
            return _bounded_result(result, request.operation_id)
        except _DeniedError:
            return _error(request_id, "FORBIDDEN")
        except ProtocolError, GlobalAuthorizationSnapshotError, ValueError:
            return _error(request_id, "INVALID")
        except AuthenticationError:
            return _error(request_id, "UNAUTHENTICATED")
        except psycopg.Error as exc:
            return _error(request_id, _sqlstate_error(exc))
        except ControlDatabaseError:
            return _error(request_id, "UNAVAILABLE")
        except Exception:
            return _error(request_id, "UNAVAILABLE")


class _DeniedError(Exception):
    pass


def _sqlstate_error(exc: psycopg.Error) -> str:
    state = getattr(exc, "sqlstate", None)
    if state == "MT049":
        return "INVALID"
    if state == "MT050":
        return "FORBIDDEN"
    if state == "MT051":
        return "CONFLICT"
    return "UNAVAILABLE"


def _error(request_id: object, error: str) -> Mapping[str, Any]:
    value: str | None
    try:
        value = str(canonical_uuid(request_id, "operation_id"))
    except ProtocolError:
        value = None
    return {"v": 1, "operation_id": value, "error": error}


def _bounded_result(result: Mapping[str, object], operation_id: uuid.UUID) -> Mapping[str, Any]:
    allowed = {"v", "operation_id", "outcome", "application_id", "entitlement_id", "entitlement"}
    if set(result) - allowed:
        raise ControlDatabaseError("control result contains unexpected fields")
    output: dict[str, Any] = {
        "v": 1,
        "operation_id": str(operation_id),
        "outcome": result.get("outcome"),
    }
    for name in ("application_id", "entitlement_id", "entitlement"):
        if name in result and result[name] is not None:
            output[name] = result[name]
    return output
