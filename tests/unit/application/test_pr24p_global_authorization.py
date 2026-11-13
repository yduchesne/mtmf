"""PR 24P global SYSTEM authorization and snapshot parsing tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from helpers import make_action_urn, make_id, make_permission, make_role

from mtmf_core.application.global_operator_authorization import (
    GlobalAuthorizationSnapshotError,
    parse_global_authorization_snapshot,
)
from mtmf_core.authentication.operator_contracts import (
    APPROVED_SYSTEM_OPERATOR_ROLE_URN,
    GlobalApplicationTarget,
    VerifiedSystemOperator,
)
from mtmf_core.authorization.authorizer import Authorizer
from mtmf_core.authorization.decision import AuthorizationEffect
from mtmf_core.domain.action import Action
from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.permission import Permission
from mtmf_core.domain.permission_set import PermissionSet
from mtmf_core.domain.policy import PermissionEffect


def _role() -> object:
    urn = RoleUrn(APPROVED_SYSTEM_OPERATOR_ROLE_URN)
    set_id = make_id()
    permission = Permission(
        make_id(),
        set_id,
        make_permission(
            permission_set_id=set_id,
            resource="application-onboarding-entitlement",
            verb="grant",
            qualifier="object",
        ).urn,
    )
    permission_set = PermissionSet(set_id, urn, PermissionEffect.ALLOW, (permission,))
    return make_role(urn=urn, permission_sets=(permission_set,))


def _operator() -> VerifiedSystemOperator:
    now = datetime.now(UTC)
    return VerifiedSystemOperator(
        "issuer", "subject", make_id(), make_id(), now + timedelta(minutes=5), now
    )


def _payload(operator: VerifiedSystemOperator, role: object) -> dict[str, object]:
    return {
        "v": 1,
        "operator": {
            "identity": {
                "id": str(operator.identity_id),
                "principal_id": str(operator.principal_id),
                "origin": 2,
                "deletion_status": 2,
                "canonical_root": False,
            },
            "principal": {
                "id": str(operator.principal_id),
                "deletion_status": 2,
                "canonical_root": False,
            },
            "binding": {
                "id": str(make_id()),
                "issuer": operator.issuer,
                "subject": operator.subject,
                "identity_id": str(operator.identity_id),
                "lifecycle": 1,
            },
        },
        "assignment": {
            "id": str(make_id()),
            "identity_id": str(operator.identity_id),
            "principal_id": str(operator.principal_id),
            "role_urn": APPROVED_SYSTEM_OPERATOR_ROLE_URN,
            "state": 1,
            "created_at": "2026-11-13T00:00:00+00:00",
            "revoked_at": None,
        },
        "role": {
            "urn": APPROVED_SYSTEM_OPERATOR_ROLE_URN,
            "name": "Application Administrator",
            "description": "",
            "defining_tenant_id": None,
            "builtin": True,
            "approved_role": True,
        },
        "permission_sets": [
            {
                "id": str(role.permission_sets[0].id),
                "role_urn": APPROVED_SYSTEM_OPERATOR_ROLE_URN,
                "effect": "allow",
                "position": 0,
            }
        ],
        "permissions": [
            {
                "id": str(role.permission_sets[0].permissions[0].id),
                "permission_set_id": str(role.permission_sets[0].id),
                "urn": str(role.permission_sets[0].permissions[0].urn),
                "position": 0,
            }
        ],
        "target": {
            "kind": "APPLICATION",
            "application_id": str(make_id()),
            "entitlement_id": None,
        },
        "checked_at": "2026-11-13T00:00:00+00:00",
    }


def test_snapshot_allows_exact_global_action_and_rejects_wrong_target() -> None:
    operator = _operator()
    role = _role()
    payload = _payload(operator, role)
    action = Action(make_action_urn(resource="application-onboarding-entitlement", verb="grant"))
    request = parse_global_authorization_snapshot(payload, operator=operator, action=action)
    assert isinstance(request.target, GlobalApplicationTarget)
    decision = Authorizer().authorize_global_system(request)
    assert decision.effect is AuthorizationEffect.ALLOW
    assert decision.allowed


def test_snapshot_wrong_target_kind_denies_and_expired_proof_denies() -> None:
    operator = _operator()
    role = _role()
    payload = _payload(operator, role)
    action = Action(make_action_urn(resource="application-onboarding-entitlement", verb="revoke"))
    request = parse_global_authorization_snapshot(payload, operator=operator, action=action)
    assert not Authorizer().authorize_global_system(request).allowed
    expired = VerifiedSystemOperator(
        operator.issuer,
        operator.subject,
        operator.identity_id,
        operator.principal_id,
        datetime.now(UTC) - timedelta(seconds=1),
        datetime.now(UTC),
    )
    request2 = parse_global_authorization_snapshot(payload, operator=expired, action=action)
    assert not Authorizer().authorize_global_system(request2).allowed


def test_snapshot_rejects_unknown_fields_and_actor_mismatch() -> None:
    operator = _operator()
    payload = _payload(operator, _role())
    payload["extra"] = True
    with pytest.raises(GlobalAuthorizationSnapshotError):
        parse_global_authorization_snapshot(
            payload, operator=operator, action=Action(make_action_urn())
        )
    payload = _payload(operator, _role())
    payload["operator"]["binding"]["subject"] = "other"  # type: ignore[index]
    with pytest.raises(GlobalAuthorizationSnapshotError):
        parse_global_authorization_snapshot(
            payload, operator=operator, action=Action(make_action_urn())
        )
