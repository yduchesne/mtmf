"""Strict parser for the persisted §6A operator authorization snapshot.

The parser turns one bounded SQL JSON object into the existing internal
``Role`` aggregate and the typed global authorization request. It performs no
I/O and no policy evaluation; :meth:`Authorizer.authorize_global_system` is the
sole evaluator.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime

from mtmf_core.authentication.operator_contracts import (
    APPROVED_SYSTEM_OPERATOR_ROLE_URN,
    GlobalApplicationTarget,
    GlobalEntitlementTarget,
    GlobalSystemAuthorizationRequest,
    SystemOperatorAssignmentFacts,
    VerifiedSystemOperator,
)
from mtmf_core.domain.action import Action
from mtmf_core.domain.errors import DomainInvariantError
from mtmf_core.domain.iam_urn import PermissionUrn, RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.permission import Permission
from mtmf_core.domain.permission_set import PermissionSet
from mtmf_core.domain.policy import PermissionEffect
from mtmf_core.domain.role import Role

__all__ = ["GlobalAuthorizationSnapshotError", "parse_global_authorization_snapshot"]


class GlobalAuthorizationSnapshotError(Exception):
    """Malformed, inconsistent, or fail-closed snapshot facts."""


_SNAPSHOT_KEYS = {
    "v",
    "operator",
    "assignment",
    "role",
    "permission_sets",
    "permissions",
    "target",
    "checked_at",
}


def parse_global_authorization_snapshot(
    payload: Mapping[str, object],
    *,
    operator: VerifiedSystemOperator,
    action: Action,
) -> GlobalSystemAuthorizationRequest:
    """Parse the exact §6A snapshot into the typed request.

    :raises GlobalAuthorizationSnapshotError: on any missing, unknown,
        duplicate, malformed, or inconsistent fact. It never returns an ALLOW.
    """
    if set(payload) != _SNAPSHOT_KEYS or payload.get("v") != 1:
        raise GlobalAuthorizationSnapshotError("malformed snapshot envelope")
    operator_obj = _obj(payload.get("operator"), "operator")
    if set(operator_obj) != {"identity", "principal", "binding"}:
        raise GlobalAuthorizationSnapshotError("malformed operator facts")
    identity = _obj(operator_obj.get("identity"), "operator.identity")
    principal = _obj(operator_obj.get("principal"), "operator.principal")
    binding = _obj(operator_obj.get("binding"), "operator.binding")
    if set(identity) != {"id", "principal_id", "origin", "deletion_status", "canonical_root"}:
        raise GlobalAuthorizationSnapshotError("malformed identity facts")
    if set(principal) != {"id", "deletion_status", "canonical_root"}:
        raise GlobalAuthorizationSnapshotError("malformed principal facts")
    if set(binding) != {"id", "issuer", "subject", "identity_id", "lifecycle"}:
        raise GlobalAuthorizationSnapshotError("malformed binding facts")
    identity_id = _id(identity.get("id"), "identity.id")
    principal_id = _id(principal.get("id"), "principal.id")
    if identity.get("principal_id") != str(principal_id):
        raise GlobalAuthorizationSnapshotError("identity/principal mismatch")
    if identity.get("origin") != 2 or identity.get("deletion_status") != 2:
        raise GlobalAuthorizationSnapshotError("operator Identity is not active FEDERATED")
    if principal.get("deletion_status") != 2:
        raise GlobalAuthorizationSnapshotError("operator Principal is not active")
    if identity.get("canonical_root") is not False or principal.get("canonical_root") is not False:
        raise GlobalAuthorizationSnapshotError("canonical root is not an operator")
    if identity_id != operator.identity_id or principal_id != operator.principal_id:
        raise GlobalAuthorizationSnapshotError("snapshot actor does not match the proof")
    if binding.get("issuer") != operator.issuer or binding.get("subject") != operator.subject:
        raise GlobalAuthorizationSnapshotError("snapshot binding does not match the proof")
    if binding.get("identity_id") != str(identity_id) or binding.get("lifecycle") != 1:
        raise GlobalAuthorizationSnapshotError("snapshot binding is not active for this Identity")

    assignment = _obj(payload.get("assignment"), "assignment")
    if set(assignment) != {
        "id",
        "identity_id",
        "principal_id",
        "role_urn",
        "state",
        "created_at",
        "revoked_at",
    }:
        raise GlobalAuthorizationSnapshotError("malformed assignment facts")
    if assignment.get("identity_id") != str(identity_id) or assignment.get("principal_id") != str(
        principal_id
    ):
        raise GlobalAuthorizationSnapshotError("assignment actor mismatch")
    if (
        assignment.get("role_urn") != APPROVED_SYSTEM_OPERATOR_ROLE_URN
        or assignment.get("state") != 1
    ):
        raise GlobalAuthorizationSnapshotError("assignment is not the approved ACTIVE SYSTEM role")
    if assignment.get("revoked_at") is not None:
        raise GlobalAuthorizationSnapshotError("active assignment cannot be revoked")
    assignment_facts = SystemOperatorAssignmentFacts(
        assignment_id=_id(assignment.get("id"), "assignment.id"),
        identity_id=identity_id,
        principal_id=principal_id,
        role_urn=str(assignment["role_urn"]),
        state=1,
    )

    role_obj = _obj(payload.get("role"), "role")
    if set(role_obj) != {
        "urn",
        "name",
        "description",
        "defining_tenant_id",
        "builtin",
        "approved_role",
    }:
        raise GlobalAuthorizationSnapshotError("malformed role facts")
    if (
        role_obj.get("urn") != APPROVED_SYSTEM_OPERATOR_ROLE_URN
        or role_obj.get("defining_tenant_id") is not None
        or role_obj.get("builtin") is not True
        or role_obj.get("approved_role") is not True
    ):
        raise GlobalAuthorizationSnapshotError("role is not the approved SYSTEM builtin")
    role_urn = RoleUrn(str(role_obj["urn"]))
    name = role_obj.get("name")
    description = role_obj.get("description")
    if not isinstance(name, str) or not isinstance(description, str):
        raise GlobalAuthorizationSnapshotError("role name/description must be text")

    sets = _list(payload.get("permission_sets"), "permission_sets")
    permissions = _list(payload.get("permissions"), "permissions")
    if not sets:
        raise GlobalAuthorizationSnapshotError("the Role has no PermissionSets")
    permissions_by_set: dict[str, list[Permission]] = {}
    for raw in permissions:
        item = _obj(raw, "permission")
        if set(item) != {"id", "permission_set_id", "urn", "position"}:
            raise GlobalAuthorizationSnapshotError("malformed permission facts")
        permission_set_id = _id(item.get("permission_set_id"), "permission.permission_set_id")
        permission = Permission(
            id=_id(item.get("id"), "permission.id"),
            permission_set_id=permission_set_id,
            urn=PermissionUrn(str(item.get("urn"))),
        )
        permissions_by_set.setdefault(str(permission_set_id), []).append(permission)

    built_sets: list[PermissionSet] = []
    for raw in sets:
        item = _obj(raw, "permission_set")
        if set(item) != {"id", "role_urn", "effect", "position"}:
            raise GlobalAuthorizationSnapshotError("malformed PermissionSet facts")
        if item.get("role_urn") != APPROVED_SYSTEM_OPERATOR_ROLE_URN:
            raise GlobalAuthorizationSnapshotError("PermissionSet Role mismatch")
        effect_value = item.get("effect")
        if effect_value not in ("allow", "deny"):
            raise GlobalAuthorizationSnapshotError("invalid PermissionSet effect")
        set_id = _id(item.get("id"), "permission_set.id")
        owned = tuple(permissions_by_set.get(str(set_id), ()))
        if not owned:
            raise GlobalAuthorizationSnapshotError("PermissionSet has no Permissions")
        built_sets.append(
            PermissionSet(
                id=set_id,
                role_urn=role_urn,
                effect=PermissionEffect(str(effect_value)),
                permissions=owned,
            )
        )
    try:
        role = Role(
            urn=role_urn,
            name=name,
            description=description,
            defining_tenant_id=None,
            permission_sets=tuple(built_sets),
        )
    except DomainInvariantError as exc:
        raise GlobalAuthorizationSnapshotError("inconsistent Role policy") from exc

    target_obj = _obj(payload.get("target"), "target")
    if set(target_obj) != {"kind", "application_id", "entitlement_id"}:
        raise GlobalAuthorizationSnapshotError("malformed target facts")
    application_id = _id(target_obj.get("application_id"), "target.application_id")
    entitlement_raw = target_obj.get("entitlement_id")
    if target_obj.get("kind") == "APPLICATION":
        if entitlement_raw is not None:
            raise GlobalAuthorizationSnapshotError("Application target cannot carry entitlement")
        target: GlobalApplicationTarget | GlobalEntitlementTarget = GlobalApplicationTarget(
            application_id=application_id
        )
    elif target_obj.get("kind") == "ENTITLEMENT":
        target = GlobalEntitlementTarget(
            application_id=application_id,
            entitlement_id=_id(entitlement_raw, "target.entitlement_id"),
        )
    else:
        raise GlobalAuthorizationSnapshotError("unknown target kind")
    _checked_at(payload.get("checked_at"))
    return GlobalSystemAuthorizationRequest(
        operator=operator,
        assignment=assignment_facts,
        role=role,
        target=target,
        action=action,
    )


def _obj(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(k, str) for k in value):
        raise GlobalAuthorizationSnapshotError(f"{name} must be an object")
    return value


def _list(value: object, name: str) -> list[object]:
    if not isinstance(value, list):
        raise GlobalAuthorizationSnapshotError(f"{name} must be a list")
    return value


def _id(value: object, name: str) -> DomainId:
    if not isinstance(value, str):
        raise GlobalAuthorizationSnapshotError(f"{name} must be canonical UUID text")
    try:
        return DomainId.from_str(value)
    except ValueError as exc:
        raise GlobalAuthorizationSnapshotError(f"{name} is not a canonical UUID") from exc


def _checked_at(value: object) -> datetime:
    if not isinstance(value, str):
        raise GlobalAuthorizationSnapshotError("checked_at must be text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GlobalAuthorizationSnapshotError("checked_at is malformed") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GlobalAuthorizationSnapshotError("checked_at must be timezone-aware")
    return parsed
