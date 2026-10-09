"""Mapping between stored function payloads and MTMF domain objects.

The PostgreSQL provider intentionally does not return live rows, cursors,
or a composite table type to the runtime. A reviewed ``SECURITY DEFINER``
function returns a detached JSON object (or a set of scalar UUIDs), and
this module is the single place that turns that detached payload into a
domain object.

Mapping is strict: a missing field, an unexpected JSON type, an unknown
lifecycle/scope enum value, or a malformed nested Role aggregate raises
:class:`~mtmf_core.persistence.errors.PersistenceDataError` rather than
coercing the value or returning a partially initialized object. The
domain constructors are authoritative for cross-field invariants (for
example Role definition ownership); they run unchanged after mapping.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from mtmf_core.domain.action import Action
from mtmf_core.domain.group import Group
from mtmf_core.domain.iam_urn import ActionUrn, PermissionUrn, RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.json_types import JsonObject
from mtmf_core.domain.lifecycle import DeletionStatus
from mtmf_core.domain.organization import Organization
from mtmf_core.domain.permission import Permission
from mtmf_core.domain.permission_set import PermissionSet
from mtmf_core.domain.policy import PermissionEffect
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.role import Role
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.tenant import Tenant
from mtmf_core.persistence.errors import PersistenceDataError

__all__ = [
    "action_from_urn",
    "group_from_payload",
    "identity_from_payload",
    "organization_from_payload",
    "principal_from_payload",
    "role_from_payload",
    "role_to_payload",
    "tenant_from_payload",
]


def _require_object(payload: object, kind: str) -> dict[str, Any]:
    """Return ``payload`` as a JSON object or fail closed."""
    if not isinstance(payload, dict):
        raise PersistenceDataError(f"stored {kind} payload is not a JSON object")
    return payload


def _require_array(payload: object, kind: str) -> list[object]:
    """Return ``payload`` as a JSON array or fail closed."""
    if not isinstance(payload, list):
        raise PersistenceDataError(f"stored {kind} payload is not a JSON array")
    return payload


def _require_str(source: dict[str, Any], name: str) -> str:
    """Return required string ``name`` from a payload or fail closed."""
    value = source.get(name)
    if not isinstance(value, str):
        raise PersistenceDataError(f"stored payload field {name!r} is not a string")
    return value


def _require_uuid(source: dict[str, Any], name: str) -> DomainId:
    """Return required UUID ``name`` from a payload as a :class:`DomainId`."""
    value = source.get(name)
    if not isinstance(value, str):
        raise PersistenceDataError(f"stored payload field {name!r} is not a UUID string")
    try:
        return DomainId(UUID(value))
    except ValueError as exc:
        raise PersistenceDataError(f"stored payload field {name!r} is not a valid UUID") from exc


def _optional_uuid(source: dict[str, Any], name: str) -> DomainId | None:
    """Return optional UUID ``name`` from a payload as a :class:`DomainId`."""
    value = source.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise PersistenceDataError(f"stored payload field {name!r} is not a UUID string or null")
    try:
        return DomainId(UUID(value))
    except ValueError as exc:
        raise PersistenceDataError(f"stored payload field {name!r} is not a valid UUID") from exc


def _require_int(source: dict[str, Any], name: str) -> int:
    """Return required integer ``name`` from a payload or fail closed."""
    value = source.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise PersistenceDataError(f"stored payload field {name!r} is not an integer")
    return value


def _require_extension(source: dict[str, Any]) -> JsonObject:
    """Return the required top-level ``extension`` JSON object or fail closed."""
    value = source.get("extension")
    if not isinstance(value, dict):
        raise PersistenceDataError("stored extension field is not a JSON object")
    return value


def _require_deletion_status(source: dict[str, Any]) -> DeletionStatus:
    """Return the required soft-deletion lifecycle value or fail closed."""
    raw = _require_int(source, "deletion_status")
    try:
        return DeletionStatus(raw)
    except ValueError as exc:
        raise PersistenceDataError(f"stored deletion_status {raw!r} is not a legal value") from exc


def tenant_from_payload(payload: object) -> Tenant:
    """Reconstruct a :class:`Tenant` from a detached stored payload."""
    source = _require_object(payload, "Tenant")
    raw_scope = _require_int(source, "scope")
    try:
        scope = SecurityScope(raw_scope)
    except ValueError as exc:
        raise PersistenceDataError(
            f"stored Tenant scope {raw_scope!r} is not a legal value"
        ) from exc
    return Tenant(
        id=_require_uuid(source, "id"),
        name=_require_str(source, "name"),
        scope=scope,
        owner_identity_id=_require_uuid(source, "owner_identity_id"),
        deletion_status=_require_deletion_status(source),
        extension=_require_extension(source),
    )


def organization_from_payload(payload: object) -> Organization:
    """Reconstruct an :class:`Organization` from a detached stored payload."""
    source = _require_object(payload, "Organization")
    return Organization(
        id=_require_uuid(source, "id"),
        tenant_id=_require_uuid(source, "tenant_id"),
        name=_require_str(source, "name"),
        owner_identity_id=_require_uuid(source, "owner_identity_id"),
        deletion_status=_require_deletion_status(source),
        extension=_require_extension(source),
    )


def principal_from_payload(payload: object) -> Principal:
    """Reconstruct a :class:`Principal` from a detached stored payload."""
    source = _require_object(payload, "Principal")
    return Principal(
        id=_require_uuid(source, "id"),
        name=_require_str(source, "name"),
        deletion_status=_require_deletion_status(source),
        extension=_require_extension(source),
    )


def identity_from_payload(payload: object) -> Identity:
    """Reconstruct an :class:`Identity` from a detached stored payload."""
    source = _require_object(payload, "Identity")
    return Identity(
        id=_require_uuid(source, "id"),
        principal_id=_require_uuid(source, "principal_id"),
        name=_require_str(source, "name"),
        deletion_status=_require_deletion_status(source),
        extension=_require_extension(source),
    )


def group_from_payload(payload: object) -> Group:
    """Reconstruct a :class:`Group` from a detached stored payload."""
    source = _require_object(payload, "Group")
    return Group(
        id=_require_uuid(source, "id"),
        tenant_id=_require_uuid(source, "tenant_id"),
        name=_require_str(source, "name"),
        deletion_status=_require_deletion_status(source),
        extension=_require_extension(source),
    )


def action_from_urn(urn: ActionUrn) -> Action:
    """Reconstruct an :class:`Action` from its exact canonical URN."""
    return Action(urn)


def _permission_from_payload(payload: object, permission_set_id: DomainId) -> Permission:
    """Reconstruct one owned :class:`Permission`, enforcing its ownership."""
    source = _require_object(payload, "Permission")
    declared_owner = _require_uuid(source, "permission_set_id")
    if declared_owner != permission_set_id:
        raise PersistenceDataError("stored Permission points at a different PermissionSet")
    return Permission(
        id=_require_uuid(source, "id"),
        permission_set_id=permission_set_id,
        urn=PermissionUrn(_require_str(source, "urn")),
    )


def _permission_set_from_payload(payload: object, role_urn: RoleUrn) -> PermissionSet:
    """Reconstruct one owned :class:`PermissionSet`, enforcing its ownership."""
    source = _require_object(payload, "PermissionSet")
    declared_role = _require_str(source, "role_urn")
    if declared_role != role_urn.value:
        raise PersistenceDataError("stored PermissionSet is owned by a different Role")
    set_id = _require_uuid(source, "id")
    raw_effect = _require_str(source, "effect")
    try:
        effect = PermissionEffect(raw_effect)
    except ValueError as exc:
        raise PersistenceDataError(
            f"stored PermissionSet effect {raw_effect!r} is illegal"
        ) from exc
    permissions = tuple(
        _permission_from_payload(item, set_id)
        for item in _require_array(source.get("permissions"), "PermissionSet.permissions")
    )
    return PermissionSet(id=set_id, role_urn=role_urn, effect=effect, permissions=permissions)


def role_from_payload(payload: object) -> Role:
    """Reconstruct the complete ``Role -> PermissionSet -> Permission`` aggregate."""
    source = _require_object(payload, "Role")
    role_urn = RoleUrn(_require_str(source, "urn"))
    permission_sets = tuple(
        _permission_set_from_payload(item, role_urn)
        for item in _require_array(source.get("permission_sets"), "Role.permission_sets")
    )
    return Role(
        urn=role_urn,
        name=_require_str(source, "name"),
        description=_require_str(source, "description"),
        defining_tenant_id=_optional_uuid(source, "defining_tenant_id"),
        permission_sets=permission_sets,
        extension=_require_extension(source),
    )


def role_to_payload(role: Role) -> dict[str, object]:
    """Serialize a Role aggregate into the reviewed ``role_add``/``role_save`` payload.

    The payload always carries each child's declared ownership
    (``role_urn`` on a PermissionSet, ``permission_set_id`` on a
    Permission) so the trusted stored function can reject a forged
    reparenting attempt independently of Python-side validation.
    """
    return {
        "urn": role.urn.value,
        "name": role.name,
        "description": role.description,
        "defining_tenant_id": (
            str(role.defining_tenant_id) if role.defining_tenant_id is not None else None
        ),
        "extension": role.extension,
        "permission_sets": [
            {
                "id": str(permission_set.id),
                "role_urn": permission_set.role_urn.value,
                "effect": permission_set.effect.value,
                "permissions": [
                    {
                        "id": str(permission.id),
                        "permission_set_id": str(permission.permission_set_id),
                        "urn": permission.urn.value,
                    }
                    for permission in permission_set.permissions
                ],
            }
            for permission_set in role.permission_sets
        ],
    }
