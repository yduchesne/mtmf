"""EXPERIMENTAL msgspec/MessagePack semantic wire definitions (PR 8F).

PR 8F is a deliberately isolated performance experiment: it replaces
the current Rust FFI's nested ``list[tuple[str, list[str]]]`` transfer
and Rust-side URN reparsing with a compact MessagePack payload carrying
*already-parsed semantic components*.

This module defines the private, versioned, *positional* wire schema
(``msgspec.Struct`` with ``array_like=True`` — field-name maps are never
encoded) plus the domain-to-wire conversion that reuses the parsed
components the domain value objects already carry
(:attr:`~mtmf_core.domain.iam_urn.ActionUrn.resource`,
:attr:`~mtmf_core.domain.iam_urn.ActionUrn.verb`, ...). No complete
MTMF Action/Permission URN text ever crosses the payload.

These definitions are benchmark/experimental-only:

- they MUST NOT become domain entities, public DTOs, persistence DTOs,
  or API DTOs;
- nothing in ``mtmf_core`` imports this module and nothing on an active
  authorization path uses it;
- the existing domain classes are not replaced and the production
  ``RustPermissionEvaluator`` (URN-text boundary) is unchanged.

Wire schema (v1):

.. code-block:: text

    EvaluationPayload   = [version, action, permission_sets]
    ActionWire          = [namespace, resource, verb, qualifier]
    PermissionSetWire   = [effect, permissions]
    PermissionWire      = [namespace, resource, verb, qualifier,
                           qualifier_wildcard]
"""

from __future__ import annotations

from collections.abc import Iterable

import msgspec

from mtmf_core.authorization.permission_evaluator import PermissionEvaluationError
from mtmf_core.domain.action import Action
from mtmf_core.domain.permission import Permission
from mtmf_core.domain.role import Role

# The only existing wire schema version. Unsupported versions fail
# explicitly on the native side and never become a policy decision.
WIRE_VERSION = 1


class ActionWire(msgspec.Struct, array_like=True):
    """Positional Action wire shape: semantic components, no URN text."""

    namespace: str
    resource: str
    verb: str
    qualifier: str


class PermissionWire(msgspec.Struct, array_like=True):
    """Positional Permission wire shape plus the explicit wildcard flag."""

    namespace: str
    resource: str
    verb: str
    qualifier: str
    qualifier_wildcard: bool


class PermissionSetWire(msgspec.Struct, array_like=True):
    """Positional PermissionSet wire shape: exact effect plus Permissions."""

    effect: str
    permissions: list[PermissionWire]


class EvaluationPayload(msgspec.Struct, array_like=True):
    """Top-level positional payload: ``[version, action, sets]``."""

    version: int
    action: ActionWire
    permission_sets: list[PermissionSetWire]


def action_to_wire(action: Action) -> ActionWire:
    """Extract the already-parsed semantic components of an exact Action.

    Reuses the validated parsed state of :class:`ActionUrn`
    (``definition_namespace``, ``resource``, ``verb``, ``qualifier``);
    no canonical URN is reconstructed and no URN is parsed again.
    """
    urn = action.urn
    return ActionWire(
        urn.definition_namespace.value,
        urn.resource,
        urn.verb,
        urn.qualifier,
    )


def permission_to_wire(permission: Permission) -> PermissionWire:
    """Extract the already-parsed semantic components of one Permission.

    ``qualifier_wildcard`` mirrors the parsed
    :attr:`~mtmf_core.domain.iam_urn.PermissionUrn.is_wildcard` state,
    so wildcard state is explicit and unambiguous on the wire.
    """
    urn = permission.urn
    return PermissionWire(
        urn.definition_namespace.value,
        urn.resource,
        urn.verb,
        urn.qualifier,
        urn.is_wildcard,
    )


def build_payload(action: Action, roles: Iterable[Role]) -> EvaluationPayload:
    """Convert one Action plus already-applicable Roles to a v1 payload.

    Ownership validation is preserved: a PermissionSet whose ``role_urn``
    disagrees with its owning Role is corrupted domain policy and fails
    closed with :class:`PermissionEvaluationError` (the same check used
    by the production evaluators, before any serialization).
    """
    permission_sets: list[PermissionSetWire] = []
    for role in roles:
        for permission_set in role.permission_sets:
            if permission_set.role_urn != role.urn:
                raise PermissionEvaluationError(
                    f"PermissionSet {permission_set.id} is owned by "
                    f"{permission_set.role_urn}, not by supplied Role {role.urn}"
                )
            permission_sets.append(
                PermissionSetWire(
                    permission_set.effect.value,
                    [permission_to_wire(permission) for permission in permission_set.permissions],
                )
            )
    return EvaluationPayload(WIRE_VERSION, action_to_wire(action), permission_sets)
