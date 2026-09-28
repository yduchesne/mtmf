"""Typed MTMF IAM URN value types: Role, Action, and Permission URNs.

PR 1's generic :class:`~mtmf_core.domain.urn.Urn` remains generic; this
module adds the typed IAM semantics on top of it. The IAM grammar is
normative in SECURITY_MODEL.md (sections 14-15).

Grammar summary:

- SYSTEM Role:  ``urn:mtmf:iam:roles:system:<role-name>``
- TENANT Role:  ``urn:mtmf:iam:roles:tenant:<tenant-id>:<role-name>``
- Action:       ``urn:mtmf:iam:actions:<definition-namespace>:``
                 ``<resource>:<verb>-<qualifier>``
- Permission:   ``urn:mtmf:iam:permissions:<definition-namespace>:``
                 ``<resource>:<verb>-<qualifier-or-*>``

Action URNs are exact only and must never contain ``*``. Permission
URNs may replace only the complete qualifier with ``*``.

This PR supports the ``system`` definition namespace for Action and
Permission URNs. A tenant-defined Action/Permission URN layout is not
specified by the authoritative documents, so a ``tenant`` definition
namespace is rejected rather than invented; a matching Permission and
Action must always agree on the definition namespace.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mtmf_core.domain.errors import DomainInvariantError
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.policy import DefinitionNamespace
from mtmf_core.domain.urn import validate_urn

_WILDCARD = "*"

_IAM_PREFIX = "urn:mtmf:iam:"


def _split_iam_components(value: str, kind: str) -> tuple[str, ...]:
    """Split a typed IAM URN after its ``kind`` segment.

    Rejects wrong prefixes/kinds, empty components, and whitespace.
    Wildcard handling is type-specific and therefore left to callers.
    """
    prefix = f"{_IAM_PREFIX}{kind}:"
    if not value.startswith(prefix):
        raise DomainInvariantError(f"invalid {kind} URN: expected the '{prefix}' prefix")
    remainder = value[len(prefix) :]
    parts = tuple(remainder.split(":"))
    if not parts or any(not part for part in parts):
        raise DomainInvariantError(f"invalid {kind} URN: empty components are not allowed")
    if any(any(character.isspace() for character in part) for part in parts):
        raise DomainInvariantError(f"invalid {kind} URN: whitespace is not allowed")
    return parts


def _parse_supported_namespace(text: str, kind: str) -> DefinitionNamespace:
    """Parse a definition-namespace component that this PR supports.

    Only the SYSTEM namespace has a settled layout for Actions and
    Permissions; tenant-defined layouts remain unspecified and are
    rejected fail-closed.
    """
    try:
        namespace = DefinitionNamespace(text)
    except ValueError as exc:
        raise DomainInvariantError(
            f"invalid {kind} URN: unknown definition namespace {text!r}"
        ) from exc
    if namespace is not DefinitionNamespace.SYSTEM:
        raise DomainInvariantError(
            f"invalid {kind} URN: definition namespace {text!r} is not supported; "
            "tenant-defined Action/Permission layout is not specified"
        )
    return namespace


def _split_operation(operation: str, kind: str) -> tuple[str, str]:
    """Split an operation into a literal verb and a qualifier.

    The operation form is always ``<verb>-<qualifier>``; the first ``-``
    separates the two parts and both parts must be non-empty.
    """
    verb, separator, qualifier = operation.partition("-")
    if not separator:
        raise DomainInvariantError(
            f"invalid {kind} URN: operation must use the '<verb>-<qualifier>' form"
        )
    if not verb:
        raise DomainInvariantError(f"invalid {kind} URN: verb must not be empty")
    if not qualifier:
        raise DomainInvariantError(f"invalid {kind} URN: qualifier must not be empty")
    return verb, qualifier


def _parse_role_urn(value: str) -> tuple[DefinitionNamespace, DomainId | None, str]:
    """Parse and validate the Role URN grammar."""
    parts = _split_iam_components(value, "roles")
    if any(_WILDCARD in part for part in parts):
        raise DomainInvariantError("invalid Role URN: wildcards are not allowed")
    try:
        namespace = DefinitionNamespace(parts[0])
    except ValueError as exc:
        raise DomainInvariantError(
            f"invalid Role URN: unknown definition namespace {parts[0]!r}"
        ) from exc
    if namespace is DefinitionNamespace.SYSTEM:
        if len(parts) != 2:
            raise DomainInvariantError(
                "invalid SYSTEM Role URN: expected exactly 'system:<role-name>'"
            )
        return namespace, None, parts[1]
    if len(parts) != 3:
        raise DomainInvariantError(
            "invalid TENANT Role URN: expected exactly 'tenant:<tenant-id>:<role-name>'"
        )
    try:
        tenant_id = DomainId.from_str(parts[1])
    except ValueError as exc:
        raise DomainInvariantError(
            f"invalid TENANT Role URN: malformed Tenant ID {parts[1]!r}"
        ) from exc
    return namespace, tenant_id, parts[2]


def _parse_action_urn(
    value: str,
) -> tuple[DefinitionNamespace, str, str, str]:
    """Parse and validate the exact Action URN grammar."""
    parts = _split_iam_components(value, "actions")
    if len(parts) != 3:
        raise DomainInvariantError(
            "invalid Action URN: expected exactly '<namespace>:<resource>:<operation>'"
        )
    namespace = _parse_supported_namespace(parts[0], "Action")
    resource = parts[1]
    verb, qualifier = _split_operation(parts[2], "Action")
    if any(_WILDCARD in component for component in (resource, verb, qualifier)):
        raise DomainInvariantError(
            "invalid Action URN: Action URNs are exact and must not contain wildcards"
        )
    return namespace, resource, verb, qualifier


def _parse_permission_urn(
    value: str,
) -> tuple[DefinitionNamespace, str, str, str]:
    """Parse and validate the Permission matcher URN grammar.

    The resource and verb must be exact; the qualifier is either exact
    or the complete wildcard ``*``. No other wildcard form is valid.
    """
    parts = _split_iam_components(value, "permissions")
    if len(parts) != 3:
        raise DomainInvariantError(
            "invalid Permission URN: expected exactly '<namespace>:<resource>:<operation>'"
        )
    namespace = _parse_supported_namespace(parts[0], "Permission")
    resource = parts[1]
    verb, qualifier = _split_operation(parts[2], "Permission")
    if _WILDCARD in resource or _WILDCARD in verb:
        raise DomainInvariantError("invalid Permission URN: resource and verb must be exact")
    if qualifier != _WILDCARD and _WILDCARD in qualifier:
        raise DomainInvariantError("invalid Permission URN: only the complete qualifier may be '*'")
    return namespace, resource, verb, qualifier


@dataclass(frozen=True, slots=True)
class RoleUrn:
    """An immutable SYSTEM or TENANT Role URN.

    The canonical ``value`` is the sole constructor input; the parsed
    state (definition namespace, optional encoded Tenant ID, and role
    name) is derived and always agrees with it.

    :raises DomainInvariantError: for wrong prefix/kind, unknown
        namespace, empty role name, malformed Tenant ID, unexpected
        components, whitespace, or wildcards.
    """

    value: str
    definition_namespace: DefinitionNamespace = field(init=False)
    encoded_tenant_id: DomainId | None = field(init=False)
    role_name: str = field(init=False)

    def __post_init__(self) -> None:
        validate_urn(self.value)
        namespace, tenant_id, role_name = _parse_role_urn(self.value)
        object.__setattr__(self, "definition_namespace", namespace)
        object.__setattr__(self, "encoded_tenant_id", tenant_id)
        object.__setattr__(self, "role_name", role_name)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ActionUrn:
    """An immutable exact Action URN.

    Actions are shared exact definitions. ``resource``, ``verb``, and
    ``qualifier`` are derived from the canonical ``value``; no Action
    URN may contain a wildcard.

    :raises DomainInvariantError: for malformed grammar or any wildcard.
    """

    value: str
    definition_namespace: DefinitionNamespace = field(init=False)
    resource: str = field(init=False)
    verb: str = field(init=False)
    qualifier: str = field(init=False)

    def __post_init__(self) -> None:
        validate_urn(self.value)
        namespace, resource, verb, qualifier = _parse_action_urn(self.value)
        object.__setattr__(self, "definition_namespace", namespace)
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "verb", verb)
        object.__setattr__(self, "qualifier", qualifier)

    @property
    def operation(self) -> str:
        """The canonical ``<verb>-<qualifier>`` operation text."""
        return f"{self.verb}-{self.qualifier}"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class PermissionUrn:
    """An immutable Permission matcher URN.

    A Permission URN expresses Action-matching semantics (exact or
    complete-qualifier wildcard). It is not the Permission object's
    identity and is not required to be globally unique.

    :raises DomainInvariantError: for malformed grammar or any wildcard
        form other than a complete qualifier ``*``.
    """

    value: str
    definition_namespace: DefinitionNamespace = field(init=False)
    resource: str = field(init=False)
    verb: str = field(init=False)
    qualifier: str = field(init=False)

    def __post_init__(self) -> None:
        validate_urn(self.value)
        namespace, resource, verb, qualifier = _parse_permission_urn(self.value)
        object.__setattr__(self, "definition_namespace", namespace)
        object.__setattr__(self, "resource", resource)
        object.__setattr__(self, "verb", verb)
        object.__setattr__(self, "qualifier", qualifier)

    @property
    def operation(self) -> str:
        """The canonical ``<verb>-<qualifier>`` operation text."""
        return f"{self.verb}-{self.qualifier}"

    @property
    def is_wildcard(self) -> bool:
        """True when the complete qualifier is the ``*`` wildcard."""
        return self.qualifier == _WILDCARD

    def __str__(self) -> str:
        return self.value
