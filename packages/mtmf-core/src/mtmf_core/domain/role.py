"""Role: an assignable policy composed of owned, ordered PermissionSets."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from mtmf_core.domain.errors import DomainInvariantError
from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.json_types import JsonObject, new_extension
from mtmf_core.domain.mixins import ImmutableFieldGuard
from mtmf_core.domain.permission_set import PermissionSet
from mtmf_core.domain.policy import DefinitionNamespace


@dataclass(slots=True)
class Role(ImmutableFieldGuard):
    """An assignable policy object with immutable unique Role URN identity.

    A Role owns an ordered, non-empty list of PermissionSets. It is
    defined in either the SYSTEM or a TENANT definition namespace; a
    TENANT Role carries independent structural :attr:`defining_tenant_id`
    state that must agree with the Tenant encoded in its Role URN.

    :attr:`urn` and the structural :attr:`defining_tenant_id` are
    immutable; :attr:`name`, :attr:`description`, and the opaque
    :attr:`extension` are mutable. A Role has no security Scope and no
    assignments: assignment context is owned by later PRs.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset({"urn", "defining_tenant_id"})

    urn: RoleUrn
    name: str
    description: str = ""
    defining_tenant_id: DomainId | None = None
    permission_sets: tuple[PermissionSet, ...] = ()
    extension: JsonObject = field(default_factory=new_extension)

    @property
    def definition_namespace(self) -> DefinitionNamespace:
        """The Role definition namespace, derived from the canonical URN."""
        return self.urn.definition_namespace

    def __post_init__(self) -> None:
        self._validate_definition_ownership()
        if not self.permission_sets:
            raise DomainInvariantError("a Role must own at least one PermissionSet")
        for permission_set in self.permission_sets:
            if permission_set.role_urn != self.urn:
                raise DomainInvariantError(
                    "owned PermissionSet points at a different Role; "
                    "mismatched ownership is rejected and never auto-reparented"
                )

    def _validate_definition_ownership(self) -> None:
        """Enforce the Role URN/structural definition-ownership invariant.

        The Role URN is never the sole source of Tenant ownership: the
        independent structural :attr:`defining_tenant_id` must agree with
        the Tenant encoded in the URN.
        """
        if self.urn.definition_namespace is DefinitionNamespace.SYSTEM:
            if self.defining_tenant_id is not None:
                raise DomainInvariantError(
                    "a SYSTEM Role must not carry a structural defining Tenant"
                )
            return
        if self.defining_tenant_id is None:
            raise DomainInvariantError("a TENANT Role requires a structural defining Tenant")
        if self.urn.encoded_tenant_id != self.defining_tenant_id:
            raise DomainInvariantError(
                f"TENANT Role structural defining Tenant {self.defining_tenant_id} "
                f"disagrees with the Tenant {self.urn.encoded_tenant_id} encoded "
                "in its Role URN"
            )
