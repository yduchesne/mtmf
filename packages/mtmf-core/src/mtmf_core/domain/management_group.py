"""Structural TenantManagementGroup domain model (PR 11, non-gated subset).

A :class:`TenantManagementGroup` (TMG) is a delegated cross-Tenant
administration relationship. It is deliberately **not** an ordinary IAM
:class:`~mtmf_core.domain.group.Group`: it carries one manager Tenant, one
management Role, and a management scope of ``ROOT`` or ``SYSTEM``
(:mod:`docs/DOMAIN_MODEL.md` section 15, :mod:`docs/SECURITY_MODEL.md`
section 20).

The ROOT management group implicitly covers every Tenant, including
Tenants created later, and never materializes managed-Tenant membership
rows. A SYSTEM management group covers only explicitly associated Tenants
through :class:`TenantManagementGroupMembership` rows.

This module captures only the *structural* facts that are already settled
by the authoritative documents. It deliberately does **not** encode the
manager-side actor eligibility rule, whose authoritative status is
``UNRESOLVED`` (:mod:`docs/SECURITY_MODEL.md` section 20.2,
:mod:`docs/DOMAIN_MODEL.md` section 15, and the PR 11 decision gate). The
structural validators here validate identity/scope/manager consistency
only. They do not authenticate a caller, evaluate a Role, elevate a
security scope, grant a Permission, or authorize an Action, and a valid
:class:`TenantManagementGroup` MUST NOT be treated as a grant of
authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from mtmf_core.domain.errors import (
    DomainInvariantError,
    ManagementGroupInvariantError,
)
from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.mixins import ImmutableFieldGuard
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.tenant import Tenant

__all__ = [
    "TenantManagementGroup",
    "TenantManagementGroupMembership",
    "TenantManagementScope",
    "validate_tenant_management_group",
    "validate_tenant_management_group_membership",
]


class TenantManagementScope(IntEnum):
    """The settled management scope of a TenantManagementGroup.

    ``ROOT`` is the single bootstrap management group's implicit-universal
    scope; ``SYSTEM`` is every ordinary delegated management group's
    explicit-membership scope. This is a *management* classification and
    must never be confused with :class:`~mtmf_core.domain.scope.SecurityScope`
    or with a Role definition namespace. The numeric ordering follows the
    security-scope convention (smaller means broader) but confers no
    authorization by itself.
    """

    ROOT = 0
    SYSTEM = 1


@dataclass(slots=True)
class TenantManagementGroup(ImmutableFieldGuard):
    """A structural delegated cross-Tenant administration group.

    :attr:`id` is the immutable management-group identity;
    :attr:`manager_tenant_id` is the immutable manager Tenant;
    :attr:`management_role_urn` is the management Role's immutable URN; and
    :attr:`scope` is the immutable ``ROOT``/``SYSTEM`` classification. None
    of these may be replaced, so a SYSTEM group can never be repurposed into
    a ROOT group or re-parented to another manager.

    The entity is structural persistence state only. It carries no actor
    eligibility, no Role assignment, and no Permission, and it authorizes
    nothing by itself.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {"id", "manager_tenant_id", "management_role_urn", "scope"}
    )

    id: DomainId
    manager_tenant_id: DomainId
    management_role_urn: RoleUrn
    scope: TenantManagementScope

    def __post_init__(self) -> None:
        if self.scope not in (TenantManagementScope.ROOT, TenantManagementScope.SYSTEM):
            raise DomainInvariantError(
                "TenantManagementGroup scope must be ROOT or SYSTEM: "
                "ROOT is the single bootstrap group and every delegated group is SYSTEM"
            )


@dataclass(slots=True)
class TenantManagementGroupMembership(ImmutableFieldGuard):
    """An explicit managed-Tenant association of one SYSTEM management group.

    :attr:`id` is the immutable membership identity;
    :attr:`management_group_id` and :attr:`tenant_id` are the immutable
    relationship endpoints. Only a SYSTEM management group may own such a
    row: ROOT coverage is implicit and universal, so an explicit ROOT
    membership row is rejected structurally.

    The row is a coverage fact only. It never grants an Action; the
    management Role must independently authorize each exact Action and the
    unresolved manager-actor eligibility rule must be satisfied.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {"id", "management_group_id", "tenant_id"}
    )

    id: DomainId
    management_group_id: DomainId
    tenant_id: DomainId


def validate_tenant_management_group(
    group: TenantManagementGroup,
    *,
    manager_tenant: Tenant,
    canonical_root_tenant_id: DomainId,
) -> None:
    """Validate the settled structural consistency of a management group.

    Enforces the manager/scope invariants of the security model:

    - the manager Tenant must be the supplied ``manager_tenant``;
    - a ``ROOT`` group must be managed by the canonical root Tenant (ROOT
      scope), advancing no other manager;
    - a ``SYSTEM`` group must be managed by a non-root ordinary (TENANT
      scope) Tenant;
    - the manager Tenant must not be soft-deleted.

    The management Role's namespace/ownership validity is deliberately not
    settled here: the approved management-Role constraints remain part of
    the PR 11 decision gate and MUST NOT be inferred. This function is
    structural validation only and MUST NOT be used as authorization.

    :raises ManagementGroupInvariantError: on any structural mismatch.
    """
    if group.manager_tenant_id != manager_tenant.id:
        raise ManagementGroupInvariantError(
            "TenantManagementGroup manager Tenant does not match the supplied Tenant"
        )
    if manager_tenant.deleted:
        raise ManagementGroupInvariantError(
            "a TenantManagementGroup manager Tenant must not be soft-deleted"
        )
    if group.scope is TenantManagementScope.ROOT:
        if manager_tenant.id != canonical_root_tenant_id:
            raise ManagementGroupInvariantError(
                "a ROOT TenantManagementGroup must be managed by the canonical root Tenant"
            )
        if manager_tenant.scope is not SecurityScope.ROOT:
            raise ManagementGroupInvariantError(
                "a ROOT TenantManagementGroup manager Tenant must have ROOT scope"
            )
        return
    if manager_tenant.id == canonical_root_tenant_id:
        raise ManagementGroupInvariantError(
            "a SYSTEM TenantManagementGroup must not be managed by the canonical root Tenant"
        )
    if manager_tenant.scope is not SecurityScope.TENANT:
        raise ManagementGroupInvariantError(
            "a SYSTEM TenantManagementGroup manager Tenant must be an ordinary TENANT-scope Tenant"
        )


def validate_tenant_management_group_membership(
    membership: TenantManagementGroupMembership,
    *,
    management_group: TenantManagementGroup,
    tenant: Tenant,
    canonical_root_tenant_id: DomainId,
) -> None:
    """Validate the settled structural consistency of a managed-Tenant row.

    Enforces:

    - the row must reference the supplied management group and Tenant;
    - only a ``SYSTEM`` management group may own explicit managed-Tenant
      rows (ROOT coverage is implicit and universal);
    - the canonical root Tenant must never be an explicitly managed target;
    - a management group must not explicitly manage its own manager Tenant
      (the restrictive default while the delegation-constraint decision
      remains open);
    - the managed Tenant must not be soft-deleted.

    This is structural validation only and MUST NOT be used as
    authorization. The managed-Tenant relationship never grants an Action.

    :raises ManagementGroupInvariantError: on any structural mismatch.
    """
    if membership.management_group_id != management_group.id:
        raise ManagementGroupInvariantError(
            "managed-Tenant membership does not correspond to the supplied management group"
        )
    if membership.tenant_id != tenant.id:
        raise ManagementGroupInvariantError(
            "managed-Tenant membership does not correspond to the supplied Tenant"
        )
    if management_group.scope is not TenantManagementScope.SYSTEM:
        raise ManagementGroupInvariantError(
            "a ROOT TenantManagementGroup must not contain explicit managed-Tenant rows; "
            "ROOT coverage is implicit and universal"
        )
    if tenant.id == canonical_root_tenant_id:
        raise ManagementGroupInvariantError(
            "the canonical root Tenant must not be an explicitly managed target"
        )
    if tenant.id == management_group.manager_tenant_id:
        raise ManagementGroupInvariantError(
            "a TenantManagementGroup must not explicitly manage its own manager Tenant"
        )
    if tenant.deleted:
        raise ManagementGroupInvariantError("an explicitly managed Tenant must not be soft-deleted")
