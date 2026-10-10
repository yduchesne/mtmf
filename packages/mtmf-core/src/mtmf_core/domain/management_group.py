"""Typed TenantManagementGroup domain model (PR 11).

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

Manager-side eligibility is settled (Gate D, PR 11): delegated authority
requires an explicit Identity-level :class:`TenantManagementGroupActorEligibility`
designation scoped to the management group and its manager Tenant.
Ordinary membership, Tenant Administrator status, stewardship, or IAM
Group membership never substitutes for it, and the ROOT group instead
follows the canonical root Identity.

This module validates structural consistency only. It does not
authenticate a caller, evaluate a management Role permission, elevate a
security scope, or authorize an Action, and a valid
:class:`TenantManagementGroup` MUST NOT be treated as a grant of
authority.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import IntEnum
from typing import ClassVar

from mtmf_core.domain.errors import (
    DomainInvariantError,
    ManagementGroupInvariantError,
)
from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.memberships import IdentityTenantMembership
from mtmf_core.domain.mixins import ImmutableFieldGuard
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.tenant import Tenant

__all__ = [
    "ROOT_MANAGEMENT_ROLE_URN",
    "SYSTEM_MANAGEMENT_ROLE_URN",
    "TenantManagementGroup",
    "TenantManagementGroupActorEligibility",
    "TenantManagementGroupMembership",
    "TenantManagementScope",
    "validate_tenant_management_group",
    "validate_tenant_management_group_actor_eligibility",
    "validate_tenant_management_group_membership",
]

#: The single approved SYSTEM-defined management Role for the ROOT group.
#: Delegated management Roles are installation constants: a TENANT-defined
#: Role, or any other SYSTEM Role, must never provide cross-Tenant
#: management authority.
ROOT_MANAGEMENT_ROLE_URN = "urn:mtmf:iam:roles:system:root-tenant-management"

#: The single approved SYSTEM-defined management Role for SYSTEM groups.
SYSTEM_MANAGEMENT_ROLE_URN = "urn:mtmf:iam:roles:system:tenant-management"


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
    management Role must independently authorize each exact Action.
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {"id", "management_group_id", "tenant_id"}
    )

    id: DomainId
    management_group_id: DomainId
    tenant_id: DomainId


@dataclass(slots=True)
class TenantManagementGroupActorEligibility(ImmutableFieldGuard):
    """An explicit Identity-level delegation eligibility designation (D01).

    :attr:`id` is the immutable designation identity;
    :attr:`management_group_id` and :attr:`identity_id` are the immutable
    relationship endpoints. Ordinary manager-Tenant membership, Tenant
    Administrator status, stewardship, or IAM Group membership never
    substitutes for this explicit designation.

    The designation is scoped to one management group and its manager
    Tenant. It is never created for the ROOT management group: ROOT
    authority follows the canonical root Identity through root recovery and
    has no independent eligibility list (D03).
    """

    _immutable_fields: ClassVar[frozenset[str]] = frozenset(
        {"id", "management_group_id", "identity_id"}
    )

    id: DomainId
    management_group_id: DomainId
    identity_id: DomainId


def validate_tenant_management_group(
    group: TenantManagementGroup,
    *,
    manager_tenant: Tenant,
    canonical_root_tenant_id: DomainId,
) -> None:
    """Validate the settled structural consistency of a management group.

    Enforces the manager/scope/Role invariants of the security model:

    - the manager Tenant must be the supplied ``manager_tenant``;
    - the management Role must be the approved SYSTEM-defined Role for the
      group's scope (D05), so a TENANT-defined Role can never be used;
    - a ``ROOT`` group must be managed by the canonical root Tenant (ROOT
      scope), advancing no other manager;
    - a ``SYSTEM`` group must be managed by a non-root ordinary (TENANT
      scope) Tenant;
    - the manager Tenant must not be soft-deleted.

    This function is structural validation only and MUST NOT be used as
    authorization.

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
    expected_role = (
        ROOT_MANAGEMENT_ROLE_URN
        if group.scope is TenantManagementScope.ROOT
        else SYSTEM_MANAGEMENT_ROLE_URN
    )
    if group.management_role_urn.value != expected_role:
        raise ManagementGroupInvariantError(
            "a TenantManagementGroup management Role must be the approved "
            f"SYSTEM-defined Role {expected_role!r} for its scope"
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
    - a management group must not explicitly manage its own manager Tenant;
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


def validate_tenant_management_group_actor_eligibility(
    eligibility: TenantManagementGroupActorEligibility,
    *,
    management_group: TenantManagementGroup,
    identity: Identity,
    identity_tenant_memberships: Iterable[IdentityTenantMembership],
) -> None:
    """Validate one explicit delegation eligibility designation (D01/D04).

    Enforces that the designation references the supplied SYSTEM management
    group and Identity, that the Identity is not soft-deleted, and that the
    Identity has an explicit membership in the management group's manager
    Tenant. A ROOT group must not carry eligibility rows: ROOT authority
    follows the canonical root Identity only.

    This is structural validation only and MUST NOT be used as
    authorization: it establishes that a designation is well-formed, not
    that the acting session was authenticated.

    :raises ManagementGroupInvariantError: on any structural mismatch.
    """
    if eligibility.management_group_id != management_group.id:
        raise ManagementGroupInvariantError(
            "eligibility designation does not correspond to the supplied management group"
        )
    if management_group.scope is not TenantManagementScope.SYSTEM:
        raise ManagementGroupInvariantError(
            "a ROOT TenantManagementGroup must not carry explicit eligibility designations; "
            "ROOT authority follows the canonical root Identity"
        )
    if eligibility.identity_id != identity.id:
        raise ManagementGroupInvariantError(
            "eligibility designation does not correspond to the supplied Identity"
        )
    if identity.deleted:
        raise ManagementGroupInvariantError("an eligible Identity must not be soft-deleted")
    if not any(
        membership.identity_id == identity.id
        and membership.tenant_id == management_group.manager_tenant_id
        for membership in identity_tenant_memberships
    ):
        raise ManagementGroupInvariantError(
            "an eligible Identity must have an explicit membership in the manager Tenant"
        )
