"""Explicit typed membership relationships.

MTMF uses distinct typed membership relationships rather than a
polymorphic ``member_type``/``member_id`` abstraction. Each membership is
an explicit relationship fact; cross-object invariants belong to the
pure validators in :mod:`mtmf_core.domain.invariants` and constructors
never query persistence or global registries.
"""

from __future__ import annotations

from dataclasses import dataclass

from mtmf_core.domain.identity import DomainId


@dataclass(frozen=True, slots=True)
class PrincipalTenantMembership:
    """Explicit Tenant membership of a global Principal.

    A Principal may have such memberships in multiple Tenants. Tenant
    Stewardship is semantically attached to this relationship, but
    stewardship behavior is owned by a later PR.
    """

    principal_id: DomainId
    tenant_id: DomainId


@dataclass(frozen=True, slots=True)
class IdentityTenantMembership:
    """Explicit Tenant membership of an Identity.

    Valid only when the Identity's Principal has a
    :class:`PrincipalTenantMembership` for the same Tenant. An Identity
    may be usable in a subset of its Principal's Tenants.
    """

    identity_id: DomainId
    tenant_id: DomainId


@dataclass(frozen=True, slots=True)
class GroupTenantMembership:
    """Explicit Tenant membership of a Group.

    Must agree with the Group's structural ``tenant_id``; the
    relationship remains explicit even though it is structurally implied
    because the authoritative domain model requires it.
    """

    group_id: DomainId
    tenant_id: DomainId


@dataclass(frozen=True, slots=True)
class IdentityGroupMembership:
    """Explicit association of an Identity with a Group.

    Requires the Identity to have an explicit
    :class:`IdentityTenantMembership` in the Group's Tenant. Sibling
    Identities never inherit this membership.
    """

    identity_id: DomainId
    group_id: DomainId


@dataclass(frozen=True, slots=True)
class IdentityOrgMembership:
    """Explicit Organization membership of an Identity.

    Requires the Identity to have an explicit
    :class:`IdentityTenantMembership` in the Organization's Tenant;
    cross-Tenant membership is invalid.
    """

    identity_id: DomainId
    organization_id: DomainId


@dataclass(frozen=True, slots=True)
class GroupOrgMembership:
    """Explicit Organization membership of a Group.

    Requires the Group and Organization to share one Tenant and the
    Group's :class:`GroupTenantMembership` to agree with that Tenant.
    """

    group_id: DomainId
    organization_id: DomainId
