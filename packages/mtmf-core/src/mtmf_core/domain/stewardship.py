"""Root-bootstrap and Tenant-stewardship structural facts (PR 10, blocked subset).

This module captures the *structural* invariants of PR 10 that are already
settled by the authoritative documents:

- the canonical root Tenant/Principal/Identity identifiers must agree with the
  singleton root records and the acting root Identity must belong to the root
  Principal (:mod:`docs/SECURITY_MODEL.md` section 5);
- a Tenant-stewardship designation must reference an ordinary Tenant, a steward
  Principal that is that Tenant's member, and a designated acting Identity that
  belongs to the steward Principal and is itself a member of the Tenant
  (:mod:`docs/ROOT_AND_STEWARDSHIP.md`).

It deliberately does NOT encode the parts that remain unresolved and are
recorded as blocked STOP decisions in ``docs/PR10_IMPLEMENTATION_DECISIONS.md``:

- STOP-01: any privileged bootstrap/transfer/recovery entry point;
- STOP-02: the built-in Role/Permission catalog, including the Tenant
  Administrator Role composition required for steward eligibility;
- STOP-03: the local-versus-federated Identity representation;
- STOP-04: explicit ACTIVE/INACTIVE lifecycle admission.

Nothing here authenticates a caller, authorizes an Action, resolves or assigns
a Role, grants dominance, persists state, touches PostgreSQL, reads a session,
or defines a privileged boundary. These helpers validate structure only and
MUST NOT be treated as a grant of authority. The application/authorization
layer remains responsible for authentication, permission, dominance, lifecycle,
Role, and locality eligibility before any protected operation is allowed.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from mtmf_core.domain.errors import RootInvariantError, StewardshipInvariantError
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.memberships import IdentityTenantMembership, PrincipalTenantMembership
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.tenant import Tenant

__all__ = [
    "RootBootstrapRecord",
    "TenantStewardshipDesignation",
    "validate_root_bootstrap_record",
    "validate_stewardship_designation",
]


@dataclass(frozen=True, slots=True)
class RootBootstrapRecord:
    """Immutable canonical identifiers of a completed root bootstrap.

    :attr:`root_tenant_id`, :attr:`root_principal_id`, and
    :attr:`root_identity_id` are stable object identifiers, never display
    names. The record intentionally omits Role policy, credentials, and any
    locality marker: those are unsettled (STOP-02/STOP-03) and MUST NOT be
    inferred here.
    """

    root_tenant_id: DomainId
    root_principal_id: DomainId
    root_identity_id: DomainId


@dataclass(frozen=True, slots=True)
class TenantStewardshipDesignation:
    """Structural stewardship designation for one ordinary Tenant.

    :attr:`tenant_id` identifies the ordinary Tenant. :attr:`steward_principal_id`
    identifies the steward Principal and :attr:`designated_identity_id` the
    single designated acting Identity of that Principal. :attr:`version` is an
    opaque monotonic transition marker used only for stale-write detection; it
    is not authorization state.

    The designation is a structural fact only. It does not itself assign the
    Tenant Administrator Role, grant any Permission, or enable stewardship
    dominance; those require independently resolved effective Roles and the
    exact operation Permission (blocked STOP-02/STOP-04).
    """

    tenant_id: DomainId
    steward_principal_id: DomainId
    designated_identity_id: DomainId
    version: int

    def __post_init__(self) -> None:
        if self.version < 0:
            raise StewardshipInvariantError(
                "TenantStewardshipDesignation.version must not be negative"
            )


def validate_root_bootstrap_record(
    record: RootBootstrapRecord,
    *,
    root_tenant: Tenant,
    root_principal: Principal,
    root_identity: Identity,
) -> None:
    """Validate the settled structural consistency of a root bootstrap record.

    Confirms that the supplied root Tenant, Principal, and Identity match the
    canonical record IDs, that the root Tenant has ROOT scope, that the root
    Identity belongs to the root Principal, that the three canonical IDs are
    distinct, and that none of the objects is soft-deleted.

    This is structural validation only. It does not verify the mandatory local
    Identity representation (STOP-03), ACTIVE/INACTIVE lifecycle admission
    (STOP-04), or the built-in Role assignment (STOP-02), and it MUST NOT be
    used as authorization.

    :raises RootInvariantError: on any structural mismatch.
    """
    if root_tenant.id != record.root_tenant_id:
        raise RootInvariantError("root Tenant does not match the canonical record")
    if root_tenant.scope is not SecurityScope.ROOT:
        raise RootInvariantError("the canonical root Tenant must have ROOT scope")
    if root_principal.id != record.root_principal_id:
        raise RootInvariantError("root Principal does not match the canonical record")
    if root_identity.id != record.root_identity_id:
        raise RootInvariantError("root Identity does not match the canonical record")
    if root_identity.principal_id != root_principal.id:
        raise RootInvariantError("the designated root Identity must belong to the root Principal")
    canonical_ids = {
        record.root_tenant_id,
        record.root_principal_id,
        record.root_identity_id,
    }
    if len(canonical_ids) != 3:
        raise RootInvariantError("root Tenant, Principal, and Identity IDs must be distinct")
    if root_tenant.deleted or root_principal.deleted or root_identity.deleted:
        raise RootInvariantError("root Tenant, Principal, and Identity must not be soft-deleted")


def validate_stewardship_designation(
    designation: TenantStewardshipDesignation,
    *,
    tenant: Tenant,
    steward_principal: Principal,
    designated_identity: Identity,
    principal_tenant_memberships: Iterable[PrincipalTenantMembership],
    identity_tenant_memberships: Iterable[IdentityTenantMembership],
) -> None:
    """Validate the settled structural consistency of a stewardship designation.

    Confirms that the designation references the supplied ordinary (TENANT
    scope) Tenant, that the designated Identity belongs to the steward
    Principal, that both have explicit memberships in the Tenant, and that none
    of the objects is soft-deleted.

    This is structural validation only. It does not verify the steward's
    TENANT-scope membership admission, ACTIVE/INACTIVE lifecycle state, local
    Identity continuity, or the required built-in Tenant Administrator Role
    (STOP-02/STOP-03/STOP-04). It confers no Role, Permission, or dominance and
    MUST NOT be used as authorization.

    :raises StewardshipInvariantError: on any structural mismatch.
    """
    if tenant.id != designation.tenant_id:
        raise StewardshipInvariantError("Tenant does not match the designation")
    if tenant.scope is not SecurityScope.TENANT:
        raise StewardshipInvariantError(
            "root Tenant stewardship is not transferable via an ordinary designation"
        )
    if steward_principal.id != designation.steward_principal_id:
        raise StewardshipInvariantError("steward Principal does not match the designation")
    if designated_identity.id != designation.designated_identity_id:
        raise StewardshipInvariantError("designated acting Identity does not match the designation")
    if designated_identity.principal_id != steward_principal.id:
        raise StewardshipInvariantError(
            "the designated acting Identity must belong to the steward Principal"
        )
    if not any(
        membership.principal_id == steward_principal.id and membership.tenant_id == tenant.id
        for membership in principal_tenant_memberships
    ):
        raise StewardshipInvariantError(
            "the steward Principal must have a PrincipalTenantMembership in the Tenant"
        )
    if not any(
        membership.identity_id == designated_identity.id and membership.tenant_id == tenant.id
        for membership in identity_tenant_memberships
    ):
        raise StewardshipInvariantError(
            "the designated acting Identity must have an IdentityTenantMembership in the Tenant"
        )
    if tenant.deleted or steward_principal.deleted or designated_identity.deleted:
        raise StewardshipInvariantError(
            "Tenant, steward Principal, and designated acting Identity must not be soft-deleted"
        )
