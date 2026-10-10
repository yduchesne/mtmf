"""Narrow internal authorization evaluation input.

The exact authorization-context representation remains unresolved by the
authoritative documents (AUTHORIZATION.md section 10). PR 4 therefore
defines the smallest internal input shape sufficient for already-settled
semantics: a caller-supplied set of pre-filtered facts plus an explicit
same-Tenant target.

The Authorizer and the evaluator never retrieve their own context: the
caller/context-retrieval layer supplies every fact this request carries.
There are no Role-assignment objects, no persistence references, and no
effective-Role loading here (PR 9 owns that model).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from mtmf_core.authorization.management import ManagementScopeResolution
from mtmf_core.domain.action import Action
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.memberships import IdentityTenantMembership, PrincipalTenantMembership
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.role import Role
from mtmf_core.domain.scope import SecurityScope
from mtmf_core.domain.session import SessionContext
from mtmf_core.domain.tenant import Tenant


class DominanceRequirement(Enum):
    """Whether an operation requires strict scope dominance.

    The requirement is declared explicitly by trusted internal context;
    it is never inferred from an Action's resource, verb, or qualifier.
    """

    NONE = "none"
    STRICT = "strict"


class UnsupportedConstraint(Enum):
    """Marker for a required security constraint PR 4 cannot evaluate.

    Declaring one forces the Authorizer to fail closed with
    ``UNSUPPORTED_CONSTRAINT``. These markers describe unresolved
    mechanisms; they do not implement them and must never be used as an
    override or bypass.

    :attr:`ALTERNATE_DOMINANCE`: the operation could only be authorized
        through an unimplemented alternate-dominance mechanism (Tenant
        Stewardship or TenantManagementGroup delegation).
    :attr:`EXTENSION_MUTATION_PROVENANCE`: the operation requires the
        unresolved application-extension mutation provenance rule
        (TENANT-defined application Role provenance for
        ``update-extension``).
    """

    ALTERNATE_DOMINANCE = "alternate-dominance"
    EXTENSION_MUTATION_PROVENANCE = "extension-mutation-provenance"


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """Caller-supplied, pre-filtered evaluation facts.

    The caller/context-retrieval layer supplies the session Tenant,
    acting Principal/Identity, their explicit Tenant memberships, and
    the Roles it asserts are applicable to this evaluation. Role-assignment
    loading (PR 9) is not invented here: ``applicable_roles`` is
    trusted, pre-filtered input whose assignment/applicability the
    Authorizer cannot yet prove.
    """

    session: SessionContext
    tenant: Tenant
    principal: Principal
    identity: Identity
    principal_tenant_memberships: tuple[PrincipalTenantMembership, ...]
    identity_tenant_memberships: tuple[IdentityTenantMembership, ...]
    applicable_roles: tuple[Role, ...]


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """The narrow internal evaluation request.

    ``target_tenant_id`` must equal the session/supplied Tenant for
    ordinary Tenant-bound evaluation. A cross-Tenant target is accepted
    only when ``management_scope`` carries a positively resolved
    TenantManagementGroup coverage and eligibility result; the caller
    must then supply exactly the management Role as
    ``context.applicable_roles``. ``subject_scope`` and ``target_scope``
    are required exactly when ``dominance_requirement`` is STRICT. A
    required-but-unresolved security constraint must be declared through
    ``unsupported_constraints``, which fails closed.
    """

    context: AuthorizationContext
    action: Action
    target_tenant_id: DomainId
    dominance_requirement: DominanceRequirement = DominanceRequirement.NONE
    subject_scope: SecurityScope | None = None
    target_scope: SecurityScope | None = None
    unsupported_constraints: tuple[UnsupportedConstraint, ...] = ()
    management_scope: ManagementScopeResolution | None = None
