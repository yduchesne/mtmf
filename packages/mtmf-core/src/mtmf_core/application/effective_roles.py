"""Trusted effective-Role resolution and authorization-context assembly (PR 9).

This module is the production bridge between persisted, Tenant-bound
Role-assignment state and the authorization layer. It fills the gap
deliberately left by PR 8H: ``AuthorizationContext.applicable_roles`` is
trusted, pre-filtered input, and this is the application-layer entry point
that builds it from verified persisted state instead of accepting an
arbitrary caller list.

The boundary is:

.. code-block:: text

    verified (Tenant, Principal, Identity) session facts
        -> EffectiveRoleResolver (reads assignments + prerequisites in one UoW)
        -> detached, tenant-filtered Role aggregates
        -> build_authorization_context(...)
        -> AuthorizationContext(applicable_roles=...)
        -> Authorizer -> DefaultAuthorizationPolicyResolver -> CompiledPolicy

The resolver never decides ALLOW/DENY and never evaluates an Action: it
only produces the applicable Role aggregate tuple. The
:class:`~mtmf_core.authorization.policy_resolver.DefaultAuthorizationPolicyResolver`
still performs no I/O; only this application-layer resolver touches
persistence.

Authorization state is never unioned across Tenants, Identities,
Principals, or Organizations. A missing or inconsistent prerequisite is a
fail-closed integrity failure or an ineligible (excluded) grant as the
documented contract dictates, never a silent ALLOW and never a fabricated
Role.
"""

from __future__ import annotations

from dataclasses import dataclass

from mtmf_core.authorization.context import AuthorizationContext
from mtmf_core.domain.errors import SessionContextError, TenantBoundaryError
from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.memberships import (
    IdentityTenantMembership,
    PrincipalTenantMembership,
)
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.role import Role
from mtmf_core.domain.session import SessionContext, validate_session_context
from mtmf_core.domain.tenant import Tenant
from mtmf_core.persistence.errors import PersistenceError
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_core.persistence.unit_of_work import UnitOfWork

__all__ = [
    "EffectiveRoleIntegrityError",
    "EffectiveRoleResolutionError",
    "EffectiveRoleResolver",
    "ResolvedAuthorizationState",
    "build_authorization_context",
]


class EffectiveRoleResolutionError(PersistenceError):
    """Effective-Role resolution could not safely produce applicable Roles.

    Raising this error is an infrastructure/application failure that fails
    closed. It is never a policy decision and never becomes an empty
    applicable-Role list that could be mistaken for a semantic DENY.
    """


class EffectiveRoleIntegrityError(EffectiveRoleResolutionError):
    """Persisted assignment/parent state is corrupt or context-inconsistent.

    Examples: an Identity/Group assignment references an unknown Role, a
    Group membership references an unknown Group, or a TENANT-defined Role
    is assigned outside its defining Tenant. Such state is rejected rather
    than silently reinterpreted as a harmless non-match.
    """


@dataclass(frozen=True, slots=True)
class ResolvedAuthorizationState:
    """Verified session facts plus the detached, applicable Roles.

    The entity and membership tuples are detached snapshots loaded in one
    UnitOfWork. ``applicable_roles`` is deduplicated by Role URN after
    context eligibility and sorted deterministically by URN; that ordering
    is diagnostic determinism only and never encodes precedence.
    """

    session: SessionContext
    tenant: Tenant
    principal: Principal
    identity: Identity
    principal_tenant_memberships: tuple[PrincipalTenantMembership, ...]
    identity_tenant_memberships: tuple[IdentityTenantMembership, ...]
    applicable_roles: tuple[Role, ...]
    target_organization_id: DomainId | None
    diagnostics: str


def build_authorization_context(state: ResolvedAuthorizationState) -> AuthorizationContext:
    """Assemble the trusted :class:`AuthorizationContext` from resolved state.

    This is the only application-facing factory that turns verified
    persisted state into the caller-supplied context the
    :class:`~mtmf_core.authorization.authorizer.Authorizer` consumes. It
    adds no authorization semantics and does not change the Authorizer or
    the policy resolver.
    """
    return AuthorizationContext(
        session=state.session,
        tenant=state.tenant,
        principal=state.principal,
        identity=state.identity,
        principal_tenant_memberships=state.principal_tenant_memberships,
        identity_tenant_memberships=state.identity_tenant_memberships,
        applicable_roles=state.applicable_roles,
    )


class EffectiveRoleResolver:
    """Resolve the applicable Role aggregate for a verified session.

    The resolver is constructed once with a provider-neutral
    :class:`~mtmf_core.persistence.spi.MtmfSpi` and given an explicit
    ``UnitOfWork`` per call. Every read shares that one transaction, so
    the resolved Role set is a consistent snapshot. The resolver performs
    no authorization and returns no decision.
    """

    __slots__ = ("_spi",)

    def __init__(self, spi: MtmfSpi) -> None:
        """Bind the resolver to one persistence provider."""
        self._spi = spi

    def resolve(
        self,
        uow: UnitOfWork,
        *,
        session: SessionContext,
        target_tenant_id: DomainId,
        target_organization_id: DomainId | None = None,
    ) -> ResolvedAuthorizationState:
        """Resolve applicable Roles for ``session`` in ``target_tenant_id``.

        :raises SessionContextError: for a missing/inconsistent structural
            session or an unknown/deleted Tenant, Principal, or Identity.
        :raises TenantBoundaryError: when the target Tenant differs from
            the session Tenant, or an Organization target belongs to
            another Tenant.
        :raises EffectiveRoleIntegrityError: for corrupt persisted Role
            assignment/parent state (unknown Role, unknown Group,
            TENANT-defined Role assigned outside its defining Tenant).
        """
        tenant_id = session.tenant_id
        if target_tenant_id != tenant_id:
            raise SessionContextError(
                "effective-Role resolution target Tenant differs from the session "
                "Tenant; cross-Tenant authorization is rejected"
            )

        tenant = self._spi.create_tenant_repository(uow).get(tenant_id)
        principal = self._spi.create_principal_repository(uow).get(session.principal_id)
        identity = self._spi.create_identity_repository(uow).get(session.identity_id)
        if tenant is None or principal is None or identity is None:
            raise SessionContextError(
                "effective-Role resolution requires an existing Tenant, Principal, and Identity"
            )
        if tenant.deleted or principal.deleted or identity.deleted:
            raise SessionContextError(
                "effective-Role resolution requires active session lifecycle state"
            )

        principal_tenant_membership = self._spi.create_principal_tenant_membership_repository(
            uow
        ).get(session.principal_id, tenant_id)
        identity_tenant_membership = self._spi.create_identity_tenant_membership_repository(
            uow
        ).get(session.identity_id, tenant_id)
        if principal_tenant_membership is None or identity_tenant_membership is None:
            raise SessionContextError(
                "effective-Role resolution requires explicit same-Tenant Principal and "
                "Identity memberships"
            )
        principal_tenant_memberships: tuple[PrincipalTenantMembership, ...] = (
            principal_tenant_membership,
        )
        identity_tenant_memberships: tuple[IdentityTenantMembership, ...] = (
            identity_tenant_membership,
        )
        validate_session_context(
            session,
            tenant,
            principal,
            identity,
            principal_tenant_memberships,
            identity_tenant_memberships,
        )

        target_organization = None
        if target_organization_id is not None:
            target_organization = self._spi.create_organization_repository(uow).get(
                target_organization_id
            )
            if target_organization is None:
                raise SessionContextError(
                    "effective-Role resolution target Organization does not exist"
                )
            if target_organization.tenant_id != tenant_id:
                raise TenantBoundaryError(
                    "effective-Role resolution target Organization belongs to another Tenant"
                )
        organization_eligible = target_organization is not None and not target_organization.deleted

        candidate_urns: set[RoleUrn] = set()
        self._collect_direct_roles(
            uow,
            tenant_id=tenant_id,
            identity_id=identity.id,
            target_organization_id=target_organization_id,
            organization_eligible=organization_eligible,
            candidate_urns=candidate_urns,
        )
        self._collect_group_roles(
            uow,
            tenant_id=tenant_id,
            identity_id=identity.id,
            target_organization_id=target_organization_id,
            organization_eligible=organization_eligible,
            candidate_urns=candidate_urns,
        )

        roles = self._load_roles(uow, tenant_id=tenant_id, candidate_urns=candidate_urns)
        return ResolvedAuthorizationState(
            session=session,
            tenant=tenant,
            principal=principal,
            identity=identity,
            principal_tenant_memberships=principal_tenant_memberships,
            identity_tenant_memberships=identity_tenant_memberships,
            applicable_roles=roles,
            target_organization_id=target_organization_id,
            diagnostics=(
                f"EffectiveRoleResolver(tenant={tenant_id}, identity={identity.id}, "
                f"target_organization={target_organization_id}, applicable_roles={len(roles)})"
            ),
        )

    def _collect_direct_roles(
        self,
        uow: UnitOfWork,
        *,
        tenant_id: DomainId,
        identity_id: DomainId,
        target_organization_id: DomainId | None,
        organization_eligible: bool,
        candidate_urns: set[RoleUrn],
    ) -> None:
        """Collect eligible direct Identity Role-assignment URNs."""
        repository = self._spi.create_identity_role_assignment_repository(uow)
        organization_memberships = self._spi.create_identity_org_membership_repository(uow)
        for assignment in repository.find_by_tenant_and_identity(tenant_id, identity_id):
            if assignment.organization_id is None:
                candidate_urns.add(assignment.role_urn)
                continue
            if not organization_eligible or assignment.organization_id != target_organization_id:
                continue
            if organization_memberships.get(identity_id, assignment.organization_id) is not None:
                candidate_urns.add(assignment.role_urn)

    def _collect_group_roles(
        self,
        uow: UnitOfWork,
        *,
        tenant_id: DomainId,
        identity_id: DomainId,
        target_organization_id: DomainId | None,
        organization_eligible: bool,
        candidate_urns: set[RoleUrn],
    ) -> None:
        """Collect eligible Group Role-assignment URNs through same-Tenant memberships."""
        identity_group_memberships = self._spi.create_identity_group_membership_repository(uow)
        group_repository = self._spi.create_group_repository(uow)
        group_tenant_memberships = self._spi.create_group_tenant_membership_repository(uow)
        group_assignments = self._spi.create_group_role_assignment_repository(uow)
        group_organization_memberships = self._spi.create_group_org_membership_repository(uow)
        seen_groups: set[DomainId] = set()
        for membership in identity_group_memberships.find_by_identity(identity_id):
            if membership.group_id in seen_groups:
                continue
            seen_groups.add(membership.group_id)
            group = group_repository.get(membership.group_id)
            if group is None:
                raise EffectiveRoleIntegrityError(
                    "IdentityGroupMembership references an unknown Group"
                )
            if group.tenant_id != tenant_id or group.deleted:
                # A Group outside the session Tenant contributes nothing; a
                # deleted Group contributes nothing. Neither is unioned in.
                continue
            if group_tenant_memberships.get(group.id, tenant_id) is None:
                continue
            for assignment in group_assignments.find_by_tenant_and_group(tenant_id, group.id):
                if assignment.organization_id is None:
                    candidate_urns.add(assignment.role_urn)
                    continue
                if (
                    not organization_eligible
                    or assignment.organization_id != target_organization_id
                ):
                    continue
                if (
                    group_organization_memberships.get(group.id, assignment.organization_id)
                    is not None
                ):
                    candidate_urns.add(assignment.role_urn)

    def _load_roles(
        self,
        uow: UnitOfWork,
        *,
        tenant_id: DomainId,
        candidate_urns: set[RoleUrn],
    ) -> tuple[Role, ...]:
        """Load each eligible Role aggregate and enforce definition namespace."""
        repository = self._spi.create_role_repository(uow)
        roles: list[Role] = []
        for role_urn in candidate_urns:
            role = repository.get(role_urn)
            if role is None:
                raise EffectiveRoleIntegrityError(
                    f"role assignment references an unknown Role {role_urn.value!r}"
                )
            defining_tenant_id = role.defining_tenant_id
            if defining_tenant_id is not None and defining_tenant_id != tenant_id:
                raise EffectiveRoleIntegrityError(
                    "a TENANT-defined Role is assigned outside its defining Tenant"
                )
            roles.append(role)
        # Deduplicate by Role URN only after eligibility; sorting is for
        # deterministic diagnostics and never encodes authorization
        # precedence.
        roles.sort(key=lambda role: role.urn.value)
        return tuple(roles)
