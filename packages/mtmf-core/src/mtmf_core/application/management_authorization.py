"""Application-layer TenantManagementGroup authorization orchestration (PR 11).

This module coordinates the persisted structural facts required for a
delegated cross-Tenant evaluation and produces the trusted
:class:`~mtmf_core.authorization.context.AuthorizationContext` plus the
:class:`~mtmf_core.authorization.management.ManagementScopeResolution` that
the authoritative :class:`~mtmf_core.authorization.authorizer.Authorizer`
consumes.

It performs reads in exactly one UnitOfWork, never commits, never caches,
and makes no ALLOW/DENY decision. It loads the approved management Role
aggregate directly (never through ordinary same-Tenant Role-assignment
resolution) and supplies it as the sole applicable Role, so an ordinary
manager-Tenant Role can never be unioned into a delegated decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from mtmf_core.application.management_scope import resolve_management_scope
from mtmf_core.authorization.context import AuthorizationContext
from mtmf_core.authorization.management import ManagementScopeResolution
from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.identity_entity import Identity
from mtmf_core.domain.memberships import IdentityTenantMembership, PrincipalTenantMembership
from mtmf_core.domain.principal import Principal
from mtmf_core.domain.role import Role
from mtmf_core.domain.session import SessionContext
from mtmf_core.domain.tenant import Tenant
from mtmf_core.persistence.spi import MtmfSpi

__all__ = [
    "ManagementAuthorizationResolution",
    "ManagementAuthorizationResolver",
]


@dataclass(frozen=True, slots=True)
class ManagementAuthorizationResolution:
    """A detached delegated-context result, never an authorization decision."""

    context: AuthorizationContext
    management_scope: ManagementScopeResolution

    @property
    def is_elevated(self) -> bool:
        """True only when coverage and explicit actor eligibility exist."""
        return self.management_scope.elevated_scope is not None


class ManagementAuthorizationResolver:
    """Resolves delegated management context from persisted structural facts.

    This is application-layer orchestration, not an authorization decision
    point. The returned context carries exactly the approved management Role
    (or nothing when there is no elevated scope) and must still be evaluated
    by the :class:`Authorizer`.
    """

    __slots__ = ("_spi",)

    def __init__(self, spi: MtmfSpi) -> None:
        self._spi = spi

    def resolve(
        self,
        *,
        session: SessionContext,
        target_tenant_id: DomainId,
        manager_tenant: Tenant,
        manager_principal: Principal,
        manager_identity: Identity,
        principal_tenant_memberships: tuple[PrincipalTenantMembership, ...],
        identity_tenant_memberships: tuple[IdentityTenantMembership, ...],
        target_tenant: Tenant,
        canonical_root_tenant_id: DomainId,
        canonical_root_identity_id: DomainId | None,
    ) -> ManagementAuthorizationResolution:
        """Load structural facts and build the delegated context.

        The caller supplies already-verified session objects; this method
        never treats a caller-supplied identifier as authentication.
        """
        with self._spi.create_unit_of_work() as uow:
            groups = self._spi.create_tenant_management_group_repository(uow)
            memberships = self._spi.create_tenant_management_group_membership_repository(uow)
            eligibilities = self._spi.create_tenant_management_group_actor_eligibility_repository(
                uow
            )
            roles = self._spi.create_role_repository(uow)

            manager_groups = groups.find_by_manager(session.tenant_id)
            resolution = resolve_management_scope(
                session=session,
                target_tenant_id=target_tenant_id,
                management_groups=manager_groups,
                memberships=tuple(
                    member
                    for group in manager_groups
                    for member in memberships.find_by_group(group.id)
                ),
                canonical_root_tenant_id=canonical_root_tenant_id,
                actor_eligibilities=tuple(
                    eligibility
                    for group in manager_groups
                    for eligibility in eligibilities.find_by_group(group.id)
                ),
                manager_tenant=manager_tenant,
                target_tenant=target_tenant,
                canonical_root_identity_id=canonical_root_identity_id,
            )
            applicable_roles: tuple[Role, ...] = ()
            if resolution.candidate is not None and resolution.actor_eligible:
                role = roles.get(RoleUrn(resolution.candidate.management_role_urn.value))
                if role is not None:
                    applicable_roles = (role,)
                else:
                    # Missing management Role is fail-closed: no policy.
                    resolution = ManagementScopeResolution(
                        candidate=resolution.candidate,
                        actor_eligible=False,
                        blocked_reason="the approved management Role aggregate is missing",
                    )
            context = AuthorizationContext(
                session=session,
                tenant=manager_tenant,
                principal=manager_principal,
                identity=manager_identity,
                principal_tenant_memberships=principal_tenant_memberships,
                identity_tenant_memberships=identity_tenant_memberships,
                applicable_roles=applicable_roles,
            )
        return ManagementAuthorizationResolution(context=context, management_scope=resolution)
