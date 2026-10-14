"""Trusted orchestration for the PR 19C membership-add management operation.

This application-layer service is the single trusted entry point that turns
two independently verified tokens into one authenticated, authorized,
atomically audited Identity-to-Group membership add. It composes existing
seams and invents no authorization semantics:

    AuthenticatedActorContextService.resolve  (verification; no UoW)
        -> one UnitOfWork:
           IdentityGroupMembershipRepository.lock_verified_add
               (ordered row locks + structural/steward recheck)
           EffectiveRoleResolver.resolve + build_authorization_context
           Authorizer.authorize(exact Action, same-Tenant target)
           VerifiedMutationProvenance + require_registered_mutation
           IdentityGroupMembershipRepository.add_verified
               (membership INSERT + one audit row, atomically)
        -> commit -> detached result

The exact Action is the server-side approved constant; it never comes from
a request. A DENY or any failure rolls the UnitOfWork back, so no partial
membership or audit state can commit. The service performs no caching and no
IdP I/O inside the transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.application.effective_roles import (
    EffectiveRoleResolver,
    build_authorization_context,
)
from mtmf_core.application.mutation_provenance import (
    IDENTITY_GROUP_MEMBERSHIP_ADD_ACTION,
    VerifiedMutationProvenance,
    require_registered_mutation,
)
from mtmf_core.authorization.authorizer import Authorizer
from mtmf_core.authorization.context import AuthorizationRequest
from mtmf_core.domain.action import Action
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.session import SessionContext
from mtmf_core.persistence.spi import MtmfSpi

__all__ = [
    "ManagementAuthorizationDeniedError",
    "ManagementMembershipResult",
    "ManagementMembershipService",
]


class ManagementAuthorizationDeniedError(PermissionError):
    """The authoritative Authorizer did not return an explicit ALLOW.

    This is a fail-closed rejection, never a policy decision disclosed to a
    caller and never a mutation trigger.
    """


@dataclass(frozen=True, slots=True)
class ManagementMembershipResult:
    """Detached outcome of one membership-add attempt.

    ``created`` is ``True`` only when a new membership row (and exactly one
    audit row) committed; ``False`` is the idempotent duplicate no-op.
    ``operation_id`` is the server-generated per-attempt audit correlation,
    never a client idempotency key and never ``None`` for this operation.
    """

    tenant_id: DomainId
    identity_id: DomainId
    group_id: DomainId
    created: bool
    operation_id: UUID


class ManagementMembershipService:
    """Authenticated, authorized, atomically audited membership add."""

    __slots__ = ("_actor_service", "_authorizer", "_role_resolver", "_spi")

    def __init__(
        self,
        *,
        spi: MtmfSpi,
        actor_service: AuthenticatedActorContextService,
        role_resolver: EffectiveRoleResolver,
        authorizer: Authorizer,
    ) -> None:
        self._spi = spi
        self._actor_service = actor_service
        self._role_resolver = role_resolver
        self._authorizer = authorizer

    def add_identity_to_group(
        self,
        *,
        service_token: str,
        user_token: str,
        tenant_id: DomainId,
        identity_id: DomainId,
        group_id: DomainId,
    ) -> ManagementMembershipResult:
        """Add an existing Identity to an existing Group in one ordinary Tenant.

        :raises mtmf_core.authentication.contracts.AuthenticationError: when
            either token, the attestation, the bindings or the application
            eligibility fails.
        :raises ManagementAuthorizationDeniedError: when the authoritative
            Authorizer does not return ALLOW (default deny).
        :raises mtmf_core.persistence.errors.PersistenceError: for a
            structural/integrity/infrastructure failure. No partial state is
            committed.
        """
        # Verification happens before the transaction and outside any lock;
        # no remote IdP I/O occurs while a database transaction is open.
        verified = self._actor_service.resolve(
            service_token=service_token,
            user_token=user_token,
            tenant_id=tenant_id,
        )
        if verified.tenant_id != tenant_id:
            raise ManagementAuthorizationDeniedError(
                "the verified actor Tenant does not match the requested Tenant"
            )
        session = SessionContext(
            tenant_id=verified.tenant_id,
            principal_id=verified.principal_id,
            identity_id=verified.identity_id,
        )

        operation_id = uuid4()
        with self._spi.create_unit_of_work() as uow:
            membership_repository = self._spi.create_identity_group_membership_repository(uow)
            # Take the bounded row locks first so the authorization decision
            # below cannot be invalidated by a concurrent revocation before
            # commit. This never authorizes.
            membership_repository.lock_verified_add(
                tenant_id=tenant_id,
                actor_identity_id=verified.identity_id,
                subject_identity_id=identity_id,
                group_id=group_id,
            )
            state = self._role_resolver.resolve(uow, session=session, target_tenant_id=tenant_id)
            context = build_authorization_context(state)
            decision = self._authorizer.authorize(
                AuthorizationRequest(
                    context=context,
                    action=Action(IDENTITY_GROUP_MEMBERSHIP_ADD_ACTION),
                    target_tenant_id=tenant_id,
                )
            )
            if not decision.allowed:
                raise ManagementAuthorizationDeniedError(
                    "the requested membership add was not authorized"
                )
            provenance = VerifiedMutationProvenance(
                operation_id=operation_id,
                actor_identity_id=verified.identity_id,
                actor_principal_id=verified.principal_id,
                tenant_id=verified.tenant_id,
                application_id=verified.application_id,
                action_urn=IDENTITY_GROUP_MEMBERSHIP_ADD_ACTION,
                target_kind="identity_group_membership",
                target_id=group_id,
                authorized_at=datetime.now(UTC),
            )
            require_registered_mutation(provenance)
            created = membership_repository.add_verified(
                identity_id=identity_id,
                group_id=group_id,
                operation_id=provenance.operation_id,
                actor_identity_id=provenance.actor_identity_id,
                actor_principal_id=provenance.actor_principal_id,
                tenant_id=provenance.tenant_id,
                application_id=provenance.application_id,
                action_urn=provenance.action_urn,
                target_kind=provenance.target_kind,
                target_id=provenance.target_id,
                authorized_at=provenance.authorized_at_utc,
            )
            uow.commit()
        return ManagementMembershipResult(
            tenant_id=tenant_id,
            identity_id=identity_id,
            group_id=group_id,
            created=created,
            operation_id=operation_id,
        )
