"""HTTP-facing adapter for the PR 19C management membership add.

This is a narrow transport adapter, not a second authorizer or a second
mutation service. It invokes the existing trusted
:class:`~mtmf_core.application.management_memberships.ManagementMembershipService`
exactly once; that service already resolves both verified tokens, performs
the ordered row lock, effective-Role resolution, the authoritative
exact-Action ``Authorizer`` call, the steward guard, provenance and the
atomic audited write in one real UnitOfWork. The adapter performs no
policy decision and opens no UnitOfWork.

Typed guard/denial failures become the opaque public ``FORBIDDEN`` error;
authentication failures and infrastructure faults flow through the existing
:func:`~mtmf_service.errors.map_exception` mapping unchanged. No exception
text, SQLSTATE, actor, target or policy detail is disclosed.
"""

from __future__ import annotations

from mtmf_api.errors import ApiErrorCode
from mtmf_api.management import (
    IdentityGroupMembershipAddRequest,
    IdentityGroupMembershipAddResponse,
)
from mtmf_core.application.management_memberships import (
    ManagementAuthorizationDeniedError,
    ManagementMembershipService,
)
from mtmf_core.domain.errors import SessionContextError, TenantBoundaryError
from mtmf_core.domain.identity import DomainId
from mtmf_core.persistence.errors import PersistenceReferenceError
from mtmf_service.errors import PublicError

__all__ = ["ManagementMembershipHttpService"]


class ManagementMembershipHttpService:
    """Adapt one verified DTO request to the existing trusted use case."""

    __slots__ = ("_membership_service",)

    def __init__(self, *, membership_service: ManagementMembershipService) -> None:
        self._membership_service = membership_service

    def add_identity_to_group(
        self,
        *,
        service_token: str,
        user_token: str,
        request: IdentityGroupMembershipAddRequest,
    ) -> IdentityGroupMembershipAddResponse:
        """Return the detached response for one authenticated request.

        :raises PublicError: ``FORBIDDEN`` for an authenticated actor whose
            exact Action or operation-specific guard denies the operation,
            or whose target/prerequisite is invalid (never disclosed).
        :raises mtmf_core.authentication.contracts.AuthenticationError: for
            token/eligibility failures (mapped by the HTTP boundary).
        :raises mtmf_core.persistence.errors.PersistenceError: for a
            dependency/infrastructure failure.
        """
        try:
            result = self._membership_service.add_identity_to_group(
                service_token=service_token,
                user_token=user_token,
                tenant_id=DomainId(request.tenant_id),
                identity_id=DomainId(request.identity_id),
                group_id=DomainId(request.group_id),
            )
        except (
            ManagementAuthorizationDeniedError,
            PersistenceReferenceError,
            SessionContextError,
            TenantBoundaryError,
        ) as exc:
            # Opaque denial: never distinguish an unknown target, an
            # ineligible prerequisite, a missing grant or a steward-guard
            # failure, and never fingerprint the persisted state.
            raise PublicError(ApiErrorCode.FORBIDDEN) from exc
        return IdentityGroupMembershipAddResponse(
            tenant_id=request.tenant_id,
            identity_id=request.identity_id,
            group_id=request.group_id,
            created=result.created,
        )
