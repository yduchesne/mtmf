"""Internal PR 24P operator and pre-Tenant admission contracts.

These value objects are detached, immutable, and carry no authority by
themselves. They are constructed only by the trusted verification/parsing
services and are never exported through the public API or connector packages.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from mtmf_core.authentication.contracts import VerifiedPreTenantSubject
from mtmf_core.domain.action import Action
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.role import Role

__all__ = [
    "APPROVED_SYSTEM_OPERATOR_ROLE_URN",
    "GLOBAL_OPERATION_ACTIONS",
    "GlobalApplicationTarget",
    "GlobalEntitlementTarget",
    "GlobalSystemAuthorizationRequest",
    "SystemOperatorAssignmentFacts",
    "VerifiedPreTenantAdmission",
    "VerifiedSystemOperator",
]

#: The sole PR 24P SYSTEM operator Role.
APPROVED_SYSTEM_OPERATOR_ROLE_URN = "urn:mtmf:iam:roles:system:application-administrator"

#: Fixed operation -> exact server-selected Action URN. Callers never choose it.
GLOBAL_OPERATION_ACTIONS: dict[str, str] = {
    "entitlement.grant": (
        "urn:mtmf:iam:actions:system:application-onboarding-entitlement:grant-object"
    ),
    "entitlement.revoke": (
        "urn:mtmf:iam:actions:system:application-onboarding-entitlement:revoke-object"
    ),
    "entitlement.get": (
        "urn:mtmf:iam:actions:system:application-onboarding-entitlement:get-object"
    ),
}


def _require_aware(value: datetime, name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


def _require_non_nil(value: DomainId, name: str) -> None:
    if not isinstance(value, DomainId) or value.value.int == 0:
        raise ValueError(f"{name} must be a canonical non-nil DomainId")


@dataclass(frozen=True, slots=True)
class VerifiedSystemOperator:
    """A genuine interactive operator proof (never an authorization decision)."""

    issuer: str
    subject: str
    identity_id: DomainId
    principal_id: DomainId
    user_token_expires_at: datetime
    verified_at: datetime
    token_class: str = "user"

    def __post_init__(self) -> None:
        if not self.issuer or not self.subject:
            raise ValueError("issuer and subject are required")
        _require_non_nil(self.identity_id, "identity_id")
        _require_non_nil(self.principal_id, "principal_id")
        _require_aware(self.user_token_expires_at, "user_token_expires_at")
        _require_aware(self.verified_at, "verified_at")
        if self.token_class != "user":
            raise ValueError("only an interactive user-class proof is permitted")


@dataclass(frozen=True, slots=True)
class GlobalApplicationTarget:
    """A global Application target, not a Tenant or SessionContext."""

    application_id: DomainId

    def __post_init__(self) -> None:
        _require_non_nil(self.application_id, "application_id")


@dataclass(frozen=True, slots=True)
class GlobalEntitlementTarget:
    """A global Application onboarding entitlement target."""

    application_id: DomainId
    entitlement_id: DomainId

    def __post_init__(self) -> None:
        _require_non_nil(self.application_id, "application_id")
        _require_non_nil(self.entitlement_id, "entitlement_id")


@dataclass(frozen=True, slots=True)
class SystemOperatorAssignmentFacts:
    """One persisted global assignment, already locked/validated by SQL."""

    assignment_id: DomainId
    identity_id: DomainId
    principal_id: DomainId
    role_urn: str
    state: int

    def __post_init__(self) -> None:
        _require_non_nil(self.assignment_id, "assignment_id")
        _require_non_nil(self.identity_id, "identity_id")
        _require_non_nil(self.principal_id, "principal_id")
        if self.role_urn != APPROVED_SYSTEM_OPERATOR_ROLE_URN:
            raise ValueError("only the approved SYSTEM operator Role is permitted")
        if self.state != 1:
            raise ValueError("only an ACTIVE assignment is permitted")


@dataclass(frozen=True, slots=True)
class GlobalSystemAuthorizationRequest:
    """Trusted, verified facts for one global SYSTEM target evaluation."""

    operator: VerifiedSystemOperator
    assignment: SystemOperatorAssignmentFacts
    role: Role
    target: GlobalApplicationTarget | GlobalEntitlementTarget
    action: Action

    def __post_init__(self) -> None:
        if self.assignment.identity_id != self.operator.identity_id:
            raise ValueError("assignment Identity must equal the verified operator Identity")
        if self.assignment.principal_id != self.operator.principal_id:
            raise ValueError("assignment Principal must equal the verified operator Principal")
        if str(self.role.urn) != APPROVED_SYSTEM_OPERATOR_ROLE_URN:
            raise ValueError("only the approved SYSTEM operator Role is permitted")
        if self.role.defining_tenant_id is not None:
            raise ValueError("the approved SYSTEM operator Role must not define a Tenant")
        if self.role.urn.definition_namespace.value != "system":
            raise ValueError("the approved operator Role must be SYSTEM-defined")


@dataclass(frozen=True, slots=True)
class VerifiedPreTenantAdmission:
    """A detached, non-authorizing pre-Tenant candidacy observation."""

    verified_subject: VerifiedPreTenantSubject
    entitlement_id: DomainId | None
    eligible_for_first_tenant: bool
    checked_at: datetime

    def __post_init__(self) -> None:
        _require_aware(self.checked_at, "checked_at")
        if self.entitlement_id is not None:
            _require_non_nil(self.entitlement_id, "entitlement_id")
        if self.eligible_for_first_tenant and self.entitlement_id is None:
            raise ValueError("an eligible candidate requires an entitlement id")
