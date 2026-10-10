"""Fail-closed TenantManagementGroup contextual resolution (PR 11).

This module implements the structural contextual-coverage step and the
approved manager-side eligibility rule of TenantManagementGroup
evaluation. Given a verified session and an explicit target Tenant it
decides whether a ROOT or SYSTEM management relationship covers the
target, and whether the verified acting Identity is explicitly eligible
under the approved Gate D policy.

The result is a typed, detached :class:`ManagementScopeResolution`. It
carries a structural *candidate* and an explicit ``actor_eligible`` flag;
``elevated_scope`` is only non-``None`` when both coverage and eligibility
are positively established. The resolver never evaluates a Permission and
never returns an authorization decision: the existing
:class:`~mtmf_core.authorization.authorizer.Authorizer` remains the
authoritative decision point, and the management Role must independently
authorize the exact Action.

The resolver consumes only already-loaded structural facts and the
verified :class:`~mtmf_core.domain.session.SessionContext`. It performs no
I/O, no caching, and no persistence, and it never treats a caller-supplied
identifier as authenticated authority.
"""

from __future__ import annotations

from collections.abc import Iterable

from mtmf_core.authorization.management import (
    ManagementScopeCandidate,
    ManagementScopeResolution,
)
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.lifecycle import TenantLifecycle
from mtmf_core.domain.management_group import (
    TenantManagementGroup,
    TenantManagementGroupActorEligibility,
    TenantManagementGroupMembership,
    TenantManagementScope,
)
from mtmf_core.domain.session import SessionContext
from mtmf_core.domain.tenant import Tenant

__all__ = [
    "ManagementScopeCandidate",
    "ManagementScopeResolution",
    "resolve_management_scope",
]

#: Stable, non-authorizing reasons reported when eligibility cannot be
#: positively established. Missing/unknown context always fails closed.
_LIFECYCLE_CONTEXT_UNAVAILABLE = (
    "manager/target Tenant lifecycle context is unavailable; eligibility cannot be established"
)
_LIFECYCLE_INVALID = "manager or target Tenant is not an active, non-deleted participant"
_NOT_ELIGIBLE = "the verified acting Identity is not explicitly eligible for this management group"
_NO_ELIGIBILITY_DESIGNATION = (
    "no explicit Identity-level eligibility designation exists for the verified acting Identity"
)
_ROOT_IDENTITY_MISMATCH = "only the canonical root Identity may exercise the ROOT management group"


def _is_active(tenant: Tenant) -> bool:
    return tenant.lifecycle is TenantLifecycle.ACTIVE and not tenant.deleted


def resolve_management_scope(
    *,
    session: SessionContext,
    target_tenant_id: DomainId,
    management_groups: Iterable[TenantManagementGroup],
    memberships: Iterable[TenantManagementGroupMembership],
    canonical_root_tenant_id: DomainId,
    actor_eligibilities: Iterable[TenantManagementGroupActorEligibility] = (),
    manager_tenant: Tenant | None = None,
    target_tenant: Tenant | None = None,
    canonical_root_identity_id: DomainId | None = None,
) -> ManagementScopeResolution:
    """Resolve structural coverage and eligibility for a verified session.

    Coverage:

    - a ``ROOT`` management group managed by the canonical root Tenant
      covers every target Tenant implicitly;
    - a ``SYSTEM`` management group covers only a target with an explicit
      :class:`TenantManagementGroupMembership` row.

    Eligibility (approved Gate D policy):

    - the manager and target Tenants must be ACTIVE and not soft-deleted;
    - a ``SYSTEM`` candidate requires an explicit
      :class:`TenantManagementGroupActorEligibility` designation for the
      verified acting Identity;
    - a ``ROOT`` candidate requires the verified acting Identity to be the
      canonical root Identity.

    Missing, unknown, or invalid lifecycle/eligibility context fails closed
    (``actor_eligible=False``). This function makes no authorization
    decision and MUST NOT be used to construct an ALLOW by itself.

    :param session: the already-verified acting ``(Tenant, Principal,
        Identity)`` context. Only its Tenant/Identity select and qualify a
        candidate; they are never treated as an eligibility proof unless a
        matching persisted/structural fact exists.
    :param target_tenant_id: the explicit target Tenant being evaluated.
    :param management_groups: already-loaded structural management groups.
    :param memberships: already-loaded explicit managed-Tenant rows.
    :param canonical_root_tenant_id: the canonical root Tenant's stable ID.
    :param actor_eligibilities: already-loaded explicit eligibility
        designations.
    :param manager_tenant: the manager (session) Tenant, when loaded.
    :param target_tenant: the target Tenant, when loaded.
    :param canonical_root_identity_id: the canonical root Identity's stable
        ID, when the root registry is available.
    """
    manager_tenant_id = session.tenant_id
    membership_targets = {
        (membership.management_group_id, membership.tenant_id) for membership in memberships
    }
    eligible_pairs = {
        (eligibility.management_group_id, eligibility.identity_id)
        for eligibility in actor_eligibilities
    }
    candidates: list[TenantManagementGroup] = []
    for group in management_groups:
        if group.manager_tenant_id != manager_tenant_id:
            continue
        if group.scope is TenantManagementScope.ROOT:
            if manager_tenant_id == canonical_root_tenant_id:
                candidates.append(group)
        elif (
            group.scope is TenantManagementScope.SYSTEM
            and (
                group.id,
                target_tenant_id,
            )
            in membership_targets
        ):
            candidates.append(group)
    if not candidates:
        return ManagementScopeResolution(candidate=None, actor_eligible=False, blocked_reason=None)
    # ROOT coverage outranks SYSTEM coverage for classification; remaining
    # ties are broken deterministically by stable ID. Ordering is diagnostic
    # only and never implies authorization precedence.
    candidates.sort(
        key=lambda group: (
            0 if group.scope is TenantManagementScope.ROOT else 1,
            str(group.id),
        )
    )
    chosen = candidates[0]
    candidate = ManagementScopeCandidate(
        management_group_id=chosen.id,
        scope=chosen.scope,
        management_role_urn=chosen.management_role_urn,
    )

    if manager_tenant is None or target_tenant is None:
        return ManagementScopeResolution(candidate, False, _LIFECYCLE_CONTEXT_UNAVAILABLE)
    if not _is_active(manager_tenant) or not _is_active(target_tenant):
        return ManagementScopeResolution(candidate, False, _LIFECYCLE_INVALID)

    if chosen.scope is TenantManagementScope.ROOT:
        if canonical_root_identity_id is None or session.identity_id != canonical_root_identity_id:
            return ManagementScopeResolution(candidate, False, _ROOT_IDENTITY_MISMATCH)
        return ManagementScopeResolution(candidate, True, None)

    if (chosen.id, session.identity_id) not in eligible_pairs:
        reason = _NO_ELIGIBILITY_DESIGNATION if not eligible_pairs else _NOT_ELIGIBLE
        return ManagementScopeResolution(candidate, False, reason)
    return ManagementScopeResolution(candidate, True, None)
