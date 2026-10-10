"""Fail-closed TenantManagementGroup contextual-scope resolution (PR 11 subset).

This module implements the *structural* contextual-coverage step of
TenantManagementGroup evaluation: given a verified session and an explicit
target Tenant, decide whether a ROOT or SYSTEM management relationship
covers the target.

It deliberately returns a **candidate** scope and never an authorization
decision. The manager-side actor-eligibility rule remains ``UNRESOLVED``
(:mod:`docs/SECURITY_MODEL.md` section 20.2, :mod:`docs/DOMAIN_MODEL.md`
section 15); until the PR 11 decision gate is approved, no actor is
eligible and the candidate therefore never elevates authorization. A
candidate scope is not a grant, cannot override a Role ``DENY``, and does
not replace the independent management Role permission, Tenant-boundary,
lifecycle, or dominance checks.

The resolver consumes only already-loaded structural facts and the
verified :class:`~mtmf_core.domain.session.SessionContext`. It performs no
I/O, no caching, and no persistence, and it never treats a caller-supplied
actor identifier as authenticated authority.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from mtmf_core.domain.iam_urn import RoleUrn
from mtmf_core.domain.identity import DomainId
from mtmf_core.domain.management_group import (
    TenantManagementGroup,
    TenantManagementGroupMembership,
    TenantManagementScope,
)
from mtmf_core.domain.session import SessionContext

__all__ = [
    "ManagementScopeCandidate",
    "ManagementScopeResolution",
    "resolve_management_scope",
]

#: The stable, non-authorizing reason reported while the manager-side
#: actor-eligibility rule is unresolved (PR 11 Gate D).
_GATE_D_UNRESOLVED = (
    "manager-side actor eligibility is unresolved; contextual management scope "
    "cannot elevate authorization"
)


@dataclass(frozen=True, slots=True)
class ManagementScopeCandidate:
    """A structural contextual-coverage match, never an authorization grant.

    :attr:`management_group_id` identifies the covering management group,
    :attr:`scope` is its ``ROOT``/``SYSTEM`` classification, and
    :attr:`management_role_urn` is the management Role whose Permissions
    must independently authorize each exact Action. The candidate carries
    no actor eligibility and no decision.
    """

    management_group_id: DomainId
    scope: TenantManagementScope
    management_role_urn: RoleUrn


@dataclass(frozen=True, slots=True)
class ManagementScopeResolution:
    """The outcome of structural contextual-scope resolution.

    :attr:`candidate` is the covering management relationship, or ``None``
    when no relationship covers the target. :attr:`actor_eligible` records
    whether the verified acting Identity was established as eligible under
    an approved manager-side rule. It is always ``False`` until the PR 11
    decision gate is approved, so :attr:`elevated_scope` is ``None`` even
    when a candidate exists.
    """

    candidate: ManagementScopeCandidate | None
    actor_eligible: bool
    blocked_reason: str | None

    @property
    def elevated_scope(self) -> TenantManagementScope | None:
        """The candidate scope that may be applied, or ``None``.

        Returns the candidate scope only when actor eligibility has been
        positively established. While the eligibility rule is unresolved
        this is always ``None``: a management relationship alone never
        elevates authorization.
        """
        if self.candidate is not None and self.actor_eligible:
            return self.candidate.scope
        return None


def resolve_management_scope(
    *,
    session: SessionContext,
    target_tenant_id: DomainId,
    management_groups: Iterable[TenantManagementGroup],
    memberships: Iterable[TenantManagementGroupMembership],
    canonical_root_tenant_id: DomainId,
) -> ManagementScopeResolution:
    """Resolve structural management coverage for a verified session/target.

    - A ``ROOT`` management group managed by the canonical root Tenant
      covers every target Tenant implicitly, including Tenants created
      after bootstrap.
    - A ``SYSTEM`` management group covers only a target with an explicit
      :class:`TenantManagementGroupMembership` row.
    - Any other group, manager, or target yields no candidate.

    Manager-side actor eligibility is unresolved, so the result always
    reports ``actor_eligible=False``; the caller must therefore treat the
    candidate as non-elevating. This function makes no authorization
    decision and MUST NOT be used to construct an ALLOW by itself.

    :param session: the already-verified acting ``(Tenant, Principal,
        Identity)`` context. Only its Tenant selects candidate groups; its
        Principal/Identity are retained for the future eligibility rule and
        are never treated as an eligibility proof here.
    :param target_tenant_id: the explicit target Tenant being evaluated.
    :param management_groups: already-loaded structural management groups.
    :param memberships: already-loaded explicit managed-Tenant rows.
    :param canonical_root_tenant_id: the canonical root Tenant's stable ID.
    """
    manager_tenant_id = session.tenant_id
    membership_targets = {
        (membership.management_group_id, membership.tenant_id) for membership in memberships
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
    return ManagementScopeResolution(
        candidate=ManagementScopeCandidate(
            management_group_id=chosen.id,
            scope=chosen.scope,
            management_role_urn=chosen.management_role_urn,
        ),
        actor_eligible=False,
        blocked_reason=_GATE_D_UNRESOLVED,
    )
