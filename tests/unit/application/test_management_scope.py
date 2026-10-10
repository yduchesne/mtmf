"""Fail-closed TenantManagementGroup contextual-resolution tests (PR 11).

Covers the non-gated structural coverage matrix (plan U08-U15). The
resolver returns a *candidate* management scope and never an ALLOW;
manager-side actor eligibility remains unresolved (Gate D), so
``elevated_scope`` is always ``None`` in these tests.
"""

from __future__ import annotations

from helpers import make_id, make_identity, make_principal, make_tenant

from mtmf_core import (
    ROOT_MANAGEMENT_ROLE_URN,
    SYSTEM_MANAGEMENT_ROLE_URN,
    RoleUrn,
    SecurityScope,
    SessionContext,
    TenantLifecycle,
    TenantManagementGroup,
    TenantManagementGroupActorEligibility,
    TenantManagementGroupMembership,
    TenantManagementScope,
    resolve_management_scope,
)


def _session(tenant_id):
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    return SessionContext(tenant_id, principal.id, identity.id)


def _group(manager_id, scope, role_urn=None):
    approved = (
        ROOT_MANAGEMENT_ROLE_URN
        if scope is TenantManagementScope.ROOT
        else SYSTEM_MANAGEMENT_ROLE_URN
    )
    return TenantManagementGroup(
        make_id(),
        manager_id,
        role_urn if role_urn is not None else RoleUrn(approved),
        scope,
    )


def test_u08_root_group_covers_existing_and_new_tenants_implicitly() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    existing = make_tenant("Existing")
    future = make_tenant("Future")
    group = _group(root.id, TenantManagementScope.ROOT)

    for target in (existing, future):
        resolution = resolve_management_scope(
            session=_session(root.id),
            target_tenant_id=target.id,
            management_groups=[group],
            memberships=[],
            canonical_root_tenant_id=root.id,
        )
        assert resolution.candidate is not None
        assert resolution.candidate.scope is TenantManagementScope.ROOT
        assert resolution.candidate.management_group_id == group.id


def test_u09_system_group_covers_explicit_target() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)

    resolution = resolve_management_scope(
        session=_session(manager.id),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
    )
    assert resolution.candidate is not None
    assert resolution.candidate.scope is TenantManagementScope.SYSTEM


def test_u10_system_group_absent_target_has_no_candidate() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    listed = make_tenant("Listed")
    unlisted = make_tenant("Unlisted")
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, listed.id)

    resolution = resolve_management_scope(
        session=_session(manager.id),
        target_tenant_id=unlisted.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
    )
    assert resolution.candidate is None
    assert resolution.elevated_scope is None
    assert resolution.actor_eligible is False


def test_u11_candidate_scope_alone_never_elevates() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)

    resolution = resolve_management_scope(
        session=_session(manager.id),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
    )
    assert resolution.candidate is not None
    # A structural relationship is not a grant: without approved eligibility
    # the candidate cannot elevate authorization.
    assert resolution.elevated_scope is None
    assert resolution.actor_eligible is False
    assert resolution.blocked_reason is not None


def test_u13_actor_eligibility_is_unresolved_fail_closed() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    group = _group(root.id, TenantManagementScope.ROOT)
    resolution = resolve_management_scope(
        session=_session(root.id),
        target_tenant_id=make_tenant("Target").id,
        management_groups=[group],
        memberships=[],
        canonical_root_tenant_id=root.id,
    )
    assert resolution.candidate is not None
    assert resolution.actor_eligible is False
    assert resolution.elevated_scope is None


def test_u14_manager_intrinsic_scope_is_unchanged() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)

    resolve_management_scope(
        session=_session(manager.id),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
    )
    # Contextual coverage never mutates the manager Tenant's intrinsic scope.
    assert manager.scope is SecurityScope.TENANT


def test_u15_unrelated_manager_context_has_no_candidate() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    unrelated = make_tenant("Unrelated")
    target = make_tenant("Target")
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)

    resolution = resolve_management_scope(
        session=_session(unrelated.id),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
    )
    assert resolution.candidate is None
    assert resolution.elevated_scope is None


def test_multiple_system_coverages_choose_deterministically() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    first = _group(manager.id, TenantManagementScope.SYSTEM)
    second = _group(manager.id, TenantManagementScope.SYSTEM)
    memberships = [
        TenantManagementGroupMembership(make_id(), first.id, target.id),
        TenantManagementGroupMembership(make_id(), second.id, target.id),
    ]

    resolution = resolve_management_scope(
        session=_session(manager.id),
        target_tenant_id=target.id,
        management_groups=[second, first],
        memberships=memberships,
        canonical_root_tenant_id=root.id,
    )
    assert resolution.candidate is not None
    expected = min((first, second), key=lambda group: str(group.id))
    assert resolution.candidate.management_group_id == expected.id


def test_root_group_of_noncanonical_manager_yields_no_coverage() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    impostor = make_tenant("Impostor", scope=SecurityScope.ROOT)
    group = _group(impostor.id, TenantManagementScope.ROOT)
    resolution = resolve_management_scope(
        session=_session(impostor.id),
        target_tenant_id=make_tenant("Target").id,
        management_groups=[group],
        memberships=[],
        canonical_root_tenant_id=root.id,
    )
    assert resolution.candidate is None


def test_system_group_for_other_manager_is_ignored() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    other = make_tenant("Other")
    target = make_tenant("Target")
    group = _group(other.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)
    resolution = resolve_management_scope(
        session=_session(manager.id),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
    )
    assert resolution.candidate is None


# --- Approved eligibility semantics (D01/D03/D04) ----------------------------


def _session_for(tenant_id, identity):
    return SessionContext(tenant_id, identity.principal_id, identity.id)


def test_system_eligible_actor_yields_elevated_system_scope() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    identity = make_identity()
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, identity.id)
    resolution = resolve_management_scope(
        session=_session_for(manager.id, identity),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
        actor_eligibilities=[eligibility],
        manager_tenant=manager,
        target_tenant=target,
    )
    assert resolution.candidate is not None
    assert resolution.actor_eligible is True
    assert resolution.elevated_scope is TenantManagementScope.SYSTEM
    assert resolution.blocked_reason is None


def test_system_without_designation_is_not_eligible() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    identity = make_identity()
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)
    other_identity = make_identity()
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, other_identity.id)
    resolution = resolve_management_scope(
        session=_session_for(manager.id, identity),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
        actor_eligibilities=[eligibility],
        manager_tenant=manager,
        target_tenant=target,
    )
    assert resolution.candidate is not None
    assert resolution.actor_eligible is False
    assert resolution.elevated_scope is None


def test_root_group_requires_canonical_root_identity() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    target = make_tenant("Target")
    root_identity = make_identity()
    other_identity = make_identity()
    group = _group(root.id, TenantManagementScope.ROOT)

    eligible = resolve_management_scope(
        session=_session_for(root.id, root_identity),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[],
        canonical_root_tenant_id=root.id,
        manager_tenant=root,
        target_tenant=target,
        canonical_root_identity_id=root_identity.id,
    )
    assert eligible.actor_eligible is True
    assert eligible.elevated_scope is TenantManagementScope.ROOT

    denied = resolve_management_scope(
        session=_session_for(root.id, other_identity),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[],
        canonical_root_tenant_id=root.id,
        manager_tenant=root,
        target_tenant=target,
        canonical_root_identity_id=root_identity.id,
    )
    assert denied.candidate is not None
    assert denied.actor_eligible is False
    assert denied.elevated_scope is None


def test_missing_lifecycle_context_fails_closed() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    identity = make_identity()
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, identity.id)
    resolution = resolve_management_scope(
        session=_session_for(manager.id, identity),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
        actor_eligibilities=[eligibility],
    )
    assert resolution.actor_eligible is False
    assert resolution.elevated_scope is None


def test_suspended_or_deleted_participant_fails_closed() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager")
    target = make_tenant("Target")
    identity = make_identity()
    group = _group(manager.id, TenantManagementScope.SYSTEM)
    membership = TenantManagementGroupMembership(make_id(), group.id, target.id)
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, identity.id)

    manager.lifecycle = TenantLifecycle.SUSPENDED
    suspended = resolve_management_scope(
        session=_session_for(manager.id, identity),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
        actor_eligibilities=[eligibility],
        manager_tenant=manager,
        target_tenant=target,
    )
    assert suspended.actor_eligible is False

    manager.lifecycle = TenantLifecycle.ACTIVE
    target.soft_delete()
    deleted = resolve_management_scope(
        session=_session_for(manager.id, identity),
        target_tenant_id=target.id,
        management_groups=[group],
        memberships=[membership],
        canonical_root_tenant_id=root.id,
        actor_eligibilities=[eligibility],
        manager_tenant=manager,
        target_tenant=target,
    )
    assert deleted.actor_eligible is False
