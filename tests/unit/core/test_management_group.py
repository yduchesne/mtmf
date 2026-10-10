"""Structural TenantManagementGroup domain tests (PR 11, non-gated subset).

These tests cover the settled structural invariants only (plan matrix
U01-U07). They deliberately contain **no** delegated-authorization ALLOW
cases: manager-side actor eligibility remains unresolved (Gate D), and a
structural management relationship must never be treated as a grant.
"""

from __future__ import annotations

import pytest
from helpers import make_id, make_identity, make_role_urn, make_tenant

from mtmf_core import (
    ROOT_MANAGEMENT_ROLE_URN,
    SYSTEM_MANAGEMENT_ROLE_URN,
    DomainInvariantError,
    IdentityTenantMembership,
    ImmutabilityError,
    ManagementGroupInvariantError,
    RoleUrn,
    SecurityScope,
    TenantManagementGroup,
    TenantManagementGroupActorEligibility,
    TenantManagementGroupMembership,
    TenantManagementScope,
    validate_tenant_management_group,
    validate_tenant_management_group_actor_eligibility,
    validate_tenant_management_group_membership,
)


def _root_group(manager_id, *, scope=TenantManagementScope.ROOT, role_urn=None):
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


def _membership(group_id, tenant_id):
    return TenantManagementGroupMembership(make_id(), group_id, tenant_id)


# --- U01 / U02: ROOT manager invariants ---------------------------------------


def test_u01_root_group_with_canonical_manager_accepted() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    group = _root_group(root.id)
    validate_tenant_management_group(group, manager_tenant=root, canonical_root_tenant_id=root.id)


def test_u02_root_group_with_ordinary_manager_rejected() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    ordinary = make_tenant("Ordinary", scope=SecurityScope.TENANT)
    group = _root_group(ordinary.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=ordinary, canonical_root_tenant_id=root.id
        )


def test_root_group_rejects_root_scope_tenant_that_is_not_canonical() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    impostor = make_tenant("Impostor", scope=SecurityScope.ROOT)
    group = _root_group(impostor.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=impostor, canonical_root_tenant_id=root.id
        )


def test_root_group_rejects_manager_scope_mismatch() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    group = _root_group(root.id)
    # A TENANT-scope Tenant cannot be the ROOT manager even if it shares the
    # canonical ID (the scope check fails after the ID match).
    forged = make_tenant("Root", scope=SecurityScope.TENANT)
    object.__setattr__(forged, "id", root.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=forged, canonical_root_tenant_id=root.id
        )


# --- U03: SYSTEM manager invariants -------------------------------------------


def test_u03_system_group_with_ordinary_manager_accepted() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    validate_tenant_management_group(
        group, manager_tenant=manager, canonical_root_tenant_id=root.id
    )


def test_system_group_with_root_manager_rejected() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    group = _root_group(root.id, scope=TenantManagementScope.SYSTEM)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=root, canonical_root_tenant_id=root.id
        )


def test_group_rejects_soft_deleted_manager() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    manager.soft_delete()
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=manager, canonical_root_tenant_id=root.id
        )


def test_group_rejects_manager_id_mismatch() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(make_id(), scope=TenantManagementScope.SYSTEM)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=manager, canonical_root_tenant_id=root.id
        )


# --- U04: scope vocabulary ----------------------------------------------------


def test_u04_invalid_management_scope_rejected() -> None:
    with pytest.raises(DomainInvariantError):
        _root_group(make_id(), scope=99)  # type: ignore[arg-type]


def test_immutable_group_fields_rejected() -> None:
    group = _root_group(make_id())
    with pytest.raises(ImmutabilityError):
        group.manager_tenant_id = make_id()
    with pytest.raises(ImmutabilityError):
        group.scope = TenantManagementScope.SYSTEM
    with pytest.raises(ImmutabilityError):
        group.management_role_urn = RoleUrn(SYSTEM_MANAGEMENT_ROLE_URN)


def test_group_rejects_non_approved_system_role() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM, role_urn=make_role_urn())
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=manager, canonical_root_tenant_id=root.id
        )


def test_group_rejects_tenant_defined_role() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(
        manager.id,
        scope=TenantManagementScope.SYSTEM,
        role_urn=make_role_urn(tenant_id=manager.id),
    )
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=manager, canonical_root_tenant_id=root.id
        )


def test_group_rejects_system_role_for_root_scope() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    group = _root_group(
        root.id, scope=TenantManagementScope.ROOT, role_urn=RoleUrn(SYSTEM_MANAGEMENT_ROLE_URN)
    )
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group(
            group, manager_tenant=root, canonical_root_tenant_id=root.id
        )


def test_immutable_membership_fields_rejected() -> None:
    membership = _membership(make_id(), make_id())
    with pytest.raises(ImmutabilityError):
        membership.tenant_id = make_id()
    with pytest.raises(ImmutabilityError):
        membership.management_group_id = make_id()


# --- U05 / U06 / U07: explicit membership invariants --------------------------


def test_u05_root_explicit_membership_attempt_rejected() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    target = make_tenant("Target", scope=SecurityScope.TENANT)
    group = _root_group(root.id)
    membership = _membership(group.id, target.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_membership(
            membership,
            management_group=group,
            tenant=target,
            canonical_root_tenant_id=root.id,
        )


def test_u06_system_membership_target_mismatch_rejected() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    target = make_tenant("Target", scope=SecurityScope.TENANT)
    other = make_tenant("Other", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    membership = _membership(group.id, target.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_membership(
            membership,
            management_group=group,
            tenant=other,
            canonical_root_tenant_id=root.id,
        )


def test_system_membership_accepted_for_ordinary_target() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    target = make_tenant("Target", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    membership = _membership(group.id, target.id)
    validate_tenant_management_group_membership(
        membership,
        management_group=group,
        tenant=target,
        canonical_root_tenant_id=root.id,
    )


def test_membership_rejects_group_id_mismatch() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    target = make_tenant("Target", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    membership = _membership(make_id(), target.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_membership(
            membership,
            management_group=group,
            tenant=target,
            canonical_root_tenant_id=root.id,
        )


def test_membership_rejects_root_target() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    membership = _membership(group.id, root.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_membership(
            membership,
            management_group=group,
            tenant=root,
            canonical_root_tenant_id=root.id,
        )


def test_membership_rejects_self_management_restrictive_default() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    membership = _membership(group.id, manager.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_membership(
            membership,
            management_group=group,
            tenant=manager,
            canonical_root_tenant_id=root.id,
        )


def test_membership_rejects_soft_deleted_target() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    target = make_tenant("Target", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    membership = _membership(group.id, target.id)
    target.soft_delete()
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_membership(
            membership,
            management_group=group,
            tenant=target,
            canonical_root_tenant_id=root.id,
        )


# --- D01 eligibility designations --------------------------------------------


def test_eligibility_designation_accepted_for_manager_member() -> None:
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    identity = make_identity()
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, identity.id)
    validate_tenant_management_group_actor_eligibility(
        eligibility,
        management_group=group,
        identity=identity,
        identity_tenant_memberships=(IdentityTenantMembership(identity.id, manager.id),),
    )


def test_eligibility_rejected_for_root_group() -> None:
    root = make_tenant("Root", scope=SecurityScope.ROOT)
    group = _root_group(root.id)
    identity = make_identity()
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, identity.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_actor_eligibility(
            eligibility,
            management_group=group,
            identity=identity,
            identity_tenant_memberships=(IdentityTenantMembership(identity.id, root.id),),
        )


def test_eligibility_requires_manager_tenant_membership() -> None:
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    other = make_tenant("Other", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    identity = make_identity()
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, identity.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_actor_eligibility(
            eligibility,
            management_group=group,
            identity=identity,
            identity_tenant_memberships=(IdentityTenantMembership(identity.id, other.id),),
        )


def test_eligibility_rejects_soft_deleted_identity() -> None:
    manager = make_tenant("Manager", scope=SecurityScope.TENANT)
    group = _root_group(manager.id, scope=TenantManagementScope.SYSTEM)
    identity = make_identity()
    identity.soft_delete()
    eligibility = TenantManagementGroupActorEligibility(make_id(), group.id, identity.id)
    with pytest.raises(ManagementGroupInvariantError):
        validate_tenant_management_group_actor_eligibility(
            eligibility,
            management_group=group,
            identity=identity,
            identity_tenant_memberships=(IdentityTenantMembership(identity.id, manager.id),),
        )
