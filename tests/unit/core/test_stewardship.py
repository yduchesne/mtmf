"""Structural tests for the root/stewardship domain helpers (PR 10).

These tests prove the *settled structural* invariants only. They also record
that the helpers deliberately do not encode authentication or authorization
(see ``docs/PR10_IMPLEMENTATION_DECISIONS.md``). The approved PR 10
``IdentityOrigin``/``TenantLifecycle`` vocabulary and lifecycle-transition
validation are covered here as pure structural rules.
"""

import pytest
from helpers import make_id, make_identity, make_principal, make_tenant

from mtmf_core import (
    Identity,
    IdentityOrigin,
    IdentityTenantMembership,
    Principal,
    PrincipalTenantMembership,
    RootBootstrapRecord,
    RootInvariantError,
    SecurityScope,
    StewardshipInvariantError,
    Tenant,
    TenantLifecycle,
    TenantLifecycleError,
    TenantStewardshipDesignation,
    validate_root_bootstrap_record,
    validate_stewardship_designation,
    validate_tenant_lifecycle_transition,
)

# --- Root bootstrap record -----------------------------------------------------


def _valid_root() -> tuple[RootBootstrapRecord, Tenant, Principal, Identity]:
    tenant = make_tenant("Root", scope=SecurityScope.ROOT)
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    record = RootBootstrapRecord(
        root_tenant_id=tenant.id,
        root_principal_id=principal.id,
        root_identity_id=identity.id,
    )
    return record, tenant, principal, identity


def test_root_record_is_value_based_and_frozen() -> None:
    record, _, _, _ = _valid_root()
    assert record == RootBootstrapRecord(
        record.root_tenant_id, record.root_principal_id, record.root_identity_id
    )
    with pytest.raises(AttributeError):
        record.root_identity_id = make_id()


def test_valid_root_bootstrap_record_accepted() -> None:
    record, tenant, principal, identity = _valid_root()
    validate_root_bootstrap_record(
        record, root_tenant=tenant, root_principal=principal, root_identity=identity
    )


def test_root_record_rejects_non_root_tenant_scope() -> None:
    record, _, principal, identity = _valid_root()
    ordinary = make_tenant("Ordinary", scope=SecurityScope.TENANT)
    mismatched = RootBootstrapRecord(ordinary.id, record.root_principal_id, record.root_identity_id)
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            mismatched, root_tenant=ordinary, root_principal=principal, root_identity=identity
        )


def test_root_record_rejects_tenant_id_mismatch() -> None:
    record, _, principal, identity = _valid_root()
    tenant = make_tenant("Other Root", scope=SecurityScope.ROOT)
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            record, root_tenant=tenant, root_principal=principal, root_identity=identity
        )


def test_root_record_rejects_principal_id_mismatch() -> None:
    record, tenant, _, identity = _valid_root()
    other_principal = make_principal()
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            record, root_tenant=tenant, root_principal=other_principal, root_identity=identity
        )


def test_root_record_rejects_identity_id_mismatch() -> None:
    record, tenant, principal, _ = _valid_root()
    other_identity = make_identity(principal_id=principal.id)
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            record, root_tenant=tenant, root_principal=principal, root_identity=other_identity
        )


def test_root_record_rejects_identity_of_other_principal() -> None:
    record, tenant, principal, _ = _valid_root()
    foreign = make_identity(principal_id=make_id())
    forged = RootBootstrapRecord(record.root_tenant_id, principal.id, foreign.id)
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            forged, root_tenant=tenant, root_principal=principal, root_identity=foreign
        )


def test_root_record_rejects_shared_canonical_ids() -> None:
    # The ID-match checks must pass first; duplicate canonical IDs are then
    # rejected outright even though the supplied objects agree with them.
    shared = make_id()
    tenant = Tenant(shared, "Root", SecurityScope.ROOT, make_id())
    principal = Principal(shared, "Root Principal")
    identity = make_identity(principal_id=principal.id)
    forged = RootBootstrapRecord(
        root_tenant_id=shared, root_principal_id=shared, root_identity_id=identity.id
    )
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            forged, root_tenant=tenant, root_principal=principal, root_identity=identity
        )


@pytest.mark.parametrize("target", ["tenant", "principal", "identity"])
def test_root_record_rejects_soft_deleted_canonical_object(target: str) -> None:
    record, tenant, principal, identity = _valid_root()
    objects = {"tenant": tenant, "principal": principal, "identity": identity}
    objects[target].soft_delete()
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            record, root_tenant=tenant, root_principal=principal, root_identity=identity
        )


# --- Tenant stewardship designation -------------------------------------------


def _valid_designation() -> tuple[
    TenantStewardshipDesignation,
    Tenant,
    Principal,
    Identity,
    list[PrincipalTenantMembership],
    list[IdentityTenantMembership],
]:
    tenant = make_tenant("Customer")
    principal = make_principal()
    identity = make_identity(principal_id=principal.id)
    designation = TenantStewardshipDesignation(
        tenant_id=tenant.id,
        steward_principal_id=principal.id,
        designated_identity_id=identity.id,
        version=1,
    )
    principal_memberships = [PrincipalTenantMembership(principal.id, tenant.id)]
    identity_memberships = [IdentityTenantMembership(identity.id, tenant.id)]
    return designation, tenant, principal, identity, principal_memberships, identity_memberships


def test_stewardship_designation_rejects_negative_version() -> None:
    with pytest.raises(StewardshipInvariantError):
        TenantStewardshipDesignation(make_id(), make_id(), make_id(), version=-1)


def test_valid_stewardship_designation_accepted() -> None:
    designation, tenant, principal, identity, pm, im = _valid_designation()
    validate_stewardship_designation(
        designation,
        tenant=tenant,
        steward_principal=principal,
        designated_identity=identity,
        principal_tenant_memberships=pm,
        identity_tenant_memberships=im,
    )


def test_designation_rejects_root_tenant() -> None:
    _, _, principal, identity, pm, im = _valid_designation()
    root_tenant = make_tenant("Root", scope=SecurityScope.ROOT)
    forged = TenantStewardshipDesignation(root_tenant.id, principal.id, identity.id, version=1)
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            forged,
            tenant=root_tenant,
            steward_principal=principal,
            designated_identity=identity,
            principal_tenant_memberships=pm,
            identity_tenant_memberships=im,
        )


def test_designation_rejects_tenant_id_mismatch() -> None:
    designation, _, principal, identity, pm, im = _valid_designation()
    other_tenant = make_tenant("Other")
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            designation,
            tenant=other_tenant,
            steward_principal=principal,
            designated_identity=identity,
            principal_tenant_memberships=pm,
            identity_tenant_memberships=im,
        )


def test_designation_rejects_principal_id_mismatch() -> None:
    designation, tenant, _, identity, pm, im = _valid_designation()
    other_principal = make_principal()
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            designation,
            tenant=tenant,
            steward_principal=other_principal,
            designated_identity=identity,
            principal_tenant_memberships=pm,
            identity_tenant_memberships=im,
        )


def test_designation_rejects_identity_id_mismatch() -> None:
    designation, tenant, principal, _, pm, im = _valid_designation()
    other_identity = make_identity(principal_id=principal.id)
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            designation,
            tenant=tenant,
            steward_principal=principal,
            designated_identity=other_identity,
            principal_tenant_memberships=pm,
            identity_tenant_memberships=im,
        )


def test_designation_rejects_identity_of_other_principal() -> None:
    designation, tenant, principal, _, pm, im = _valid_designation()
    foreign = make_identity(principal_id=make_id())
    forged = TenantStewardshipDesignation(
        designation.tenant_id, principal.id, foreign.id, version=1
    )
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            forged,
            tenant=tenant,
            steward_principal=principal,
            designated_identity=foreign,
            principal_tenant_memberships=pm,
            identity_tenant_memberships=im,
        )


def test_designation_rejects_missing_principal_membership() -> None:
    designation, tenant, principal, identity, _, im = _valid_designation()
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            designation,
            tenant=tenant,
            steward_principal=principal,
            designated_identity=identity,
            principal_tenant_memberships=[],
            identity_tenant_memberships=im,
        )


def test_designation_rejects_missing_identity_membership() -> None:
    designation, tenant, principal, identity, pm, _ = _valid_designation()
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            designation,
            tenant=tenant,
            steward_principal=principal,
            designated_identity=identity,
            principal_tenant_memberships=pm,
            identity_tenant_memberships=[],
        )


@pytest.mark.parametrize("target", ["tenant", "principal", "identity"])
def test_designation_rejects_soft_deleted_object(target: str) -> None:
    designation, tenant, principal, identity, pm, im = _valid_designation()
    objects = {"tenant": tenant, "principal": principal, "identity": identity}
    objects[target].soft_delete()
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            designation,
            tenant=tenant,
            steward_principal=principal,
            designated_identity=identity,
            principal_tenant_memberships=pm,
            identity_tenant_memberships=im,
        )


# --- Identity origin and Tenant lifecycle vocabulary ---------------------------


def test_identity_origin_exact_values() -> None:
    assert IdentityOrigin.LOCAL.value == 1
    assert IdentityOrigin.FEDERATED.value == 2
    assert set(IdentityOrigin) == {IdentityOrigin.LOCAL, IdentityOrigin.FEDERATED}


def test_tenant_lifecycle_exact_values() -> None:
    assert TenantLifecycle.PROVISIONING.value == 0
    assert TenantLifecycle.ACTIVE.value == 1
    assert TenantLifecycle.SUSPENDED.value == 2


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (TenantLifecycle.PROVISIONING, TenantLifecycle.ACTIVE),
        (TenantLifecycle.ACTIVE, TenantLifecycle.SUSPENDED),
        (TenantLifecycle.SUSPENDED, TenantLifecycle.ACTIVE),
        (TenantLifecycle.ACTIVE, TenantLifecycle.ACTIVE),
    ],
)
def test_permitted_ordinary_lifecycle_transitions(
    current: TenantLifecycle, target: TenantLifecycle
) -> None:
    validate_tenant_lifecycle_transition(current=current, target=target, is_root=False)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (TenantLifecycle.PROVISIONING, TenantLifecycle.SUSPENDED),
        (TenantLifecycle.SUSPENDED, TenantLifecycle.PROVISIONING),
        (TenantLifecycle.ACTIVE, TenantLifecycle.PROVISIONING),
    ],
)
def test_forbidden_ordinary_lifecycle_transitions(
    current: TenantLifecycle, target: TenantLifecycle
) -> None:
    with pytest.raises(TenantLifecycleError):
        validate_tenant_lifecycle_transition(current=current, target=target, is_root=False)


def test_root_lifecycle_must_remain_active() -> None:
    validate_tenant_lifecycle_transition(
        current=TenantLifecycle.ACTIVE, target=TenantLifecycle.ACTIVE, is_root=True
    )
    with pytest.raises(TenantLifecycleError):
        validate_tenant_lifecycle_transition(
            current=TenantLifecycle.ACTIVE, target=TenantLifecycle.SUSPENDED, is_root=True
        )
    with pytest.raises(TenantLifecycleError):
        validate_tenant_lifecycle_transition(
            current=TenantLifecycle.PROVISIONING, target=TenantLifecycle.ACTIVE, is_root=True
        )


def test_root_record_accepts_local_active_identity() -> None:
    record, tenant, principal, identity = _valid_root()
    validate_root_bootstrap_record(
        record,
        root_tenant=tenant,
        root_principal=principal,
        root_identity=identity,
        root_identity_origin=IdentityOrigin.LOCAL,
        root_tenant_lifecycle=TenantLifecycle.ACTIVE,
    )


def test_root_record_rejects_federated_root_identity() -> None:
    record, tenant, principal, identity = _valid_root()
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            record,
            root_tenant=tenant,
            root_principal=principal,
            root_identity=identity,
            root_identity_origin=IdentityOrigin.FEDERATED,
        )


def test_root_record_rejects_non_active_root_tenant() -> None:
    record, tenant, principal, identity = _valid_root()
    with pytest.raises(RootInvariantError):
        validate_root_bootstrap_record(
            record,
            root_tenant=tenant,
            root_principal=principal,
            root_identity=identity,
            root_tenant_lifecycle=TenantLifecycle.SUSPENDED,
        )


def test_designation_rejects_non_active_tenant() -> None:
    designation, tenant, principal, identity, pm, im = _valid_designation()
    with pytest.raises(StewardshipInvariantError):
        validate_stewardship_designation(
            designation,
            tenant=tenant,
            steward_principal=principal,
            designated_identity=identity,
            principal_tenant_memberships=pm,
            identity_tenant_memberships=im,
            tenant_lifecycle=TenantLifecycle.PROVISIONING,
        )
