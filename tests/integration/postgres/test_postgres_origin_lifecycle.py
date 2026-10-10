"""Identity origin and Tenant lifecycle persistence (revisions 0007-0008).

Uses the production PostgreSQL provider through the restricted runtime
login to prove the new fields round-trip, that illegal values are rejected
at the database boundary, that Identity origin is immutable, that runtime
Tenant creation must start PROVISIONING, that activation requires a
designation, and that the trusted effective-Role path fails closed for
non-ACTIVE ordinary Tenants.
"""

from __future__ import annotations

import psycopg
import pytest

from mtmf_core import (
    DomainId,
    Identity,
    IdentityOrigin,
    IdentityRoleAssignment,
    IdentityTenantMembership,
    Principal,
    PrincipalTenantMembership,
    RoleUrn,
    SecurityScope,
    SessionContext,
    Tenant,
    TenantLifecycle,
)
from mtmf_core.application import EffectiveRoleResolver
from mtmf_core.domain.errors import SessionContextError
from mtmf_core.persistence.errors import PersistenceIntegrityError
from mtmf_core.persistence.spi import MtmfSpi

_TENANT_ADMIN_URN = RoleUrn("urn:mtmf:iam:roles:system:tenant-administrator")


def _graph(spi: MtmfSpi, *, origin: IdentityOrigin) -> tuple[Tenant, Principal, Identity]:
    principal = Principal(DomainId.generate(), "P")
    identity = Identity(DomainId.generate(), principal.id, "I", origin)
    tenant = Tenant(
        DomainId.generate(),
        "T",
        SecurityScope.TENANT,
        identity.id,
        lifecycle=TenantLifecycle.PROVISIONING,
    )
    with spi.create_unit_of_work() as uow:
        spi.create_principal_repository(uow).add(principal)
        spi.create_identity_repository(uow).add(identity)
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()
    return tenant, principal, identity


def _make_eligible(spi: MtmfSpi, tenant: Tenant, principal: Principal, identity: Identity) -> None:
    with spi.create_unit_of_work() as uow:
        spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(principal.id, tenant.id)
        )
        spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(identity.id, tenant.id)
        )
        spi.create_identity_role_assignment_repository(uow).add(
            IdentityRoleAssignment(DomainId.generate(), tenant.id, identity.id, _TENANT_ADMIN_URN)
        )
        uow.commit()


def test_ol01_origin_and_lifecycle_round_trip(postgres_spi: MtmfSpi) -> None:
    tenant, _principal, identity = _graph(postgres_spi, origin=IdentityOrigin.FEDERATED)
    with postgres_spi.create_unit_of_work() as uow:
        stored_tenant = postgres_spi.create_tenant_repository(uow).get(tenant.id)
        stored_identity = postgres_spi.create_identity_repository(uow).get(identity.id)
    assert stored_tenant is not None and stored_tenant.lifecycle is TenantLifecycle.PROVISIONING
    assert stored_identity is not None and stored_identity.origin is IdentityOrigin.FEDERATED


def test_ol02_activation_and_suspension_use_protected_paths(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> None:
    tenant, principal, identity = _graph(postgres_spi, origin=IdentityOrigin.LOCAL)
    _make_eligible(postgres_spi, tenant, principal, identity)
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'initial', 'test-operator')",
        (tenant.id.value, principal.id.value, identity.id.value),
    )
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    with postgres_spi.create_unit_of_work() as uow:
        stored = postgres_spi.create_tenant_repository(uow).get(tenant.id)
    assert stored is not None and stored.lifecycle is TenantLifecycle.ACTIVE
    db.execute("SELECT mtmf.suspend_tenant(%s)", (tenant.id.value,))
    with postgres_spi.create_unit_of_work() as uow:
        suspended = postgres_spi.create_tenant_repository(uow).get(tenant.id)
    assert suspended is not None and suspended.lifecycle is TenantLifecycle.SUSPENDED


def test_ol03_runtime_cannot_create_an_active_ordinary_tenant(postgres_spi: MtmfSpi) -> None:
    principal = Principal(DomainId.generate(), "P")
    identity = Identity(DomainId.generate(), principal.id, "I", IdentityOrigin.LOCAL)
    tenant = Tenant(
        DomainId.generate(),
        "T",
        SecurityScope.TENANT,
        identity.id,
        lifecycle=TenantLifecycle.ACTIVE,
    )
    with pytest.raises(PersistenceIntegrityError), postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(principal)
        postgres_spi.create_identity_repository(uow).add(identity)
        postgres_spi.create_tenant_repository(uow).add(tenant)
        uow.commit()


def test_ol04_illegal_lifecycle_and_origin_are_rejected(db: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
            ("11111111-1111-4111-8111-111111111111",),
        )
        db.execute(
            "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
            "VALUES (%s, %s, 'I', 9, 2)",
            ("22222222-2222-4222-8222-222222222222", "11111111-1111-4111-8111-111111111111"),
        )


def test_ol05_root_tenant_must_be_active(db: psycopg.Connection) -> None:
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        ("11111111-1111-4111-8111-111111111111",),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', 1, 2)",
        ("22222222-2222-4222-8222-222222222222", "11111111-1111-4111-8111-111111111111"),
    )
    db.commit()
    with pytest.raises(psycopg.errors.CheckViolation), db.transaction():
        db.execute(
            "INSERT INTO mtmf.tenant "
            "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
            "VALUES (%s, 'Root', 0, %s, 2, 2)",
            ("44444444-4444-4444-8444-444444444444", "22222222-2222-4222-8222-222222222222"),
        )


def test_ol06_identity_origin_is_immutable(postgres_spi: MtmfSpi, db: psycopg.Connection) -> None:
    _tenant, _principal, identity = _graph(postgres_spi, origin=IdentityOrigin.LOCAL)
    forged = Identity(identity.id, identity.principal_id, identity.name, IdentityOrigin.FEDERATED)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_identity_repository(uow).save(forged)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        stored = postgres_spi.create_identity_repository(uow).get(identity.id)
    assert stored is not None and stored.origin is IdentityOrigin.LOCAL
    with pytest.raises(psycopg.errors.RaiseException), db.transaction():
        db.execute("UPDATE mtmf.identity SET origin = 2 WHERE id = %s", (identity.id.value,))


def test_ol07_provisioning_tenant_fails_closed(
    postgres_spi: MtmfSpi,
) -> None:
    tenant, principal, identity = _graph(postgres_spi, origin=IdentityOrigin.LOCAL)
    _make_eligible(postgres_spi, tenant, principal, identity)
    resolver = EffectiveRoleResolver(postgres_spi)
    with pytest.raises(SessionContextError), postgres_spi.create_unit_of_work() as uow:
        resolver.resolve(
            uow,
            session=SessionContext(tenant.id, principal.id, identity.id),
            target_tenant_id=tenant.id,
        )


def test_ol08_active_tenant_resolves_its_roles(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> None:
    tenant, principal, identity = _graph(postgres_spi, origin=IdentityOrigin.LOCAL)
    _make_eligible(postgres_spi, tenant, principal, identity)
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'initial', 'test-operator')",
        (tenant.id.value, principal.id.value, identity.id.value),
    )
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    resolver = EffectiveRoleResolver(postgres_spi)
    with postgres_spi.create_unit_of_work() as uow:
        state = resolver.resolve(
            uow,
            session=SessionContext(tenant.id, principal.id, identity.id),
            target_tenant_id=tenant.id,
        )
    assert [role.urn.value for role in state.applicable_roles] == [_TENANT_ADMIN_URN.value]
