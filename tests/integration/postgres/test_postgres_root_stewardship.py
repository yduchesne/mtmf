"""Canonical root bootstrap and stewardship protection (revision 0008).

Proves, on real PostgreSQL, that:
- protected bootstrap creates exactly one canonical root and is idempotent
  and fail-closed;
- root state cannot be suspended/deleted/reassigned through direct SQL or
  the pre-existing runtime-granted functions;
- an ACTIVE ordinary Tenant requires an eligible designated steward, and
  the current steward's Principal/Identity/memberships cannot be removed;
- the privileged structural functions are not runtime-executable and the
  stewardship audit is append-only.
"""

from __future__ import annotations

import uuid

import psycopg
import pytest

from mtmf_core import (
    DomainId,
    Group,
    GroupOrgMembership,
    GroupRoleAssignment,
    GroupTenantMembership,
    Identity,
    IdentityGroupMembership,
    IdentityOrgMembership,
    IdentityOrigin,
    IdentityRoleAssignment,
    IdentityTenantMembership,
    Organization,
    Principal,
    PrincipalTenantMembership,
    RoleUrn,
    SecurityScope,
    Tenant,
    TenantLifecycle,
)
from mtmf_core.persistence.spi import MtmfSpi

_TENANT_ADMIN_URN = RoleUrn("urn:mtmf:iam:roles:system:tenant-administrator")


def helpers_ids() -> tuple[str, str, str]:
    return str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())


def _bootstrap(db: psycopg.Connection) -> tuple[str, str, str]:
    tenant_id, principal_id, identity_id = helpers_ids()
    db.execute(
        "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
        (tenant_id, principal_id, identity_id),
    )
    return tenant_id, principal_id, identity_id


def _provision_designated_tenant(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> tuple[Tenant, Principal, Identity]:
    principal = Principal(DomainId.generate(), "P")
    identity = Identity(DomainId.generate(), principal.id, "I", IdentityOrigin.LOCAL)
    tenant = Tenant(
        DomainId.generate(),
        "T",
        SecurityScope.TENANT,
        identity.id,
        lifecycle=TenantLifecycle.PROVISIONING,
    )
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(principal)
        postgres_spi.create_identity_repository(uow).add(identity)
        postgres_spi.create_tenant_repository(uow).add(tenant)
        postgres_spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(principal.id, tenant.id)
        )
        postgres_spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(identity.id, tenant.id)
        )
        postgres_spi.create_identity_role_assignment_repository(uow).add(
            IdentityRoleAssignment(DomainId.generate(), tenant.id, identity.id, _TENANT_ADMIN_URN)
        )
        uow.commit()
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'initial', 'test-operator')",
        (tenant.id.value, principal.id.value, identity.id.value),
    )
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    return tenant, principal, identity


# --- ROOT bootstrap -----------------------------------------------------------


def test_rs01_bootstrap_creates_one_canonical_root(db: psycopg.Connection) -> None:
    tenant_id, principal_id, identity_id = _bootstrap(db)
    registry = db.execute(
        "SELECT root_tenant_id, root_principal_id, root_identity_id FROM mtmf.root_registry"
    ).fetchall()
    assert registry == [
        (
            DomainId.from_str(tenant_id).value,
            DomainId.from_str(principal_id).value,
            DomainId.from_str(identity_id).value,
        )
    ]
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE operation='BOOTSTRAP'"
        ).fetchone()[0]
        == 1
    )
    row = db.execute(
        "SELECT scope, lifecycle FROM mtmf.tenant WHERE id = %s", (tenant_id,)
    ).fetchone()
    assert row == (0, 1)


def test_rs02_bootstrap_replay_is_idempotent(db: psycopg.Connection) -> None:
    tenant_id, principal_id, identity_id = _bootstrap(db)
    db.execute(
        "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
        (tenant_id, principal_id, identity_id),
    )
    assert db.execute("SELECT count(*) FROM mtmf.root_registry").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.stewardship_audit").fetchone()[0] == 1


def test_rs03_conflicting_bootstrap_fails_closed(db: psycopg.Connection) -> None:
    _bootstrap(db)
    other = helpers_ids()
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        db.execute("SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')", other)
    assert captured.value.sqlstate == "MT020"


# --- Root protection ----------------------------------------------------------


def test_rs04_root_cannot_be_suspended_deleted_or_reassigned(db: psycopg.Connection) -> None:
    tenant_id, principal_id, identity_id = _bootstrap(db)
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        db.execute("UPDATE mtmf.tenant SET lifecycle = 2 WHERE id = %s", (tenant_id,))
    assert captured.value.sqlstate == "MT030"
    with pytest.raises(psycopg.errors.DatabaseError):
        db.execute("DELETE FROM mtmf.tenant WHERE id = %s", (tenant_id,))
    with pytest.raises(psycopg.errors.DatabaseError):
        db.execute("UPDATE mtmf.identity SET origin = 2 WHERE id = %s", (identity_id,))
    with pytest.raises(psycopg.errors.DatabaseError):
        db.execute(
            "DELETE FROM mtmf.principal_tenant_membership "
            "WHERE principal_id = %s AND tenant_id = %s",
            (principal_id, tenant_id),
        )


def test_rs05_legacy_tenant_save_cannot_suspend_root(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    tenant_id, _principal_id, _identity_id = _bootstrap(db)
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        runtime_connection.execute(
            "SELECT mtmf.tenant_save(%s, %s, %s, %s, %s)",
            (tenant_id, "Root", 2, 2, "{}"),
        )
    assert captured.value.sqlstate == "MT030"
    runtime_connection.rollback()


def test_rs06_root_recovery_rejects_federated_candidate(db: psycopg.Connection) -> None:
    _tenant_id, principal_id, _identity_id = _bootstrap(db)
    candidate = helpers_ids()
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'Fed', 2, 2)",
        (candidate[2], principal_id),
    )
    db.commit()
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        db.execute("SELECT mtmf.recover_root_identity(%s, 'rotate', 'operator')", (candidate[2],))
    assert captured.value.sqlstate == "MT027"


# --- Stewardship protection ---------------------------------------------------


def test_rs07_active_tenant_requires_designation(db: psycopg.Connection) -> None:
    # Raw SQL ordinary Tenant plus a direct UPDATE to ACTIVE without a
    # designation must be rejected by the DB guard.
    principal_id, identity_id, tenant_id = helpers_ids()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (principal_id,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', 1, 2)",
        (identity_id, principal_id),
    )
    db.execute(
        "INSERT INTO mtmf.tenant "
        "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'T', 2, %s, 0, 2)",
        (tenant_id, identity_id),
    )
    db.commit()
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        db.execute("UPDATE mtmf.tenant SET lifecycle = 1 WHERE id = %s", (tenant_id,))
    assert captured.value.sqlstate == "MT014"


@pytest.mark.parametrize("target", ["principal_membership", "identity_membership"])
def test_rs08_steward_membership_removal_is_rejected(
    postgres_spi: MtmfSpi,
    db: psycopg.Connection,
    runtime_connection: psycopg.Connection,
    target: str,
) -> None:
    tenant, principal, identity = _provision_designated_tenant(postgres_spi, db)
    if target == "principal_membership":
        statement = "SELECT mtmf.remove_principal_tenant_membership(%s, %s, NULL)"
        params = (principal.id.value, tenant.id.value)
    else:
        statement = "SELECT mtmf.remove_identity_tenant_membership(%s, %s, NULL)"
        params = (identity.id.value, tenant.id.value)
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        runtime_connection.execute(statement, params)
    assert captured.value.sqlstate == "MT032"
    runtime_connection.rollback()


def test_rs09_steward_deactivation_is_rejected(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> None:
    _tenant, principal, identity = _provision_designated_tenant(postgres_spi, db)
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        db.execute(
            "UPDATE mtmf.principal SET deletion_status = 1 WHERE id = %s", (principal.id.value,)
        )
    assert captured.value.sqlstate == "MT032"
    with pytest.raises(psycopg.errors.DatabaseError):
        db.execute(
            "UPDATE mtmf.identity SET deletion_status = 1 WHERE id = %s", (identity.id.value,)
        )


def test_rs09b_steward_final_tenant_admin_assignment_cannot_be_revoked(
    postgres_spi: MtmfSpi,
    db: psycopg.Connection,
    runtime_connection: psycopg.Connection,
) -> None:
    tenant, _principal, identity = _provision_designated_tenant(postgres_spi, db)
    assignment_id = db.execute(
        "SELECT id FROM mtmf.identity_role_assignment "
        "WHERE tenant_id = %s AND identity_id = %s AND organization_id IS NULL",
        (tenant.id.value, identity.id.value),
    ).fetchone()[0]
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        runtime_connection.execute(
            "SELECT mtmf.identity_role_assignment_remove(%s)", (assignment_id,)
        )
    assert captured.value.sqlstate == "MT032"
    runtime_connection.rollback()


def test_rs10_transfer_then_old_membership_removal_is_allowed(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> None:
    tenant, principal, identity = _provision_designated_tenant(postgres_spi, db)
    replacement = Principal(DomainId.generate(), "P2")
    replacement_identity = Identity(DomainId.generate(), replacement.id, "I2", IdentityOrigin.LOCAL)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(replacement)
        postgres_spi.create_identity_repository(uow).add(replacement_identity)
        postgres_spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(replacement.id, tenant.id)
        )
        postgres_spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(replacement_identity.id, tenant.id)
        )
        postgres_spi.create_identity_role_assignment_repository(uow).add(
            IdentityRoleAssignment(
                DomainId.generate(), tenant.id, replacement_identity.id, _TENANT_ADMIN_URN
            )
        )
        uow.commit()
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, 1, 'TRANSFER', 'succession', 'steward-actor')",
        (tenant.id.value, replacement.id.value, replacement_identity.id.value),
    )
    # The previous steward is no longer designated, so its Role assignment
    # can be revoked and its membership removed.
    db.execute(
        "DELETE FROM mtmf.identity_role_assignment WHERE tenant_id = %s AND identity_id = %s",
        (tenant.id.value, identity.id.value),
    )
    db.execute(
        "SELECT mtmf.remove_principal_tenant_membership(%s, %s, NULL)",
        (principal.id.value, tenant.id.value),
    )
    audit = db.execute(
        "SELECT operation, previous_principal_id, new_principal_id FROM mtmf.stewardship_audit "
        "ORDER BY id"
    ).fetchall()
    assert audit[-1] == ("TRANSFER", principal.id.value, replacement.id.value)


# --- Privilege posture --------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        (
            "SELECT mtmf.bootstrap_root(gen_random_uuid(), gen_random_uuid(), "
            "gen_random_uuid(), 'R', 'P', 'I')"
        ),
        "SELECT mtmf.activate_tenant(gen_random_uuid())",
        "SELECT mtmf.suspend_tenant(gen_random_uuid())",
        (
            "SELECT mtmf.designate_steward(gen_random_uuid(), gen_random_uuid(), "
            "gen_random_uuid(), NULL, 'RECOVERY', 'r', 'a')"
        ),
        "SELECT mtmf.recover_root_identity(gen_random_uuid(), 'r', 'a')",
        (
            "SELECT mtmf.stewardship_is_eligible("
            "gen_random_uuid(), gen_random_uuid(), gen_random_uuid())"
        ),
    ],
)
def test_rs11_privileged_functions_are_not_runtime_executable(
    runtime_connection: psycopg.Connection, statement: str
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(statement)
    runtime_connection.rollback()


def test_rs21_privileged_functions_are_invoker_and_owner_owned(
    db: psycopg.Connection,
) -> None:
    rows = db.execute(
        "SELECT p.proname, p.prosecdef, pg_get_userbyid(p.proowner) "
        "FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' AND p.proname IN ("
        "  'bootstrap_root', 'designate_steward', 'activate_tenant', "
        "  'suspend_tenant', 'recover_root_identity', 'stewardship_is_eligible')"
    ).fetchall()
    assert len(rows) == 6
    for name, prosecdef, owner in rows:
        assert prosecdef is False, name
        assert owner == "mtmf_owner", name


def test_rs22_runtime_signature_allowlist_is_exact(db: psycopg.Connection) -> None:
    from mtmf_core.persistence.postgres import expected_runtime_signatures

    executable = {
        str(row[0])
        for row in db.execute(
            "SELECT format('%I.%I(%s)', n.nspname, p.proname, "
            "              pg_get_function_identity_arguments(p.oid)) "
            "FROM pg_catalog.pg_proc p "
            "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'mtmf' "
            "AND has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')"
        ).fetchall()
    }
    assert executable == set(expected_runtime_signatures())
    assert len(executable) == 58


def test_rs12_stewardship_audit_is_append_only(db: psycopg.Connection) -> None:
    _bootstrap(db)
    with pytest.raises(psycopg.errors.DatabaseError):
        db.execute("UPDATE mtmf.stewardship_audit SET reason = 'tampered'")
    with pytest.raises(psycopg.errors.DatabaseError):
        db.execute("DELETE FROM mtmf.stewardship_audit")


def test_rs13_runtime_cannot_read_root_registry(
    runtime_connection: psycopg.Connection,
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("SELECT * FROM mtmf.root_registry")
    runtime_connection.rollback()


def test_rs14_sibling_identity_is_not_steward(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> None:
    _tenant, principal, _identity = _provision_designated_tenant(postgres_spi, db)
    sibling = Identity(DomainId.generate(), principal.id, "Sibling", IdentityOrigin.LOCAL)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_identity_repository(uow).add(sibling)
        uow.commit()
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_designation WHERE designated_identity_id = %s",
            (sibling.id.value,),
        ).fetchone()[0]
        == 0
    )


# --- Deterministic concurrency ------------------------------------------------


def test_rs15_concurrent_bootstrap_serializes_to_one_root(db: psycopg.Connection, dsn: str) -> None:
    import threading

    tenant_id, principal_id, identity_id = helpers_ids()
    barrier = threading.Barrier(2)
    outcomes: dict[str, str] = {}

    def worker(name: str) -> None:
        try:
            with psycopg.connect(dsn, autocommit=True) as connection:
                barrier.wait(timeout=10)
                connection.execute(
                    "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
                    (tenant_id, principal_id, identity_id),
                )
            outcomes[name] = "ok"
        except Exception as exc:  # pragma: no cover - diagnostic only
            outcomes[name] = type(exc).__name__

    threads = [threading.Thread(target=worker, args=(name,)) for name in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert outcomes == {"a": "ok", "b": "ok"}
    assert db.execute("SELECT count(*) FROM mtmf.root_registry").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.stewardship_audit").fetchone()[0] == 1


def test_rs16_concurrent_designation_rejects_the_stale_writer(
    postgres_spi: MtmfSpi, db: psycopg.Connection, dsn: str
) -> None:
    import threading

    tenant, principal, identity = _provision_designated_tenant(postgres_spi, db)
    # A second eligible steward.
    replacement = Principal(DomainId.generate(), "P2")
    replacement_identity = Identity(DomainId.generate(), replacement.id, "I2", IdentityOrigin.LOCAL)
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_principal_repository(uow).add(replacement)
        postgres_spi.create_identity_repository(uow).add(replacement_identity)
        postgres_spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(replacement.id, tenant.id)
        )
        postgres_spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(replacement_identity.id, tenant.id)
        )
        postgres_spi.create_identity_role_assignment_repository(uow).add(
            IdentityRoleAssignment(
                DomainId.generate(), tenant.id, replacement_identity.id, _TENANT_ADMIN_URN
            )
        )
        uow.commit()

    barrier = threading.Barrier(2)
    outcomes: dict[str, str] = {}

    def worker(name: str, target_principal: DomainId, target_identity: DomainId) -> None:
        try:
            with psycopg.connect(dsn, autocommit=True) as connection:
                barrier.wait(timeout=10)
                connection.execute(
                    "SELECT mtmf.designate_steward(%s, %s, %s, 1, 'TRANSFER', 'race', 'actor')",
                    (tenant.id.value, target_principal.value, target_identity.value),
                )
            outcomes[name] = "ok"
        except psycopg.Error as exc:
            outcomes[name] = getattr(exc, "sqlstate", "error")

    threads = [
        threading.Thread(target=worker, args=("a", replacement.id, replacement_identity.id)),
        threading.Thread(target=worker, args=("b", principal.id, identity.id)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    # Exactly one writer wins; the stale peer is rejected deterministically.
    assert sorted(outcomes.values()) == ["MT012", "ok"]
    # Exactly one designation row and one transfer audit event committed.
    assert db.execute("SELECT count(*) FROM mtmf.stewardship_designation").fetchone()[0] == 1
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE operation = 'TRANSFER'"
        ).fetchone()[0]
        == 1
    )


# --- Group-derived and Organization-scoped eligibility -------------------------


def _new_provisioning_tenant(spi: MtmfSpi) -> Tenant:
    owner_principal = Principal(DomainId.generate(), "Owner")
    owner_identity = Identity(
        DomainId.generate(), owner_principal.id, "Owner I", IdentityOrigin.LOCAL
    )
    tenant = Tenant(
        DomainId.generate(),
        "T",
        SecurityScope.TENANT,
        owner_identity.id,
        lifecycle=TenantLifecycle.PROVISIONING,
    )
    with spi.create_unit_of_work() as uow:
        spi.create_principal_repository(uow).add(owner_principal)
        spi.create_identity_repository(uow).add(owner_identity)
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()
    return tenant


def _add_group_steward(
    spi: MtmfSpi, tenant: Tenant, *, organization_scoped: bool
) -> tuple[Principal, Identity]:
    principal = Principal(DomainId.generate(), "Group Steward")
    identity = Identity(DomainId.generate(), principal.id, "Group Steward I", IdentityOrigin.LOCAL)
    group = Group(DomainId.generate(), tenant.id, "Stewards")
    organization = (
        Organization(DomainId.generate(), tenant.id, "O", identity.id)
        if organization_scoped
        else None
    )
    with spi.create_unit_of_work() as uow:
        spi.create_principal_repository(uow).add(principal)
        spi.create_identity_repository(uow).add(identity)
        spi.create_group_repository(uow).add(group)
        spi.create_principal_tenant_membership_repository(uow).add(
            PrincipalTenantMembership(principal.id, tenant.id)
        )
        spi.create_identity_tenant_membership_repository(uow).add(
            IdentityTenantMembership(identity.id, tenant.id)
        )
        spi.create_group_tenant_membership_repository(uow).add(
            GroupTenantMembership(group.id, tenant.id)
        )
        spi.create_identity_group_membership_repository(uow).add(
            IdentityGroupMembership(identity.id, group.id)
        )
        if organization is not None:
            spi.create_organization_repository(uow).add(organization)
            spi.create_identity_org_membership_repository(uow).add(
                IdentityOrgMembership(identity.id, organization.id)
            )
            spi.create_group_org_membership_repository(uow).add(
                GroupOrgMembership(group.id, organization.id)
            )
        spi.create_group_role_assignment_repository(uow).add(
            GroupRoleAssignment(
                DomainId.generate(),
                tenant.id,
                group.id,
                _TENANT_ADMIN_URN,
                organization.id if organization is not None else None,
            )
        )
        uow.commit()
    return principal, identity


def test_rs17_group_derived_tenant_admin_confers_stewardship_eligibility(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> None:
    tenant = _new_provisioning_tenant(postgres_spi)
    principal, identity = _add_group_steward(postgres_spi, tenant, organization_scoped=False)
    # Eligibility is satisfied purely through the Group-derived authority.
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'group', 'operator')",
        (tenant.id.value, principal.id.value, identity.id.value),
    )
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    assert (
        db.execute(
            "SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant.id.value,)
        ).fetchone()[0]
        == 1
    )


def test_rs18_organization_refined_assignment_is_not_stewardship_eligibility(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> None:
    tenant = _new_provisioning_tenant(postgres_spi)
    principal, identity = _add_group_steward(postgres_spi, tenant, organization_scoped=True)
    # An Organization-refined grant is Organization-scoped authority, not
    # Tenant-level stewardship eligibility.
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        db.execute(
            "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'org', 'operator')",
            (tenant.id.value, principal.id.value, identity.id.value),
        )
    assert captured.value.sqlstate == "MT013"
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_designation WHERE tenant_id = %s",
            (tenant.id.value,),
        ).fetchone()[0]
        == 0
    )


# --- Designation prerequisite rejection ----------------------------------------


def _bare_principal_identity(spi: MtmfSpi) -> tuple[Principal, Identity]:
    principal = Principal(DomainId.generate(), "Bare")
    identity = Identity(DomainId.generate(), principal.id, "Bare I", IdentityOrigin.LOCAL)
    with spi.create_unit_of_work() as uow:
        spi.create_principal_repository(uow).add(principal)
        spi.create_identity_repository(uow).add(identity)
        uow.commit()
    return principal, identity


@pytest.mark.parametrize("scenario", ["no_membership", "no_role", "wrong_principal"])
def test_rs19_designation_rejects_ineligible_prerequisites(
    postgres_spi: MtmfSpi, db: psycopg.Connection, scenario: str
) -> None:
    tenant = _new_provisioning_tenant(postgres_spi)
    principal, identity = _bare_principal_identity(postgres_spi)
    designate_principal = principal
    if scenario in {"no_role", "wrong_principal"}:
        with postgres_spi.create_unit_of_work() as uow:
            postgres_spi.create_principal_tenant_membership_repository(uow).add(
                PrincipalTenantMembership(principal.id, tenant.id)
            )
            postgres_spi.create_identity_tenant_membership_repository(uow).add(
                IdentityTenantMembership(identity.id, tenant.id)
            )
            uow.commit()
    if scenario == "wrong_principal":
        designate_principal, _ = _bare_principal_identity(postgres_spi)
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        db.execute(
            "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'r', 'op')",
            (tenant.id.value, designate_principal.id.value, identity.id.value),
        )
    assert captured.value.sqlstate == "MT013"
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_designation WHERE tenant_id = %s",
            (tenant.id.value,),
        ).fetchone()[0]
        == 0
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE tenant_id = %s", (tenant.id.value,)
        ).fetchone()[0]
        == 0
    )


def test_rs20_activation_without_designation_writes_no_audit(db: psycopg.Connection) -> None:
    tenant_id, _principal_id, identity_id = helpers_ids()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (_principal_id,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', 1, 2)",
        (identity_id, _principal_id),
    )
    db.execute(
        "INSERT INTO mtmf.tenant "
        "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'T', 2, %s, 0, 2)",
        (tenant_id, identity_id),
    )
    db.commit()
    with pytest.raises(psycopg.errors.DatabaseError) as captured:
        db.execute("SELECT mtmf.activate_tenant(%s)", (tenant_id,))
    assert captured.value.sqlstate == "MT014"
    assert db.execute("SELECT count(*) FROM mtmf.stewardship_audit").fetchone()[0] == 0


# --- Group-derived eligibility invalidation paths ------------------------------


def _group_id_for(db: psycopg.Connection, identity: Identity) -> str:
    return str(
        db.execute(
            "SELECT group_id FROM mtmf.identity_group_membership WHERE identity_id = %s",
            (identity.id.value,),
        ).fetchone()[0]
    )


def test_rs23_group_derived_steward_membership_removal_is_rejected(
    postgres_spi: MtmfSpi, db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    tenant = _new_provisioning_tenant(postgres_spi)
    principal, identity = _add_group_steward(postgres_spi, tenant, organization_scoped=False)
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'g', 'op')",
        (tenant.id.value, principal.id.value, identity.id.value),
    )
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    group_id = _group_id_for(db, identity)
    with pytest.raises(psycopg.errors.DatabaseError):
        runtime_connection.execute(
            "SELECT mtmf.remove_identity_group_membership(%s, %s, NULL)",
            (identity.id.value, group_id),
        )
    runtime_connection.rollback()


def test_rs24_group_soft_delete_cannot_orphan_group_derived_steward(
    postgres_spi: MtmfSpi, db: psycopg.Connection
) -> None:
    tenant = _new_provisioning_tenant(postgres_spi)
    principal, identity = _add_group_steward(postgres_spi, tenant, organization_scoped=False)
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'g', 'op')",
        (tenant.id.value, principal.id.value, identity.id.value),
    )
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    group_id = _group_id_for(db, identity)
    with pytest.raises(psycopg.errors.DatabaseError):
        db.execute("UPDATE mtmf.group SET deletion_status = 1 WHERE id = %s", (group_id,))


def test_rs25_group_membership_removal_allowed_when_another_source_remains(
    postgres_spi: MtmfSpi, db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    tenant = _new_provisioning_tenant(postgres_spi)
    principal, identity = _add_group_steward(postgres_spi, tenant, organization_scoped=False)
    # Add a direct Tenant Administrator source so the Group is not the last one.
    with postgres_spi.create_unit_of_work() as uow:
        postgres_spi.create_identity_role_assignment_repository(uow).add(
            IdentityRoleAssignment(DomainId.generate(), tenant.id, identity.id, _TENANT_ADMIN_URN)
        )
        uow.commit()
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'g', 'op')",
        (tenant.id.value, principal.id.value, identity.id.value),
    )
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    group_id = _group_id_for(db, identity)
    # The direct assignment remains, so removing the Group membership is allowed.
    runtime_connection.execute(
        "SELECT mtmf.remove_identity_group_membership(%s, %s, NULL)",
        (identity.id.value, group_id),
    )
    runtime_connection.commit()
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.identity_group_membership WHERE identity_id = %s",
            (identity.id.value,),
        ).fetchone()[0]
        == 0
    )
