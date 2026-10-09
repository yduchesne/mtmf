"""PostgreSQL Role-assignment integration slice (plan matrix P07-P14).

Every runtime action runs on a real connection authenticated as the
restricted ``mtmf_runtime`` login. Structural prerequisites are enforced
by the trusted SECURITY DEFINER functions and the composite foreign keys,
not by Python. The runtime has no direct table privilege on either typed
assignment table.
"""

from __future__ import annotations

import threading
import time

import helpers
import psycopg
import psycopg.errors
import pytest

from mtmf_core import (
    DomainId,
    GroupRoleAssignment,
    IdentityRoleAssignment,
    RoleUrn,
    SessionContext,
)
from mtmf_core.application import EffectiveRoleResolver
from mtmf_core.persistence.errors import (
    DuplicatePersistenceIdentityError,
    PersistenceConstraintError,
    PersistenceReferenceError,
    PersistenceTransactionError,
    UnknownPersistenceIdentityError,
)
from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresMigrationManager,
    PostgresMtmfSpi,
)

_SYSTEM_ROLE = RoleUrn(helpers.ROLE_URN)
_TENANT_A_ROLE = RoleUrn(helpers.TENANT_A_ROLE_URN)


def _seed_assignable_graph(db: psycopg.Connection) -> None:
    helpers.seed_base_entities(db)
    helpers.seed_role(db, helpers.ROLE_URN)
    helpers.seed_role(db, helpers.TENANT_A_ROLE_URN, defining_tenant_id=helpers.TENANT_A)
    helpers.insert_memberships(
        db,
        principal_tenant=(helpers.PRINCIPAL, helpers.TENANT_A),
        identity_tenant=(helpers.IDENTITY_A, helpers.TENANT_A),
        group_tenant=(helpers.GROUP_A, helpers.TENANT_A),
        identity_org=(helpers.IDENTITY_A, helpers.ORG_A),
        identity_group=(helpers.IDENTITY_A, helpers.GROUP_A),
        group_org=(helpers.GROUP_A, helpers.ORG_A),
    )
    helpers.insert_memberships(
        db,
        principal_tenant=(helpers.PRINCIPAL, helpers.TENANT_B),
        identity_tenant=(helpers.IDENTITY_B, helpers.TENANT_B),
        group_tenant=(helpers.GROUP_B, helpers.TENANT_B),
        identity_org=(helpers.IDENTITY_B, helpers.ORG_B),
        identity_group=(helpers.IDENTITY_B, helpers.GROUP_B),
        group_org=(helpers.GROUP_B, helpers.ORG_B),
    )
    helpers.insert_memberships(db, identity_tenant=(helpers.IDENTITY_A, helpers.TENANT_B))
    helpers.insert_memberships(db, identity_tenant=(helpers.IDENTITY_B, helpers.TENANT_A))
    db.commit()


# --- P01/P02/P08: repository round-trips through the runtime login ----------


def test_pa01_direct_assignment_round_trip(db, postgres_spi: PostgresMtmfSpi) -> None:
    _seed_assignable_graph(db)
    identity = DomainId.from_str(helpers.IDENTITY_A)
    tenant = DomainId.from_str(helpers.TENANT_A)
    assignment = IdentityRoleAssignment(DomainId.generate(), tenant, identity, _SYSTEM_ROLE)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        repository.add(assignment)
        assert repository.get(assignment.id) == assignment
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        assert repository.get(assignment.id) == assignment
        assert repository.find_by_tenant_and_identity(tenant, identity) == (assignment,)


def test_pa02_organization_refined_and_tenant_wide_are_distinct(
    db, postgres_spi: PostgresMtmfSpi
) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    identity = DomainId.from_str(helpers.IDENTITY_A)
    organization = DomainId.from_str(helpers.ORG_A)
    tenant_wide = IdentityRoleAssignment(DomainId.generate(), tenant, identity, _SYSTEM_ROLE)
    refined = IdentityRoleAssignment(
        DomainId.generate(), tenant, identity, _SYSTEM_ROLE, organization
    )
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        repository.add(tenant_wide)
        repository.add(refined)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        found = postgres_spi.create_identity_role_assignment_repository(uow)
        identities = found.find_by_tenant_and_identity(tenant, identity)
        assert {item.id for item in identities} == {tenant_wide.id, refined.id}


def test_pa03_group_assignment_round_trip(db, postgres_spi: PostgresMtmfSpi) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    group = DomainId.from_str(helpers.GROUP_A)
    assignment = GroupRoleAssignment(DomainId.generate(), tenant, group, _SYSTEM_ROLE)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_group_role_assignment_repository(uow)
        repository.add(assignment)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_group_role_assignment_repository(uow)
        assert repository.get(assignment.id) == assignment
        assert repository.find_by_tenant_and_group(tenant, group) == (assignment,)


def test_pa04_duplicate_logical_tuple_is_a_deterministic_conflict(
    db, postgres_spi: PostgresMtmfSpi
) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    identity = DomainId.from_str(helpers.IDENTITY_A)
    first = IdentityRoleAssignment(DomainId.generate(), tenant, identity, _SYSTEM_ROLE)
    second = IdentityRoleAssignment(DomainId.generate(), tenant, identity, _SYSTEM_ROLE)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        repository.add(first)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        with pytest.raises(DuplicatePersistenceIdentityError):
            repository.add(second)
        uow.rollback()


def test_pa05_remove_is_physical_and_unknown_remove_is_rejected(
    db, postgres_spi: PostgresMtmfSpi
) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    identity = DomainId.from_str(helpers.IDENTITY_A)
    assignment = IdentityRoleAssignment(DomainId.generate(), tenant, identity, _SYSTEM_ROLE)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        repository.add(assignment)
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        repository.remove(assignment.id)
        assert repository.get(assignment.id) is None
        uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        with pytest.raises(UnknownPersistenceIdentityError):
            repository.remove(assignment.id)
        uow.rollback()


def test_pa06_failed_uow_cannot_commit_partial_state(db, postgres_spi: PostgresMtmfSpi) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    identity = DomainId.from_str(helpers.IDENTITY_A)
    valid = IdentityRoleAssignment(DomainId.generate(), tenant, identity, _SYSTEM_ROLE)
    invalid = IdentityRoleAssignment(
        DomainId.generate(),
        tenant,
        DomainId.generate(),  # no membership: prerequisite failure
        _SYSTEM_ROLE,
    )
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        repository.add(valid)
        with pytest.raises(PersistenceConstraintError):
            repository.add(invalid)
        # The failed statement aborted the transaction; the UnitOfWork must
        # refuse to commit and roll back both writes.
        with pytest.raises(PersistenceTransactionError):
            uow.commit()
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        assert repository.get(valid.id) is None


# --- P09/P10: structural Tenant/subject/Organization prerequisites ----------


def test_pa07_cross_tenant_organization_refinement_is_rejected(
    db, postgres_spi: PostgresMtmfSpi
) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    identity = DomainId.from_str(helpers.IDENTITY_A)
    other_tenant_org = DomainId.from_str(helpers.ORG_B)
    assignment = IdentityRoleAssignment(
        DomainId.generate(), tenant, identity, _SYSTEM_ROLE, other_tenant_org
    )
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        with pytest.raises(PersistenceConstraintError):
            repository.add(assignment)
        uow.rollback()


def test_pa08_missing_identity_membership_prerequisite_is_rejected(
    db, postgres_spi: PostgresMtmfSpi
) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    assignment = IdentityRoleAssignment(
        DomainId.generate(), tenant, DomainId.generate(), _SYSTEM_ROLE
    )
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        with pytest.raises(PersistenceReferenceError):
            repository.add(assignment)
        uow.rollback()


def test_pa09_tenant_role_outside_defining_tenant_is_rejected(
    db, postgres_spi: PostgresMtmfSpi
) -> None:
    _seed_assignable_graph(db)
    tenant_b = DomainId.from_str(helpers.TENANT_B)
    identity_b = DomainId.from_str(helpers.IDENTITY_B)
    # TENANT_A_ROLE is defined in Tenant A; assigning it in Tenant B is a
    # structural context violation, not a harmless non-match.
    assignment = IdentityRoleAssignment(DomainId.generate(), tenant_b, identity_b, _TENANT_A_ROLE)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        with pytest.raises(PersistenceConstraintError):
            repository.add(assignment)
        uow.rollback()


def test_pa10_group_cross_tenant_assignment_is_rejected(db, postgres_spi: PostgresMtmfSpi) -> None:
    _seed_assignable_graph(db)
    tenant_a = DomainId.from_str(helpers.TENANT_A)
    group_b = DomainId.from_str(helpers.GROUP_B)
    assignment = GroupRoleAssignment(DomainId.generate(), tenant_a, group_b, _SYSTEM_ROLE)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_group_role_assignment_repository(uow)
        with pytest.raises(PersistenceConstraintError):
            repository.add(assignment)
        uow.rollback()


def test_pa11_organization_refined_group_grant_requires_group_org_membership(
    db, postgres_spi: PostgresMtmfSpi
) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    group_a = DomainId.from_str(helpers.GROUP_A)
    org_a = DomainId.from_str(helpers.ORG_A)
    # GROUP_A has a GroupOrgMembership for ORG_A, so this succeeds.
    assignment = GroupRoleAssignment(DomainId.generate(), tenant, group_a, _SYSTEM_ROLE, org_a)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_group_role_assignment_repository(uow)
        repository.add(assignment)
        uow.commit()
    # A Tenant-A group without a GroupOrgMembership for ORG_A cannot take an
    # Organization-refined grant.
    extra_group = helpers.new_id()
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s, %s, 'Extra', 2)",
        (extra_group, helpers.TENANT_A),
    )
    db.execute(
        "INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)",
        (extra_group, helpers.TENANT_A),
    )
    db.commit()
    missing = GroupRoleAssignment(
        DomainId.generate(), tenant, DomainId.from_str(extra_group), _SYSTEM_ROLE, org_a
    )
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_group_role_assignment_repository(uow)
        with pytest.raises(PersistenceReferenceError):
            repository.add(missing)
        uow.rollback()


# --- P07: runtime cannot touch the tables directly ---------------------------


@pytest.mark.parametrize("table", helpers.ROLE_ASSIGNMENT_TABLES)
def test_pa12_runtime_cannot_mutate_assignment_tables(
    db, runtime_connection: psycopg.Connection, table: str
) -> None:
    _seed_assignable_graph(db)
    statements = (
        (psycopg.sql.SQL("SELECT count(*) FROM mtmf.{}").format(_identifier(table)), None),
        (
            psycopg.sql.SQL(
                "INSERT INTO mtmf.{} (id, tenant_id, identity_id, role_urn) VALUES (%s, %s, %s, %s)"
                if table == helpers.IDENTITY_ROLE_ASSIGNMENT_TABLE
                else "INSERT INTO mtmf.{} (id, tenant_id, group_id, role_urn) "
                "VALUES (%s, %s, %s, %s)"
            ).format(_identifier(table)),
            (helpers.new_id(), helpers.TENANT_A, helpers.IDENTITY_A, helpers.ROLE_URN),
        ),
        (psycopg.sql.SQL("DELETE FROM mtmf.{}").format(_identifier(table)), None),
        (psycopg.sql.SQL("TRUNCATE mtmf.{}").format(_identifier(table)), None),
    )
    for statement, parameters in statements:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute(statement, parameters)
        runtime_connection.rollback()


def _identifier(name: str) -> psycopg.sql.Identifier:
    return psycopg.sql.Identifier(name)


def test_pa13_runtime_can_call_approved_assignment_functions(
    db, runtime_connection: psycopg.Connection
) -> None:
    _seed_assignable_graph(db)
    assignment_id = helpers.new_id()
    inserted = runtime_connection.execute(
        "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, %s)",
        (assignment_id, helpers.TENANT_A, helpers.IDENTITY_A, helpers.ROLE_URN, None),
    ).fetchone()[0]
    runtime_connection.commit()
    assert inserted is True
    payload = runtime_connection.execute(
        "SELECT mtmf.identity_role_assignment_get(%s)", (assignment_id,)
    ).fetchone()[0]
    assert payload["identity_id"] == helpers.IDENTITY_A
    assert payload["organization_id"] is None
    found = runtime_connection.execute(
        "SELECT * FROM mtmf.identity_role_assignment_find_by_tenant_and_identity(%s, %s)",
        (helpers.TENANT_A, helpers.IDENTITY_A),
    ).fetchall()
    assert len(found) == 1
    removed = runtime_connection.execute(
        "SELECT mtmf.identity_role_assignment_remove(%s)", (assignment_id,)
    ).fetchone()[0]
    runtime_connection.commit()
    assert removed is True


def test_pa14_private_validation_helpers_are_not_runtime_executable(
    runtime_connection: psycopg.Connection,
) -> None:
    for statement, parameters in (
        ("SELECT mtmf.role_assignment_validate_role(%s, %s)", (helpers.ROLE_URN, helpers.TENANT_A)),
        (
            "SELECT mtmf.identity_role_assignment_validate(%s, %s, %s, %s)",
            (helpers.TENANT_A, helpers.IDENTITY_A, helpers.ROLE_URN, None),
        ),
        (
            "SELECT mtmf.group_role_assignment_validate(%s, %s, %s, %s)",
            (helpers.TENANT_A, helpers.GROUP_A, helpers.ROLE_URN, None),
        ),
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute(statement, parameters)
        runtime_connection.rollback()


# --- P12: prerequisite membership removal is restricted ---------------------


def test_pa15_membership_removal_is_restricted_while_an_assignment_exists(db) -> None:
    _seed_assignable_graph(db)
    assignment_id = helpers.new_id()
    db.execute(
        "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, %s)",
        (assignment_id, helpers.TENANT_A, helpers.IDENTITY_A, helpers.ROLE_URN, None),
    )
    db.commit()
    before_audit = len(helpers.audit_rows(db))
    with pytest.raises(psycopg.errors.ForeignKeyViolation), db.transaction():
        db.execute(
            "SELECT mtmf.remove_identity_tenant_membership(%s, %s)",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
    # The removal rolled back entirely: the membership and assignment remain,
    # and no audit row was committed.
    assert (
        helpers.membership_count(
            db,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
        == 1
    )
    assert len(helpers.audit_rows(db)) == before_audit
    # After explicit revocation the membership can be removed normally.
    db.execute("SELECT mtmf.identity_role_assignment_remove(%s)", (assignment_id,))
    db.commit()
    assert helpers.remove_membership(
        db, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    db.commit()


# --- P11: concurrent membership removal vs assignment creation --------------


def test_pa16_concurrent_membership_removal_blocks_assignment_creation(db, dsn: str) -> None:
    _seed_assignable_graph(db)
    remover = psycopg.connect(dsn)
    remover.execute(
        "SELECT 1 FROM mtmf.identity_tenant_membership "
        "WHERE identity_id = %s AND tenant_id = %s FOR UPDATE",
        (helpers.IDENTITY_A, helpers.TENANT_A),
    )
    observer = psycopg.connect(dsn, autocommit=True)
    outcome: dict[str, str] = {}
    assignment_id = helpers.new_id()

    def inserter() -> None:
        connection = psycopg.connect(dsn, application_name="mtmf-pa-race-inserter")
        try:
            connection.execute(
                "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, %s)",
                (assignment_id, helpers.TENANT_A, helpers.IDENTITY_A, helpers.ROLE_URN, None),
            )
            connection.commit()
            outcome["result"] = "committed"
        except psycopg.errors.Error:
            connection.rollback()
            outcome["result"] = "rejected"
        finally:
            connection.close()

    thread = threading.Thread(target=inserter)
    thread.start()
    _wait_for_lock_wait(observer, "mtmf-pa-race-inserter")
    remover.execute(
        "SELECT mtmf.remove_identity_tenant_membership(%s, %s)",
        (helpers.IDENTITY_A, helpers.TENANT_A),
    )
    remover.commit()
    thread.join(timeout=15)
    observer.close()
    remover.close()

    assert outcome["result"] == "rejected"
    assert (
        helpers.membership_count(
            db,
            helpers.IDENTITY_ROLE_ASSIGNMENT_TABLE,
            "id = %s",
            (assignment_id,),
        )
        == 0
    )


def test_pa18_effective_role_resolver_reads_persisted_assignments(
    db, postgres_spi: PostgresMtmfSpi
) -> None:
    _seed_assignable_graph(db)
    tenant = DomainId.from_str(helpers.TENANT_A)
    identity = DomainId.from_str(helpers.IDENTITY_A)
    organization = DomainId.from_str(helpers.ORG_A)
    principal = DomainId.from_str(helpers.PRINCIPAL)
    tenant_wide = IdentityRoleAssignment(DomainId.generate(), tenant, identity, _SYSTEM_ROLE)
    refined = IdentityRoleAssignment(
        DomainId.generate(), tenant, identity, _SYSTEM_ROLE, organization
    )
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_role_assignment_repository(uow)
        repository.add(tenant_wide)
        repository.add(refined)
        uow.commit()

    resolver = EffectiveRoleResolver(postgres_spi)
    session = SessionContext(tenant, principal, identity)
    with postgres_spi.create_unit_of_work() as uow:
        state = resolver.resolve(uow, session=session, target_tenant_id=tenant)
    # Both the Tenant-wide and the Organization-refined direct grants are
    # eligible; duplicate Role contributions collapse to one Role.
    assert [role.urn for role in state.applicable_roles] == [_SYSTEM_ROLE]
    with postgres_spi.create_unit_of_work() as uow:
        resolved = resolver.resolve(
            uow, session=session, target_tenant_id=tenant, target_organization_id=organization
        )
    assert [role.urn for role in resolved.applicable_roles] == [_SYSTEM_ROLE]


def test_pa17_in_place_0004_to_0005_upgrade_preserves_data(
    migrator_config: PostgresConfig, mtmf_config: PostgresConfig
) -> None:
    with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
        connection.execute("CREATE SCHEMA mtmf AUTHORIZATION mtmf_owner")
    helpers.upgrade_to_revision(migrator_config, "0004")
    with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
        _seed_assignable_graph(connection)
        assert helpers.membership_count(connection, "identity_tenant_membership") == 4

    manager = PostgresMigrationManager(migrator_config)
    manager.upgrade_to_head()
    assert manager.current_revision() == "0005"
    with psycopg.connect(mtmf_config.psycopg_dsn, autocommit=True) as connection:
        # Existing entity/membership state is preserved across the upgrade.
        assert helpers.membership_count(connection, "identity_tenant_membership") == 4
        assert connection.execute("SELECT count(*) FROM mtmf.role").fetchone()[0] == 2
        # The new typed assignment tables are empty and usable.
        assert helpers.membership_count(connection, "identity_role_assignment") == 0
        inserted = connection.execute(
            "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, %s)",
            (
                helpers.new_id(),
                helpers.TENANT_A,
                helpers.IDENTITY_A,
                helpers.ROLE_URN,
                None,
            ),
        ).fetchone()[0]
        assert inserted is True


def _wait_for_lock_wait(observer: psycopg.Connection, application_name: str) -> None:
    """Wait (bounded) until the named backend is blocked on a lock."""
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        row = observer.execute(
            "SELECT count(*) FROM pg_stat_activity "
            "WHERE application_name = %s AND wait_event_type = 'Lock'",
            (application_name,),
        ).fetchone()
        if row[0] > 0:
            return
        time.sleep(0.02)
    raise AssertionError(f"backend {application_name!r} never blocked on a lock")
