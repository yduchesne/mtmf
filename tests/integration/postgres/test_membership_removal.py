"""Typed membership hard-deletion cascade tests (MIG, PRE, GRP, CAS).

Real-PostgreSQL proof that the sanctioned removal functions physically
delete the correct Tenant-scoped rows, cascade transitively, preserve
other Tenants and siblings, keep no membership lifecycle state, close the
IdentityGroup GroupTenantMembership prerequisite gap, and enforce Group
Tenant exclusivity. No-op removals write no audit row; rejoin never
restores dependents.
"""

from __future__ import annotations

import helpers
import psycopg
import psycopg.errors
import pytest


@pytest.fixture
def graph(db) -> psycopg.Connection:
    """A freshly migrated database with the complete two-Tenant graph."""
    helpers.seed_full_membership_graph(db)
    return db


# --- MIG: shape and migration -------------------------------------------------


def test_mig03_membership_tables_have_no_lifecycle_status(db) -> None:
    for table in helpers.MEMBERSHIP_TABLES:
        columns = helpers.columns_of(db, table)
        assert "deletion_status" not in columns
        assert "active_status" not in columns
        assert "id" not in columns
        assert len(helpers.primary_key_columns(db, table)) == 2


def test_mig03_audit_schema_constraints_hold(db) -> None:
    columns = helpers.columns_of(db, helpers.AUDIT_TABLE)
    assert columns["id"] == "uuid"
    assert columns["occurred_at"] == "timestamp with time zone"
    assert columns["tenant_id"] == "uuid"
    assert helpers.primary_key_columns(db, helpers.AUDIT_TABLE) == {"id"}
    for count_column in (
        "principal_tenant_count",
        "identity_tenant_count",
        "group_tenant_count",
        "identity_group_count",
        "identity_org_count",
        "group_org_count",
    ):
        assert columns[count_column] == "bigint"


def test_mig02_populated_0001_upgrades_to_head_without_data_loss(db, mtmf_config, dsn: str) -> None:
    helpers.seed_full_membership_graph(db)
    before = {table: helpers.membership_count(db, table) for table in helpers.MEMBERSHIP_TABLES}

    # Rebuild the same data on a database pinned to revision 0001, then
    # upgrade in place and confirm every membership fact survived.
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
        connection.execute("CREATE SCHEMA mtmf AUTHORIZATION mtmf_owner")
    helpers.upgrade_to_revision(mtmf_config, "0001")
    with psycopg.connect(dsn, autocommit=True) as connection:
        helpers.seed_full_membership_graph(connection)
        seeded = {
            table: helpers.membership_count(connection, table)
            for table in helpers.MEMBERSHIP_TABLES
        }
    assert seeded == before
    helpers.upgrade_to_revision(mtmf_config, "head")
    with psycopg.connect(dsn, autocommit=True) as connection:
        after = {
            table: helpers.membership_count(connection, table)
            for table in helpers.MEMBERSHIP_TABLES
        }
    assert after == before


def test_mig02b_upgrade_fails_loudly_on_new_invariant_violation(db, mtmf_config, dsn: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
        connection.execute("CREATE SCHEMA mtmf AUTHORIZATION mtmf_owner")
    helpers.upgrade_to_revision(mtmf_config, "0001")
    with psycopg.connect(dsn, autocommit=True) as connection:
        helpers.seed_base_entities(connection)
        # v001 permitted an IdentityGroupMembership without the Group's
        # GroupTenantMembership; revision 0002 newly forbids it, so the
        # upgrade must fail rather than silently drop the row.
        helpers.insert_memberships(
            connection,
            principal_tenant=(helpers.PRINCIPAL, helpers.TENANT_A),
            identity_tenant=(helpers.IDENTITY_A, helpers.TENANT_A),
            identity_group=(helpers.IDENTITY_A, helpers.GROUP_A),
        )
        connection.commit()

    with pytest.raises(Exception) as excinfo:
        helpers.upgrade_to_revision(mtmf_config, "head")
    assert "GroupTenantMembership" in str(excinfo.value)

    with psycopg.connect(dsn) as connection:
        assert "membership_removal_audit" not in helpers.tables(connection)
        revision = connection.execute("SELECT version_num FROM mtmf.alembic_version").fetchone()[0]
        assert revision == "0001"


# --- PRE: insert-time prerequisites -------------------------------------------


def test_pre01_identity_group_requires_identity_tenant(db) -> None:
    helpers.seed_base_entities(db)
    helpers.insert_memberships(db, group_tenant=(helpers.GROUP_A, helpers.TENANT_A))
    db.commit()
    with pytest.raises(psycopg.errors.RaiseException), db.transaction():
        helpers.insert_memberships(db, identity_group=(helpers.IDENTITY_A, helpers.GROUP_A))


def test_pre02_identity_group_requires_group_tenant(db) -> None:
    helpers.seed_base_entities(db)
    helpers.insert_memberships(
        db,
        principal_tenant=(helpers.PRINCIPAL, helpers.TENANT_A),
        identity_tenant=(helpers.IDENTITY_A, helpers.TENANT_A),
    )
    db.commit()
    # group.tenant_id already equals TENANT_A; the missing GroupTenantMembership
    # must still reject the insert.
    with pytest.raises(psycopg.errors.RaiseException), db.transaction():
        helpers.insert_memberships(db, identity_group=(helpers.IDENTITY_A, helpers.GROUP_A))


def test_pre03_identity_group_succeeds_with_both_prerequisites(db) -> None:
    helpers.seed_base_entities(db)
    helpers.insert_memberships(
        db,
        principal_tenant=(helpers.PRINCIPAL, helpers.TENANT_A),
        identity_tenant=(helpers.IDENTITY_A, helpers.TENANT_A),
        group_tenant=(helpers.GROUP_A, helpers.TENANT_A),
        identity_group=(helpers.IDENTITY_A, helpers.GROUP_A),
    )
    db.commit()
    assert (
        helpers.membership_count(
            db,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_A, helpers.GROUP_A),
        )
        == 1
    )


def test_pre04_cross_tenant_inserts_rejected(graph: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.RaiseException), graph.transaction():
        helpers.insert_memberships(graph, identity_org=(helpers.IDENTITY_A, helpers.ORG_B))
    with pytest.raises(psycopg.errors.RaiseException), graph.transaction():
        helpers.insert_memberships(graph, group_org=(helpers.GROUP_A, helpers.ORG_B))
    with pytest.raises(psycopg.errors.RaiseException), graph.transaction():
        helpers.insert_memberships(graph, identity_group=(helpers.IDENTITY_A, helpers.GROUP_B))


def test_pre05_membership_update_remains_forbidden(graph: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.RaiseException), graph.transaction():
        graph.execute(
            "UPDATE mtmf.principal_tenant_membership SET tenant_id = %s", (helpers.TENANT_B,)
        )


# --- GRP: Group Tenant exclusivity --------------------------------------------


def test_grp01_group_cannot_join_two_tenants(graph: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.RaiseException), graph.transaction():
        helpers.insert_memberships(graph, group_tenant=(helpers.GROUP_A, helpers.TENANT_B))
    assert (
        helpers.membership_count(
            graph,
            "group_tenant_membership",
            "group_id = %s",
            (helpers.GROUP_A,),
        )
        == 1
    )


# --- CAS: cascade correctness -------------------------------------------------


def test_cas01_principal_removal_deletes_owned_identity_tenant_in_tenant(
    graph: psycopg.Connection,
) -> None:
    assert helpers.remove_membership(
        graph, "principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
        == 0
    )


def test_cas02_principal_removal_deletes_downstream_identity_org(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(
        graph, "principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_A, helpers.ORG_A),
        )
        == 0
    )


def test_cas03_principal_removal_deletes_downstream_identity_group(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(
        graph, "principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_A, helpers.GROUP_A),
        )
        == 0
    )


def test_cas04_principal_removal_preserves_other_tenant_memberships(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(
        graph, "principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            graph,
            "principal_tenant_membership",
            "principal_id = %s AND tenant_id = %s",
            (helpers.PRINCIPAL, helpers.TENANT_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_B, helpers.TENANT_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_B, helpers.ORG_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_B, helpers.GROUP_B),
        )
        == 1
    )


def test_cas05_principal_removal_does_not_touch_sibling_principal(
    db,
) -> None:
    helpers.seed_full_membership_graph(db)
    sibling_principal = helpers.new_id()
    sibling_identity = helpers.new_id()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P2', 2)",
        (sibling_principal,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, deletion_status) "
        "VALUES (%s, %s, 'I3', 2)",
        (sibling_identity, sibling_principal),
    )
    helpers.insert_memberships(
        db,
        principal_tenant=(sibling_principal, helpers.TENANT_A),
        identity_tenant=(sibling_identity, helpers.TENANT_A),
        identity_org=(sibling_identity, helpers.ORG_A),
    )
    db.commit()

    helpers.remove_membership(
        db, "principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            db,
            "principal_tenant_membership",
            "principal_id = %s",
            (sibling_principal,),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            db,
            "identity_tenant_membership",
            "identity_id = %s",
            (sibling_identity,),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            db,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (sibling_identity, helpers.ORG_A),
        )
        == 1
    )


def test_cas06_identity_removal_deletes_dependent_identity_org(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(
        graph, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s",
            (helpers.IDENTITY_A,),
        )
        == 0
    )


def test_cas07_identity_removal_deletes_dependent_identity_group(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(
        graph, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s",
            (helpers.IDENTITY_A,),
        )
        == 0
    )


def test_cas08_identity_removal_preserves_other_tenant_memberships(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(
        graph, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_B, helpers.TENANT_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s",
            (helpers.IDENTITY_B,),
        )
        == 1
    )


def test_cas09_identity_removal_leaves_group_memberships_intact(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(
        graph, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            graph,
            "group_tenant_membership",
            "group_id = %s",
            (helpers.GROUP_A,),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s",
            (helpers.GROUP_A,),
        )
        == 1
    )


def test_cas10_group_removal_deletes_group_org(graph: psycopg.Connection) -> None:
    helpers.remove_membership(graph, "group_tenant_membership", helpers.GROUP_A, helpers.TENANT_A)
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s",
            (helpers.GROUP_A,),
        )
        == 0
    )


def test_cas11_group_removal_deletes_all_identity_group(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(graph, "group_tenant_membership", helpers.GROUP_A, helpers.TENANT_A)
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "group_id = %s",
            (helpers.GROUP_A,),
        )
        == 0
    )


def test_cas12_group_removal_preserves_member_identity_tenant(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(graph, "group_tenant_membership", helpers.GROUP_A, helpers.TENANT_A)
    assert (
        helpers.membership_count(
            graph,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
        == 1
    )


def test_cas13_group_removal_preserves_unrelated_groups_and_other_tenant(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_membership(graph, "group_tenant_membership", helpers.GROUP_A, helpers.TENANT_A)
    assert (
        helpers.membership_count(
            graph,
            "group_tenant_membership",
            "group_id = %s",
            (helpers.GROUP_B,),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "group_id = %s",
            (helpers.GROUP_B,),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s",
            (helpers.GROUP_B,),
        )
        == 1
    )


def test_cas14_empty_dependent_set_still_removes_and_audits_once(db) -> None:
    helpers.seed_base_entities(db)
    helpers.insert_memberships(db, principal_tenant=(helpers.PRINCIPAL, helpers.TENANT_A))
    db.commit()
    assert helpers.remove_membership(
        db, "principal_tenant_membership", helpers.PRINCIPAL, helpers.TENANT_A
    )
    assert (
        helpers.membership_count(
            db,
            "principal_tenant_membership",
            "principal_id = %s",
            (helpers.PRINCIPAL,),
        )
        == 0
    )
    rows = helpers.audit_rows(db)
    assert len(rows) == 1
    # (id, occurred_at, kind, tenant, principal, identity, group, org, actor,
    #  principal_tenant, identity_tenant, group_tenant, identity_group,
    #  identity_org, group_org)
    assert rows[0][9] == 1
    assert rows[0][10:15] == (0, 0, 0, 0, 0)


def test_cas15_repeated_removal_is_a_noop_without_audit(
    graph: psycopg.Connection,
) -> None:
    assert helpers.remove_membership(
        graph, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    assert not helpers.remove_membership(
        graph, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    assert len(helpers.audit_rows(graph)) == 1


def test_cas16_rejoin_does_not_restore_dependents(graph: psycopg.Connection) -> None:
    helpers.remove_membership(
        graph, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    helpers.insert_memberships(graph, identity_tenant=(helpers.IDENTITY_A, helpers.TENANT_A))
    graph.commit()
    assert (
        helpers.membership_count(
            graph,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_A, helpers.ORG_A),
        )
        == 0
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_A, helpers.GROUP_A),
        )
        == 0
    )


# --- LEAF: individual leaf-relationship removals ------------------------------


def _snapshot(connection: psycopg.Connection) -> dict[str, int]:
    return {
        table: helpers.membership_count(connection, table) for table in helpers.MEMBERSHIP_TABLES
    }


def test_leaf01_identity_group_removal_deletes_only_exact_row(
    graph: psycopg.Connection,
) -> None:
    assert helpers.remove_identity_group_membership(graph, helpers.IDENTITY_A, helpers.GROUP_A)
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_A, helpers.GROUP_A),
        )
        == 0
    )
    # Prerequisites, the sibling relationship, and the parallel Tenant B
    # relationship are all untouched.
    assert (
        helpers.membership_count(
            graph,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "group_tenant_membership",
            "group_id = %s AND tenant_id = %s",
            (helpers.GROUP_A, helpers.TENANT_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_A, helpers.ORG_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s AND organization_id = %s",
            (helpers.GROUP_A, helpers.ORG_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_B, helpers.GROUP_B),
        )
        == 1
    )
    row = helpers.audit_rows(graph)[0]
    assert row[2] == "identity_group_membership"
    assert str(row[3]) == helpers.TENANT_A
    assert str(row[5]) == helpers.IDENTITY_A
    assert str(row[6]) == helpers.GROUP_A
    assert row[12] == 1
    assert (row[9], row[10], row[11], row[13], row[14]) == (0, 0, 0, 0, 0)


def test_leaf02_identity_org_removal_deletes_only_exact_row(
    graph: psycopg.Connection,
) -> None:
    assert helpers.remove_identity_org_membership(graph, helpers.IDENTITY_A, helpers.ORG_A)
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_A, helpers.ORG_A),
        )
        == 0
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_A, helpers.TENANT_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_A, helpers.GROUP_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s AND organization_id = %s",
            (helpers.GROUP_A, helpers.ORG_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_B, helpers.ORG_B),
        )
        == 1
    )
    row = helpers.audit_rows(graph)[0]
    assert row[2] == "identity_org_membership"
    assert str(row[3]) == helpers.TENANT_A
    assert str(row[5]) == helpers.IDENTITY_A
    assert str(row[7]) == helpers.ORG_A
    assert row[13] == 1
    assert (row[9], row[10], row[11], row[12], row[14]) == (0, 0, 0, 0, 0)


def test_leaf03_group_org_removal_deletes_only_exact_row(
    graph: psycopg.Connection,
) -> None:
    assert helpers.remove_group_org_membership(graph, helpers.GROUP_A, helpers.ORG_A)
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s AND organization_id = %s",
            (helpers.GROUP_A, helpers.ORG_A),
        )
        == 0
    )
    assert (
        helpers.membership_count(
            graph,
            "group_tenant_membership",
            "group_id = %s AND tenant_id = %s",
            (helpers.GROUP_A, helpers.TENANT_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_A, helpers.GROUP_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_A, helpers.ORG_A),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s AND organization_id = %s",
            (helpers.GROUP_B, helpers.ORG_B),
        )
        == 1
    )
    row = helpers.audit_rows(graph)[0]
    assert row[2] == "group_org_membership"
    assert str(row[3]) == helpers.TENANT_A
    assert str(row[6]) == helpers.GROUP_A
    assert str(row[7]) == helpers.ORG_A
    assert row[14] == 1
    assert (row[9], row[10], row[11], row[12], row[13]) == (0, 0, 0, 0, 0)


def test_leaf03b_group_org_cross_tenant_inconsistency_fails_closed(
    graph: psycopg.Connection,
) -> None:
    # Simulate a structural inconsistency that the normal precondition forbids
    # by disabling that trigger and inserting a cross-Tenant GroupOrg row.
    graph.execute(
        "ALTER TABLE mtmf.group_org_membership "
        "DISABLE TRIGGER group_org_membership_precondition_trigger"
    )
    helpers.insert_memberships(graph, group_org=(helpers.GROUP_A, helpers.ORG_B))
    graph.commit()
    with pytest.raises(psycopg.errors.RaiseException):
        helpers.remove_group_org_membership(graph, helpers.GROUP_A, helpers.ORG_B)
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s AND organization_id = %s",
            (helpers.GROUP_A, helpers.ORG_B),
        )
        == 1
    )
    assert helpers.audit_rows(graph) == []


def test_leaf04_other_tenant_and_siblings_unaffected(
    graph: psycopg.Connection,
) -> None:
    helpers.remove_identity_group_membership(graph, helpers.IDENTITY_A, helpers.GROUP_A)
    assert (
        helpers.membership_count(
            graph,
            "principal_tenant_membership",
            "principal_id = %s AND tenant_id = %s",
            (helpers.PRINCIPAL, helpers.TENANT_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_tenant_membership",
            "identity_id = %s AND tenant_id = %s",
            (helpers.IDENTITY_B, helpers.TENANT_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_org_membership",
            "identity_id = %s AND organization_id = %s",
            (helpers.IDENTITY_B, helpers.ORG_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "group_tenant_membership",
            "group_id = %s AND tenant_id = %s",
            (helpers.GROUP_B, helpers.TENANT_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "identity_group_membership",
            "identity_id = %s AND group_id = %s",
            (helpers.IDENTITY_B, helpers.GROUP_B),
        )
        == 1
    )
    assert (
        helpers.membership_count(
            graph,
            "group_org_membership",
            "group_id = %s AND organization_id = %s",
            (helpers.GROUP_B, helpers.ORG_B),
        )
        == 1
    )


@pytest.mark.parametrize(
    ("kind", "first_id", "second_id"),
    [
        ("identity_group_membership", helpers.IDENTITY_A, helpers.GROUP_B),
        ("identity_org_membership", helpers.IDENTITY_A, helpers.ORG_B),
        ("group_org_membership", helpers.GROUP_A, helpers.ORG_B),
    ],
)
def test_leaf08_missing_membership_is_a_noop_without_audit(
    graph: psycopg.Connection, kind: str, first_id: str, second_id: str
) -> None:
    before = _snapshot(graph)
    assert not helpers.remove_membership(graph, kind, first_id, second_id)
    assert _snapshot(graph) == before
    assert helpers.audit_rows(graph) == []


def test_leaf09_repeated_leaf_removal_writes_one_audit(
    graph: psycopg.Connection,
) -> None:
    assert helpers.remove_identity_org_membership(graph, helpers.IDENTITY_A, helpers.ORG_A)
    assert not helpers.remove_identity_org_membership(graph, helpers.IDENTITY_A, helpers.ORG_A)
    assert len(helpers.audit_rows(graph)) == 1
