"""Removal trust-boundary tests (SEC-01..SEC-03).

SEC-01: a direct DELETE/TRUNCATE cannot bypass the cascade/audit boundary;
memberships are hard-deleted only through the sanctioned removal functions.
SEC-02/SEC-03: protected root/bootstrap and Tenant Stewardship enforcement is
deferred because revision 0002 has no authoritative persisted root or
stewardship state to identify a protected membership (PR 10 owns it). The
removal functions enforce structural cascade and audit invariants only; the
gap is asserted here and documented in ``docs/ARCHITECTURE.md`` rather than
silently claimed as enforced.
"""

from __future__ import annotations

import helpers
import psycopg.errors
import psycopg.sql
import pytest


def _table_statement(verb: str, table: str) -> psycopg.sql.SQL:
    """Compose a schema-qualified statement for a fixed membership table."""
    return psycopg.sql.SQL("{} mtmf.{}").format(
        psycopg.sql.SQL(verb), psycopg.sql.Identifier(table)
    )


@pytest.mark.parametrize("table", sorted(helpers.MEMBERSHIP_TABLES))
def test_sec01_direct_delete_is_rejected(db, table: str) -> None:
    helpers.seed_full_membership_graph(db)
    with pytest.raises(psycopg.errors.RaiseException), db.transaction():
        db.execute(_table_statement("DELETE FROM", table))


@pytest.mark.parametrize("table", sorted(helpers.MEMBERSHIP_TABLES))
def test_sec01_direct_truncate_is_rejected(db, table: str) -> None:
    helpers.seed_full_membership_graph(db)
    with pytest.raises(psycopg.errors.RaiseException), db.transaction():
        db.execute(_table_statement("TRUNCATE", table))


def test_sec01_sanctioned_removal_is_the_only_supported_path(db) -> None:
    helpers.seed_full_membership_graph(db)
    assert helpers.remove_membership(
        db, "identity_tenant_membership", helpers.IDENTITY_A, helpers.TENANT_A
    )
    assert len(helpers.audit_rows(db)) == 1


def test_sec02_sec03_protected_root_and_stewardship_enforcement_deferred(db) -> None:
    # There is deliberately no persisted root Principal marker, no root
    # membership flag, and no stewardship table in this revision, so a
    # protected root/stewardship membership cannot be identified from
    # authoritative data. Enforcement must not be invented here; it is
    # deferred to PR 10 (bootstrap/root/stewardship).
    tenant_columns = helpers.columns_of(db, "tenant")
    principal_columns = helpers.columns_of(db, "principal")
    assert not {"is_root", "root", "bootstrap"} & set(tenant_columns)
    assert not {"is_root", "root", "bootstrap"} & set(principal_columns)
    assert "tenant_stewardship" not in helpers.tables(db)
    # Authorization/protection is applied above the persistence boundary; the
    # removal functions themselves consult no session or role context.
    assert "remove_principal_tenant_membership" in helpers.functions_in_schema(db)
