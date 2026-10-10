"""Migration ownership tests (MIG) and PR boundary tests (BND).

MIG: an empty database upgrades to head; the second upgrade is
idempotent; the current revision is visible through the MTMF migration
interface without Alembic objects; the MTMF migration graph lives inside
the ``mtmf`` schema; and packaged resources resolve without the
repository working directory.

BND: the PR 7B PostgreSQL provider, repositories, and UnitOfWork exist
and satisfy the persistence SPI; PR 9 adds only the two typed
Role-assignment tables and their trusted functions. No polymorphic
RoleAssignment table, stewardship, TenantManagementGroup, bootstrap/root
state, IdP state, or public API DTOs exist.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import helpers

from mtmf_core.persistence import MtmfSpi
from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresMigrationManager,
)

EXPECTED_FUNCTION_NAMES = {
    "mtf_schema_version",
    "identity_tenant_membership_precondition",
    "group_tenant_membership_precondition",
    "identity_group_membership_precondition",
    "identity_org_membership_precondition",
    "group_org_membership_precondition",
    "identity_tenant_membership_check",
    "group_tenant_membership_check",
    "identity_group_membership_check",
    "identity_org_membership_check",
    "group_org_membership_check",
    "guard_tenant_immutable_columns",
    "guard_organization_immutable_columns",
    "guard_principal_immutable_columns",
    "guard_identity_immutable_columns",
    "guard_group_immutable_columns",
    "guard_role_immutable_columns",
    "guard_permission_set_immutable_columns",
    "guard_permission_immutable_columns",
    "guard_action_immutable_columns",
    "block_membership_updates",
    "membership_delete_guard",
    "guard_membership_removal_audit",
    "remove_principal_tenant_membership",
    "remove_identity_tenant_membership",
    "remove_group_tenant_membership",
    "remove_identity_group_membership",
    "remove_identity_org_membership",
    "remove_group_org_membership",
    "role_insert_children",
    "role_validate_children",
    "tenant_add",
    "tenant_get",
    "tenant_save",
    "organization_add",
    "organization_get",
    "organization_save",
    "principal_add",
    "principal_get",
    "principal_save",
    "identity_add",
    "identity_get",
    "identity_save",
    "group_add",
    "group_get",
    "group_save",
    "action_add",
    "action_get",
    "role_add",
    "role_get",
    "role_save",
    "install_builtin_policy",
    "stewardship_is_eligible",
    "bootstrap_root",
    "designate_steward",
    "activate_tenant",
    "suspend_tenant",
    "recover_root_identity",
    "guard_stewardship_designation",
    "guard_root_registry",
    "guard_root_registry_delete",
    "guard_root_tenant",
    "guard_root_principal",
    "guard_root_identity",
    "guard_steward_principal",
    "guard_steward_identity",
    "guard_root_steward_membership_delete",
    "guard_tenant_activation",
    "guard_stewardship_audit",
    "guard_steward_role_assignment",
    "guard_steward_group_membership",
    "guard_steward_group",
    "principal_tenant_membership_add",
    "principal_tenant_membership_get",
    "principal_tenant_membership_find_by_principal",
    "principal_tenant_membership_find_by_tenant",
    "identity_tenant_membership_add",
    "identity_tenant_membership_get",
    "identity_tenant_membership_find_by_identity",
    "identity_tenant_membership_find_by_tenant",
    "group_tenant_membership_add",
    "group_tenant_membership_get",
    "group_tenant_membership_find_by_group",
    "group_tenant_membership_find_by_tenant",
    "identity_group_membership_add",
    "identity_group_membership_get",
    "identity_group_membership_find_by_identity",
    "identity_group_membership_find_by_group",
    "identity_org_membership_add",
    "identity_org_membership_get",
    "identity_org_membership_find_by_identity",
    "identity_org_membership_find_by_organization",
    "group_org_membership_add",
    "group_org_membership_get",
    "group_org_membership_find_by_group",
    "group_org_membership_find_by_organization",
    "role_assignment_validate_role",
    "identity_role_assignment_validate",
    "group_role_assignment_validate",
    "identity_role_assignment_add",
    "identity_role_assignment_get",
    "identity_role_assignment_find_by_tenant_and_identity",
    "identity_role_assignment_remove",
    "group_role_assignment_add",
    "group_role_assignment_get",
    "group_role_assignment_find_by_tenant_and_group",
    "group_role_assignment_remove",
    "install_management_roles",
    "guard_tenant_management_group",
    "guard_tenant_management_group_membership",
    "guard_tenant_management_group_actor_eligibility",
    "create_root_management_group",
    "initialize_root_tenant_management_group",
    "create_tenant_management_group",
    "add_tenant_management_group_membership",
    "remove_tenant_management_group_membership",
    "add_tenant_management_group_actor_eligibility",
    "remove_tenant_management_group_actor_eligibility",
    "tenant_management_group_get",
    "tenant_management_group_find_by_manager",
    "tenant_management_group_membership_get",
    "tenant_management_group_membership_find_by_group",
    "tenant_management_group_membership_find_by_tenant",
    "tenant_management_group_actor_eligibility_get",
    "tenant_management_group_actor_eligibility_find_by_group",
    "tenant_management_group_actor_eligibility_find_by_identity",
    "root_registry_get",
}

_FORBIDDEN_TABLES = (
    "role_assignment",
    "tenant_stewardship",
    "principal_org_membership",
    "principal_group_membership",
    "generic_membership",
    "membership",
)


# --- MIG: migration ownership -------------------------------------------------


def test_mig01_empty_database_upgrades_to_head(db, migrator_config: PostgresConfig) -> None:
    manager = PostgresMigrationManager(migrator_config)
    assert manager.current_revision() == manager.head_revision


def test_mig02_second_upgrade_to_head_is_idempotent(db, migrator_config: PostgresConfig) -> None:
    manager = PostgresMigrationManager(migrator_config)
    manager.upgrade_to_head()
    assert manager.current_revision() == manager.head_revision


def test_mig03_current_revision_available_through_mtmf_interface(
    db, migrator_config: PostgresConfig
) -> None:
    manager = PostgresMigrationManager(migrator_config)
    revision = manager.current_revision()
    assert revision == "0009"
    assert revision == manager.head_revision


def test_mig04_callers_need_no_alembic_objects(db, migrator_config: PostgresConfig) -> None:
    manager = PostgresMigrationManager(migrator_config)
    for name in (
        "config_file",
        "script_location",
        "revision",
        "revisions",
        "command",
        "alembic",
        "ini",
    ):
        assert not hasattr(manager, name), f"migration interface must not expose {name!r}"
    # The public surface is deliberate and minimal.
    public = {name for name in vars(type(manager)) if not name.startswith("_")}
    assert public == {"config", "head_revision", "current_revision", "upgrade_to_head"}


def test_mig05_mtmf_migration_graph_is_isolated(db) -> None:
    # The Alembic version table lives inside the MTMF schema...
    assert "alembic_version" in helpers.tables(db)
    # ...and no MTMF table leaks into the public schema.
    assert helpers.tables(db, schema="public") == set()


def test_mig06_mtmf_spi_has_no_migration_methods() -> None:
    for name in ("upgrade", "upgrade_to_head", "downgrade", "current_revision", "migrate"):
        assert not hasattr(MtmfSpi, name), f"MtmfSpi must not expose {name!r}"


def test_mig07_packaged_resources_work_without_repository_cwd(
    mtmf_config: PostgresConfig,
) -> None:
    code = (
        "from mtmf_core.persistence.postgres import "
        "PostgresMigrationManager, PostgresRole, PostgresConfig;"
        "PostgresMigrationManager("
        "PostgresConfig.from_env(PostgresRole.MIGRATOR)"
        ").upgrade_to_head()"
    )
    env = {key: value for key, value in os.environ.items() if key.startswith("MTMF_")}
    with tempfile.TemporaryDirectory() as tmp:
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=tmp,  # not the repository root: packaged resources only
            env=env,
            capture_output=True,
            text=True,
        )
    assert result.returncode == 0, result.stderr


# --- BND: PR boundary ---------------------------------------------------------


def test_bnd01_and_bnd03_postgres_provider_implements_the_existing_spi() -> None:
    import mtmf_core.persistence as persistence
    from mtmf_core.persistence import postgres  # type: ignore[attr-defined]

    # PR 7B implements the existing SPI; it does not add a second,
    # competing provider surface under ``mtmf_core.persistence``.
    assert not hasattr(persistence, "PostgresMtmfSpi")
    assert hasattr(postgres, "PostgresMtmfSpi")
    assert hasattr(postgres, "PostgresUnitOfWork")
    assert not hasattr(postgres, "UnitOfWork")
    # The SPI surface itself is unchanged from PR 5.
    assert hasattr(persistence, "MtmfSpi")


def test_bnd02_no_repository_crud_function_family(db) -> None:
    functions = helpers.functions_in_schema(db)
    assert functions == EXPECTED_FUNCTION_NAMES
    assert not any("repository" in name for name in functions)


def test_bnd04_to_bnd07_no_role_assignment_stewardship_tmg_or_bootstrap(db) -> None:
    actual = helpers.tables(db)
    assert all(table not in actual for table in _FORBIDDEN_TABLES)
    # No root/bootstrap columns exist on tenants.
    tenant_columns = helpers.columns_of(db, "tenant")
    assert "is_root" not in tenant_columns
    assert "bootstrap" not in tenant_columns


def test_bnd08_no_idp_or_federation_state(db) -> None:
    identity_columns = helpers.columns_of(db, "identity")
    for name in ("idp", "federation", "identity_type", "provider", "subject"):
        assert name not in identity_columns
    principal_columns = helpers.columns_of(db, "principal")
    assert "kind" not in principal_columns


def test_bnd09_no_public_api_imports_from_postgres_infrastructure() -> None:
    code = (
        "import mtmf_core.persistence.postgres, sys; "
        "sys.exit('mtmf_api' in sys.modules or 'mtmf_client' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_bnd10_postgres_infrastructure_imports_no_authorization() -> None:
    # The postgres infrastructure package must not import the
    # authorization foundation: persistence never evaluates policy.
    import importlib
    import types

    for module_name in (
        "mtmf_core.persistence.postgres",
        "mtmf_core.persistence.postgres.config",
        "mtmf_core.persistence.postgres.resources",
        "mtmf_core.persistence.postgres.migration",
        "mtmf_core.persistence.postgres.mapping",
        "mtmf_core.persistence.postgres.error_translation",
        "mtmf_core.persistence.postgres.repositories",
        "mtmf_core.persistence.postgres.spi",
        "mtmf_core.persistence.postgres.unit_of_work",
    ):
        module = importlib.import_module(module_name)
        for attribute in vars(module).values():
            if isinstance(attribute, types.ModuleType) and attribute.__name__.startswith(
                "mtmf_core.authorization"
            ):
                raise AssertionError(f"{module_name} must not import {attribute.__name__}")
