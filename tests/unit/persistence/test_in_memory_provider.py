"""In-memory provider boundary and detachment tests.

These tests prove the deterministic in-memory contract provider really
behaves like persistence rather than an object registry: committed and
loaded objects are detached snapshots, providers are isolated per
instance, no SQL/driver/migration/IdP machinery leaks in, domain and
authorization never depend on persistence, and repositories do not
authorize.
"""

from __future__ import annotations

import importlib
import subprocess
import sys
import types
from pathlib import Path

import pytest
from helpers import make_organization, make_tenant

from mtmf_core import (
    DeletionStatus,
    Identity,
    InMemoryMtmfSpi,
)
from mtmf_core.persistence import (
    ForeignUnitOfWorkError,
    MtmfSpi,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

PERSISTENCE_MODULES = (
    "mtmf_core.persistence",
    "mtmf_core.persistence.errors",
    "mtmf_core.persistence.unit_of_work",
    "mtmf_core.persistence.repositories",
    "mtmf_core.persistence.spi",
    "mtmf_core.persistence.testing",
    "mtmf_core.persistence.testing.in_memory",
)

FORBIDDEN_MODULE_FRAGMENTS = (
    "psycopg",
    "sqlalchemy",
    "alembic",
    "sqlite",
    "asyncpg",
)


def test_provider_lives_in_the_testing_package() -> None:
    assert InMemoryMtmfSpi.__module__ == "mtmf_core.persistence.testing.in_memory"


def test_two_provider_instances_are_fully_isolated() -> None:
    first = InMemoryMtmfSpi()
    second = InMemoryMtmfSpi()
    tenant = make_tenant()
    with first.create_unit_of_work() as uow:
        first.create_tenant_repository(uow).add(tenant)
        uow.commit()
    with second.create_unit_of_work() as uow:
        assert second.create_tenant_repository(uow).get(tenant.id) is None


def test_get_returns_detached_copies(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        tenants = spi.create_tenant_repository(uow)
        first_load = tenants.get(tenant.id)
        second_load = tenants.get(tenant.id)
        assert first_load is not tenant
        assert first_load is not second_load
        first_load.name = "mutated-first"
        assert second_load.name == tenant.name


def test_added_entity_is_detached_from_the_caller(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    name_at_add = tenant.name
    with spi.create_unit_of_work() as uow:
        tenants = spi.create_tenant_repository(uow)
        tenants.add(tenant)
        # Mutating the caller's original inside the transaction does not
        # retroactively change the staged snapshot taken at add-time.
        tenant.name = "mutated-after-add"
        assert tenants.get(tenant.id).name == name_at_add
        uow.commit()
    with spi.create_unit_of_work() as uow:
        assert spi.create_tenant_repository(uow).get(tenant.id).name == name_at_add


def test_loaded_entity_mutation_does_not_reach_other_loads(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        tenants = spi.create_tenant_repository(uow)
        loaded = tenants.get(tenant.id)
        loaded.extension["mutated"] = True
        assert "mutated" not in tenants.get(tenant.id).extension
    with spi.create_unit_of_work() as uow:
        assert "mutated" not in spi.create_tenant_repository(uow).get(tenant.id).extension


def test_committed_state_is_a_detached_snapshot_between_unit_of_works(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = spi.create_tenant_repository(uow).get(tenant.id)
        loaded.name = "corrupted"
    with spi.create_unit_of_work() as uow:
        assert spi.create_tenant_repository(uow).get(tenant.id).name == tenant.name


def test_soft_deletion_state_survives_commit_through_save(spi: MtmfSpi) -> None:
    tenant = make_tenant()
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(tenant)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        loaded = spi.create_tenant_repository(uow).get(tenant.id)
        loaded.soft_delete()
        spi.create_tenant_repository(uow).save(loaded)
        uow.commit()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_tenant_repository(uow).get(tenant.id)
        assert stored.deletion_status is DeletionStatus.DELETED
        assert stored.deleted


def test_foreign_provider_unit_of_work_is_rejected_by_every_factory() -> None:
    foreign = InMemoryMtmfSpi()
    with foreign.create_unit_of_work() as foreign_uow:
        for factory_name in (
            "create_tenant_repository",
            "create_organization_repository",
            "create_principal_repository",
            "create_identity_repository",
            "create_group_repository",
            "create_role_repository",
            "create_action_repository",
            "create_principal_tenant_membership_repository",
            "create_identity_tenant_membership_repository",
            "create_group_tenant_membership_repository",
            "create_identity_group_membership_repository",
            "create_identity_org_membership_repository",
            "create_group_org_membership_repository",
        ):
            with pytest.raises(ForeignUnitOfWorkError):
                getattr(InMemoryMtmfSpi(), factory_name)(foreign_uow)


def test_persistence_modules_import_no_sql_driver_or_migration_machinery() -> None:
    for module_name in PERSISTENCE_MODULES:
        module = importlib.import_module(module_name)
        for attribute in vars(module).values():
            if isinstance(attribute, types.ModuleType):
                for fragment in FORBIDDEN_MODULE_FRAGMENTS:
                    assert fragment not in attribute.__name__, (
                        f"{module_name} must not import {attribute.__name__} "
                        f"(contains {fragment!r})"
                    )


def test_persistence_imports_do_not_pull_database_drivers_or_migrations() -> None:
    # Deterministic regardless of test order: a fresh interpreter state.
    code = (
        "import sys; "
        "import mtmf_core.persistence; "
        "import mtmf_core.persistence.testing; "
        "offenders = [m for m in sys.modules "
        "if m.startswith(('psycopg', 'alembic', 'sqlalchemy'))]; "
        "sys.exit(bool(offenders))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_importing_spi_does_not_pull_the_postgres_package() -> None:
    code = (
        "import sys, importlib; "
        "importlib.import_module('mtmf_core.persistence'); "
        "sys.exit('mtmf_core.persistence.postgres' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "mtmf_core.persistence (the PR 5 SPI) must stay free of PostgreSQL "
        "infrastructure imports; " + result.stderr
    )


def test_core_persistence_is_importable_without_mtmf_api() -> None:
    code = (
        "import mtmf_core.persistence, mtmf_core.persistence.testing, sys; "
        "sys.exit('mtmf_api' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_domain_does_not_depend_on_persistence() -> None:
    # No domain module may import the persistence package: the import
    # edge must flow persistence -> domain, never the reverse.
    domain = importlib.import_module("mtmf_core.domain")
    offenders: list[str] = []
    for name, attribute in list(vars(domain).items()):
        if isinstance(attribute, types.ModuleType) and attribute.__name__.startswith(
            "mtmf_core.persistence"
        ):
            offenders.append(name)
    assert offenders == []


def test_persistence_does_not_import_authorization() -> None:
    for module_name in PERSISTENCE_MODULES:
        module = importlib.import_module(module_name)
        for attribute in vars(module).values():
            if isinstance(attribute, types.ModuleType) and attribute.__name__.startswith(
                "mtmf_core.authorization"
            ):
                raise AssertionError(f"{module_name} must not import {attribute.__name__}")


def test_repositories_do_not_authorize(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        repositories = [
            spi.create_tenant_repository(uow),
            spi.create_organization_repository(uow),
            spi.create_principal_repository(uow),
            spi.create_identity_repository(uow),
            spi.create_group_repository(uow),
            spi.create_role_repository(uow),
            spi.create_action_repository(uow),
            spi.create_principal_tenant_membership_repository(uow),
            spi.create_identity_tenant_membership_repository(uow),
            spi.create_group_tenant_membership_repository(uow),
            spi.create_identity_group_membership_repository(uow),
            spi.create_identity_org_membership_repository(uow),
            spi.create_group_org_membership_repository(uow),
        ]
    for repository in repositories:
        for name in ("authorize", "decide", "allowed", "is_allowed"):
            assert not hasattr(repository, name), (
                f"{type(repository).__name__} must not expose {name!r}"
            )


def test_spi_and_uow_do_not_simulate_concurrency_machinery(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        for subject in (spi, uow):
            for name in (
                "lock",
                "locks",
                "mvcc",
                "isolation_level",
                "isolation",
                "deadlock",
                "retry",
                "serializable",
            ):
                assert not hasattr(subject, name), f"must not simulate {name!r}"


def test_provider_is_not_used_by_domain_or_authorization() -> None:
    # Domain and authorization constructors never see persistence: the
    # provider is only reachable through the explicit SPI seam.
    assert Identity is not None
    tenant = make_tenant()
    organization = make_organization(tenant_id=tenant.id)
    assert tenant.id is not None
    assert organization.id is not None


def test_duplicate_immutable_identity_never_silently_overwrites(spi: MtmfSpi) -> None:
    from mtmf_core.persistence import DuplicatePersistenceIdentityError

    original = make_tenant(name="original")
    with spi.create_unit_of_work() as uow:
        spi.create_tenant_repository(uow).add(original)
        uow.commit()
    # A distinct object carrying the same immutable id is rejected, not merged.
    impostor = make_tenant(name="impostor")
    object.__setattr__(impostor, "id", original.id)
    with spi.create_unit_of_work() as uow:
        with pytest.raises(DuplicatePersistenceIdentityError):
            spi.create_tenant_repository(uow).add(impostor)
        uow.rollback()
    with spi.create_unit_of_work() as uow:
        stored = spi.create_tenant_repository(uow).get(original.id)
        assert stored.name == "original"


def test_no_hard_delete_surface_exists_on_entity_repositories(spi: MtmfSpi) -> None:
    with spi.create_unit_of_work() as uow:
        repositories = [
            spi.create_tenant_repository(uow),
            spi.create_organization_repository(uow),
            spi.create_principal_repository(uow),
            spi.create_identity_repository(uow),
            spi.create_group_repository(uow),
            spi.create_role_repository(uow),
            spi.create_action_repository(uow),
        ]
    for repository in repositories:
        for name in ("delete", "remove", "hard_delete", "truncate"):
            assert not hasattr(repository, name)
