"""Unit tests for the PostgreSQL MtmfSpi provider surface (no database).

A runtime-only configuration is required at construction, repository
factories reject foreign UnitOfWorks, and the provider exposes no
migration, IdP, or driver surface. No connection is opened here.
"""

from __future__ import annotations

import pytest

from mtmf_core.persistence.errors import (
    ForeignUnitOfWorkError,
    PersistenceConfigurationError,
)
from mtmf_core.persistence.postgres.config import PostgresConfig, PostgresRole
from mtmf_core.persistence.postgres.spi import PostgresMtmfSpi


def _config(role: PostgresRole) -> PostgresConfig:
    return PostgresConfig(
        host="db.example",
        port=25432,
        database="mtmf",
        user=f"user_{role.value}",
        password="pw",
        role=role,
    )


@pytest.mark.parametrize("role", [PostgresRole.ADMIN, PostgresRole.MIGRATOR])
def test_non_runtime_configuration_is_rejected(role: PostgresRole) -> None:
    with pytest.raises(PersistenceConfigurationError):
        PostgresMtmfSpi(_config(role))


def test_runtime_configuration_is_accepted() -> None:
    provider = PostgresMtmfSpi(_config(PostgresRole.RUNTIME))
    uow = provider.create_unit_of_work()
    assert uow is not None
    assert provider.create_unit_of_work() is not uow


def test_all_repository_factories_build_for_the_owning_unit_of_work() -> None:
    provider = PostgresMtmfSpi(_config(PostgresRole.RUNTIME))
    uow = provider.create_unit_of_work()
    factories = (
        provider.create_tenant_repository,
        provider.create_organization_repository,
        provider.create_principal_repository,
        provider.create_identity_repository,
        provider.create_group_repository,
        provider.create_role_repository,
        provider.create_action_repository,
        provider.create_principal_tenant_membership_repository,
        provider.create_identity_tenant_membership_repository,
        provider.create_group_tenant_membership_repository,
        provider.create_identity_group_membership_repository,
        provider.create_identity_org_membership_repository,
        provider.create_group_org_membership_repository,
    )
    for factory in factories:
        assert factory(uow) is not None


def test_foreign_unit_of_work_is_rejected() -> None:
    first = PostgresMtmfSpi(_config(PostgresRole.RUNTIME))
    second = PostgresMtmfSpi(_config(PostgresRole.RUNTIME))
    foreign = second.create_unit_of_work()
    with pytest.raises(ForeignUnitOfWorkError):
        first.create_tenant_repository(foreign)
    with pytest.raises(ForeignUnitOfWorkError):
        first.create_role_repository(foreign)


def test_non_unit_of_work_object_is_rejected() -> None:
    provider = PostgresMtmfSpi(_config(PostgresRole.RUNTIME))
    with pytest.raises(ForeignUnitOfWorkError):
        provider.create_tenant_repository(object())  # type: ignore[arg-type]


def test_provider_exposes_no_driver_or_migration_surface() -> None:
    provider = PostgresMtmfSpi(_config(PostgresRole.RUNTIME))
    for name in (
        "connection",
        "cursor",
        "session",
        "engine",
        "pool",
        "transaction",
        "execute",
        "query",
        "sql",
        "upgrade",
        "downgrade",
        "migration",
        "revision",
        "idp",
        "oidc",
    ):
        assert not hasattr(provider, name), f"provider must not expose {name!r}"
