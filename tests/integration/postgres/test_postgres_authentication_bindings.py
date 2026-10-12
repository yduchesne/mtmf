"""Authentication-binding integration tests (0011) on real PostgreSQL.

Operator mutation is exercised through the administrator/owner connection
against the operator-only stored functions; the restricted ``mtmf_runtime``
login is used for the read path and to prove that direct table access and
privileged mutation are denied.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import psycopg
import pytest

from mtmf_core import DomainId
from mtmf_core.domain.authentication_binding import (
    BindingLifecycle,
    ExternalSubjectBinding,
    ServiceCredentialBinding,
)
from mtmf_core.persistence.postgres import PostgresConfig, PostgresMtmfSpi

_ACTIVE = int(BindingLifecycle.ACTIVE)


def _uuid() -> str:
    return str(uuid.uuid4())


def _seed(db: psycopg.Connection) -> tuple[str, str, str]:
    """Seed a Principal/Identity/Tenant and one Application; return ids."""
    principal_id, identity_id, tenant_id = _uuid(), _uuid(), _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (principal_id,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', 2, 2)",
        (identity_id, principal_id),
    )
    db.execute(
        "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'T', 2, %s, 1, 2)",
        (tenant_id, identity_id),
    )
    application_id = _uuid()
    added = db.execute(
        "SELECT mtmf.application_add(%s, %s, 'A', %s, 1::smallint, '{}'::jsonb)",
        (application_id, f"app-{_uuid()[:8]}", identity_id),
    ).fetchone()[0]
    assert added is True
    return identity_id, application_id, tenant_id


def _add_service_binding(
    db: psycopg.Connection, issuer: str, client_id: str, application_id: str
) -> str:
    binding_id = _uuid()
    added = db.execute(
        "SELECT mtmf.service_credential_application_add(%s, %s, %s, %s, %s::smallint, now())",
        (binding_id, issuer, client_id, application_id, _ACTIVE),
    ).fetchone()[0]
    assert added is True
    return binding_id


def _add_subject_binding(
    db: psycopg.Connection, issuer: str, subject: str, identity_id: str
) -> str:
    binding_id = _uuid()
    added = db.execute(
        "SELECT mtmf.external_subject_identity_add(%s, %s, %s, %s, %s::smallint, now())",
        (binding_id, issuer, subject, identity_id, _ACTIVE),
    ).fetchone()[0]
    assert added is True
    return binding_id


def test_pr14_binding01_operator_add_and_runtime_read(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    identity_id, application_id, _ = _seed(db)
    issuer = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"
    _add_service_binding(db, issuer, "client-1", application_id)
    _add_subject_binding(db, issuer, "user-1", identity_id)

    with postgres_spi.create_unit_of_work() as uow:
        service = postgres_spi.create_service_credential_application_repository(
            uow
        ).find_active_by_key(issuer, "client-1")
        subject = postgres_spi.create_external_subject_binding_repository(uow).find_active_by_key(
            issuer, "user-1"
        )
    assert service is not None
    assert service.application_id == DomainId.from_str(application_id)
    assert service.lifecycle is BindingLifecycle.ACTIVE
    assert subject is not None
    assert subject.identity_id == DomainId.from_str(identity_id)


def test_pr14_binding02_revoked_binding_is_not_active(
    db: psycopg.Connection, postgres_spi: PostgresMtmfSpi
) -> None:
    _, application_id, _ = _seed(db)
    issuer = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"
    binding_id = _add_service_binding(db, issuer, "client-2", application_id)
    revoked = db.execute(
        "SELECT mtmf.service_credential_application_revoke(%s)", (binding_id,)
    ).fetchone()[0]
    assert revoked is True
    with postgres_spi.create_unit_of_work() as uow:
        found = postgres_spi.create_service_credential_application_repository(
            uow
        ).find_active_by_key(issuer, "client-2")
    assert found is None


def test_pr14_binding03_duplicate_active_key_is_rejected(db: psycopg.Connection) -> None:
    _, application_id, _ = _seed(db)
    issuer = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"
    _add_service_binding(db, issuer, "client-3", application_id)
    second = db.execute(
        "SELECT mtmf.service_credential_application_add(%s, %s, %s, %s, %s::smallint, now())",
        (_uuid(), issuer, "client-3", application_id, _ACTIVE),
    ).fetchone()[0]
    assert second is False


def test_pr14_binding04_runtime_cannot_mutate_or_read_tables(
    db: psycopg.Connection, runtime_config: PostgresConfig
) -> None:
    _, application_id, _ = _seed(db)
    issuer = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"
    _add_service_binding(db, issuer, "client-4", application_id)
    with psycopg.connect(runtime_config.psycopg_dsn, autocommit=True) as runtime:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute("SELECT issuer FROM mtmf.service_credential_application").fetchone()
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime.execute(
                "SELECT mtmf.service_credential_application_add("
                "%s, %s, %s, %s, %s::smallint, now())",
                (_uuid(), issuer, "client-5", application_id, _ACTIVE),
            ).fetchone()


def test_pr14_binding05_immutable_key_guard(db: psycopg.Connection) -> None:
    _, application_id, _ = _seed(db)
    issuer = "https://127.0.0.1:28443/realms/mtmf-pr14-dev"
    binding_id = _add_service_binding(db, issuer, "client-6", application_id)
    with pytest.raises(psycopg.Error):
        db.execute(
            "UPDATE mtmf.service_credential_application SET client_id = 'other' WHERE id = %s",
            (binding_id,),
        )


def test_pr14_binding06_root_registry_read(postgres_spi: PostgresMtmfSpi) -> None:
    with postgres_spi.create_unit_of_work() as uow:
        record = postgres_spi.create_root_registry_repository(uow).get()
    assert record is None or record.root_tenant_id is not None


def test_pr14_binding07_domain_objects_round_trip() -> None:
    now = datetime.now(UTC)
    binding = ServiceCredentialBinding(
        id=DomainId.generate(),
        issuer="https://issuer.example",
        client_id="client",
        application_id=DomainId.generate(),
        created_at=now,
    )
    assert binding.lifecycle is BindingLifecycle.ACTIVE
    subject = ExternalSubjectBinding(
        id=DomainId.generate(),
        issuer="https://issuer.example",
        subject="user",
        identity_id=DomainId.generate(),
        created_at=now,
    )
    assert subject.is_active is True
