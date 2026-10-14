"""PR 19C PostgreSQL behaviour for the verified membership add (0012).

Exercises the audited repository path on the actual restricted runtime
login: one membership and exactly one append-only audit row for a new
insert, no audit for a duplicate no-op, atomic rollback, and the revoked
legacy runtime bypass.
"""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime

import psycopg
import pytest

from mtmf_core import DomainId
from mtmf_core.domain.iam_urn import ActionUrn
from mtmf_core.persistence.errors import PersistenceError, PersistenceReferenceError
from mtmf_core.persistence.postgres import PostgresConfig, PostgresMtmfSpi
from mtmf_core.persistence.spi import MtmfSpi

_TENANT_ADMIN_URN = "urn:mtmf:iam:roles:system:tenant-administrator"
_ACTION_URN = ActionUrn("urn:mtmf:iam:actions:system:identity-group-membership:add-object")


def _sid() -> str:
    return str(uuid.uuid4())


def _seed(db: psycopg.Connection) -> dict[str, str]:
    tenant, other_tenant = _sid(), _sid()
    principal, actor, subject, group, application = (_sid() for _ in range(5))
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', 2)",
        (principal,),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'Actor', 2, 2), (%s, %s, 'Subject', 2, 2)",
        (actor, principal, subject, principal),
    )
    db.execute(
        "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'T', 2, %s, 1, 2), (%s, 'Other', 2, %s, 1, 2)",
        (tenant, actor, other_tenant, actor),
    )
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s, %s, 'G', 2)",
        (group, tenant),
    )
    db.execute("INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)", (principal, tenant))
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s), (%s, %s)",
        (actor, tenant, subject, tenant),
    )
    db.execute("INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)", (group, tenant))
    db.execute(
        "INSERT INTO mtmf.identity_role_assignment (id, tenant_id, identity_id, role_urn) "
        "VALUES (%s, %s, %s, %s)",
        (_sid(), tenant, actor, _TENANT_ADMIN_URN),
    )
    db.execute(
        "INSERT INTO mtmf.stewardship_designation "
        "(tenant_id, steward_principal_id, designated_identity_id, version) VALUES (%s, %s, %s, 1)",
        (tenant, principal, actor),
    )
    return {
        "tenant": tenant,
        "principal": principal,
        "actor": actor,
        "subject": subject,
        "group": group,
        "application": application,
    }


def _add_verified(postgres_spi: MtmfSpi, ids: dict[str, str], *, commit: bool = True) -> bool:
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_group_membership_repository(uow)
        repository.lock_verified_add(
            tenant_id=DomainId.from_str(ids["tenant"]),
            actor_identity_id=DomainId.from_str(ids["actor"]),
            subject_identity_id=DomainId.from_str(ids["subject"]),
            group_id=DomainId.from_str(ids["group"]),
        )
        created = repository.add_verified(
            identity_id=DomainId.from_str(ids["subject"]),
            group_id=DomainId.from_str(ids["group"]),
            operation_id=uuid.uuid4(),
            actor_identity_id=DomainId.from_str(ids["actor"]),
            actor_principal_id=DomainId.from_str(ids["principal"]),
            tenant_id=DomainId.from_str(ids["tenant"]),
            application_id=DomainId.from_str(ids["application"]),
            action_urn=_ACTION_URN,
            target_kind="identity_group_membership",
            target_id=DomainId.from_str(ids["group"]),
            authorized_at=datetime.now(UTC),
        )
        if commit:
            uow.commit()
        return created


def test_i01_new_membership_writes_exactly_one_audit_row(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed(db)
    created = _add_verified(postgres_spi, ids)
    assert created is True
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.identity_group_membership "
            "WHERE identity_id = %s AND group_id = %s",
            (ids["subject"], ids["group"]),
        ).fetchone()[0]
        == 1
    )
    audit = db.execute(
        "SELECT actor_identity_id, actor_principal_id, tenant_id, application_id, "
        "action_urn, target_kind, target_id, subject_identity_id, outcome, authorized_at "
        "FROM mtmf.security_mutation_audit"
    ).fetchall()
    assert len(audit) == 1
    row = audit[0]
    assert str(row[0]) == ids["actor"]
    assert str(row[1]) == ids["principal"]
    assert str(row[2]) == ids["tenant"]
    assert str(row[3]) == ids["application"]
    assert row[4] == _ACTION_URN.value
    assert row[5] == "identity_group_membership"
    assert str(row[6]) == ids["group"]
    assert str(row[7]) == ids["subject"]
    assert row[8] == "CREATED"
    assert row[9] is not None


def test_i02_duplicate_is_a_no_op_without_a_new_audit_row(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed(db)
    first = _add_verified(postgres_spi, ids)
    second = _add_verified(postgres_spi, ids)
    assert first is True
    assert second is False
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.identity_group_membership").fetchone()[0] == 1


def test_i04_caller_rollback_rolls_back_both_writes(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed(db)
    _add_verified(postgres_spi, ids, commit=False)
    assert db.execute("SELECT count(*) FROM mtmf.identity_group_membership").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 0


def test_i06_legacy_runtime_execute_is_denied(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    ids = _seed(db)
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(
            "SELECT mtmf.identity_group_membership_add(%s, %s)",
            (ids["subject"], ids["group"]),
        )
    runtime_connection.rollback()


def test_i07_runtime_direct_audit_dml_is_denied(runtime_connection: psycopg.Connection) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute("SELECT count(*) FROM mtmf.security_mutation_audit")
    runtime_connection.rollback()


def test_i08_verified_function_rejects_malformed_target(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed(db)
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_group_membership_repository(uow)
        repository.lock_verified_add(
            tenant_id=DomainId.from_str(ids["tenant"]),
            actor_identity_id=DomainId.from_str(ids["actor"]),
            subject_identity_id=DomainId.from_str(ids["subject"]),
            group_id=DomainId.from_str(ids["group"]),
        )
        with pytest.raises(PersistenceError):
            repository.add_verified(
                identity_id=DomainId.from_str(ids["subject"]),
                group_id=DomainId.from_str(ids["group"]),
                operation_id=uuid.uuid4(),
                actor_identity_id=DomainId.from_str(ids["actor"]),
                actor_principal_id=DomainId.from_str(ids["principal"]),
                tenant_id=DomainId.from_str(ids["tenant"]),
                application_id=DomainId.from_str(ids["application"]),
                action_urn=_ACTION_URN,
                target_kind="identity_group_membership",
                target_id=DomainId.from_str(ids["subject"]),  # wrong: not the Group
                authorized_at=datetime.now(UTC),
            )


def _add_verified_custom(
    postgres_spi: MtmfSpi,
    ids: dict[str, str],
    *,
    subject: str,
    group: str,
    operation_id: uuid.UUID,
    commit: bool = True,
) -> bool:
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_group_membership_repository(uow)
        repository.lock_verified_add(
            tenant_id=DomainId.from_str(ids["tenant"]),
            actor_identity_id=DomainId.from_str(ids["actor"]),
            subject_identity_id=DomainId.from_str(subject),
            group_id=DomainId.from_str(group),
        )
        created = repository.add_verified(
            identity_id=DomainId.from_str(subject),
            group_id=DomainId.from_str(group),
            operation_id=operation_id,
            actor_identity_id=DomainId.from_str(ids["actor"]),
            actor_principal_id=DomainId.from_str(ids["principal"]),
            tenant_id=DomainId.from_str(ids["tenant"]),
            application_id=DomainId.from_str(ids["application"]),
            action_urn=_ACTION_URN,
            target_kind="identity_group_membership",
            target_id=DomainId.from_str(group),
            authorized_at=datetime.now(UTC),
        )
        if commit:
            uow.commit()
        return created


def _add_member_target(
    db: psycopg.Connection, ids: dict[str, str], *, subject: str, group: str
) -> None:
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'Extra', 2, 2)",
        (subject, ids["principal"]),
    )
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
        (subject, ids["tenant"]),
    )
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s, %s, 'G', 2)",
        (group, ids["tenant"]),
    )
    db.execute("INSERT INTO mtmf.group_tenant_membership VALUES (%s, %s)", (group, ids["tenant"]))


def test_db_h03_non_steward_actor_is_rejected(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed(db)
    other_actor = _sid()
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'Other', 2, 2)",
        (other_actor, ids["principal"]),
    )
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
        (other_actor, ids["tenant"]),
    )
    db.execute(
        "INSERT INTO mtmf.identity_role_assignment (id, tenant_id, identity_id, role_urn) "
        "VALUES (%s, %s, %s, %s)",
        (_sid(), ids["tenant"], other_actor, _TENANT_ADMIN_URN),
    )
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_group_membership_repository(uow)
        with pytest.raises(PersistenceReferenceError):
            repository.lock_verified_add(
                tenant_id=DomainId.from_str(ids["tenant"]),
                actor_identity_id=DomainId.from_str(other_actor),
                subject_identity_id=DomainId.from_str(ids["subject"]),
                group_id=DomainId.from_str(ids["group"]),
            )
    assert db.execute("SELECT count(*) FROM mtmf.identity_group_membership").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 0


def test_db_h03_cross_tenant_and_inactive_targets_are_rejected(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed(db)
    # Cross-Tenant subject: an Identity whose only membership is another Tenant.
    cross_subject = _sid()
    other_tenant = _sid()
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'Cross', 2, 2)",
        (cross_subject, ids["principal"]),
    )
    db.execute(
        "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'O', 2, %s, 1, 2)",
        (other_tenant, ids["actor"]),
    )
    db.execute(
        "INSERT INTO mtmf.principal_tenant_membership VALUES (%s, %s)",
        (ids["principal"], other_tenant),
    )
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership VALUES (%s, %s)",
        (cross_subject, other_tenant),
    )
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_group_membership_repository(uow)
        with pytest.raises(PersistenceReferenceError):
            repository.lock_verified_add(
                tenant_id=DomainId.from_str(ids["tenant"]),
                actor_identity_id=DomainId.from_str(ids["actor"]),
                subject_identity_id=DomainId.from_str(cross_subject),
                group_id=DomainId.from_str(ids["group"]),
            )
    # Inactive Tenant.
    db.execute("UPDATE mtmf.tenant SET lifecycle = 2 WHERE id = %s", (ids["tenant"],))
    with postgres_spi.create_unit_of_work() as uow:
        repository = postgres_spi.create_identity_group_membership_repository(uow)
        with pytest.raises(PersistenceReferenceError):
            repository.lock_verified_add(
                tenant_id=DomainId.from_str(ids["tenant"]),
                actor_identity_id=DomainId.from_str(ids["actor"]),
                subject_identity_id=DomainId.from_str(ids["subject"]),
                group_id=DomainId.from_str(ids["group"]),
            )
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 0


def test_db_h04_audit_conflict_rolls_back_the_membership(
    db: psycopg.Connection, postgres_spi: MtmfSpi
) -> None:
    ids = _seed(db)
    second_subject, second_group = _sid(), _sid()
    _add_member_target(db, ids, subject=second_subject, group=second_group)
    operation_id = uuid.uuid4()
    assert (
        _add_verified_custom(
            postgres_spi,
            ids,
            subject=ids["subject"],
            group=ids["group"],
            operation_id=operation_id,
        )
        is True
    )
    with pytest.raises(PersistenceError):
        _add_verified_custom(
            postgres_spi,
            ids,
            subject=second_subject,
            group=second_group,
            operation_id=operation_id,
        )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.identity_group_membership "
            "WHERE identity_id = %s AND group_id = %s",
            (second_subject, second_group),
        ).fetchone()[0]
        == 0
    )
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 1


def test_cc_h04_concurrent_duplicate_adds_commit_one_row_and_one_audit(
    db: psycopg.Connection, runtime_config: PostgresConfig
) -> None:
    ids = _seed(db)
    barrier = threading.Barrier(2)
    results: dict[str, str] = {}

    def _worker(name: str) -> None:
        spi = PostgresMtmfSpi(runtime_config)
        try:
            barrier.wait(timeout=10)
            _add_verified_custom(
                spi,
                ids,
                subject=ids["subject"],
                group=ids["group"],
                operation_id=uuid.uuid4(),
            )
            results[name] = "ok"
        except Exception as exc:  # pragma: no cover - diagnostic
            results[name] = type(exc).__name__

    threads = [threading.Thread(target=_worker, args=(name,)) for name in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert results == {"a": "ok", "b": "ok"}, results
    assert db.execute("SELECT count(*) FROM mtmf.identity_group_membership").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.security_mutation_audit").fetchone()[0] == 1
