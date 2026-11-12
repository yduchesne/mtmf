"""PR 23 real-PostgreSQL acceptance for the initial-stewardship participants.

Every test runs against the explicitly configured MTMF database with the
established administrator/migrator/runtime topology. Positive participant
execution uses a genuine ``mtmf_migrator`` login that assumes the
non-login ``mtmf_owner`` role with an explicit ``SET ROLE`` inside one
caller-owned transaction. That is a TEST HARNESS only: it is not the future
PR 24P privileged production adapter.

The restricted ``mtmf_runtime`` login is used, without ``SET ROLE``, to prove
that neither participant nor any protected table write is reachable.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import psycopg
import pytest

from mtmf_core.persistence.errors import PersistenceError
from mtmf_core.persistence.postgres import (
    PostgresConfig,
    PostgresMigrationManager,
)
from mtmf_core.persistence.postgres.error_translation import translate_operation_error

_ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
_ISSUER_OTHER = "https://other-issuer.mtmf.test:28443/realms/mtmf-dev"
_SUBJECT = "pr23-subject-1"
_TENANT_ADMIN_URN = "urn:mtmf:iam:roles:system:tenant-administrator"
_OWNER = "mtmf_owner"
_MIGRATOR = "mtmf_migrator"
_RUNTIME = "mtmf_runtime"


def _uuid() -> str:
    return str(uuid.uuid4())


@contextmanager
def _owner(migrator_config: PostgresConfig) -> Iterator[psycopg.Connection]:
    """Open a real migrator login and assume mtmf_owner inside one transaction."""
    connection = psycopg.connect(migrator_config.psycopg_dsn)
    try:
        session_user, current_user = connection.execute(
            "SELECT session_user, current_user"
        ).fetchone()
        assert session_user == _MIGRATOR, session_user
        assert current_user == _MIGRATOR, current_user
        connection.execute(f"SET ROLE {_OWNER}")
        assert connection.execute("SELECT current_user").fetchone()[0] == _OWNER
        yield connection
    finally:
        connection.rollback()
        connection.close()


@contextmanager
def _savepoint(connection: psycopg.Connection) -> Iterator[None]:
    """Isolate one expected failing statement inside a caller-owned transaction."""
    connection.execute("SAVEPOINT pr23_case")
    try:
        yield
    finally:
        connection.execute("ROLLBACK TO SAVEPOINT pr23_case")


def _bootstrap_root(db: psycopg.Connection) -> dict[str, str]:
    root_tenant, root_principal, root_identity = _uuid(), _uuid(), _uuid()
    db.execute(
        "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Root', 'Root P', 'Root I')",
        (root_tenant, root_principal, root_identity),
    )
    return {
        "tenant": root_tenant,
        "principal": root_principal,
        "identity": root_identity,
    }


def _prepare(
    connection: psycopg.Connection,
    *,
    issuer: str = _ISSUER,
    subject: str = _SUBJECT,
    principal: str | None = None,
    identity: str | None = None,
    binding: str | None = None,
) -> tuple[dict[str, str], str, str, str]:
    principal = principal or _uuid()
    identity = identity or _uuid()
    binding = binding or _uuid()
    payload = connection.execute(
        "SELECT mtmf.onboarding_subject_prepare(%s, %s, %s, %s, %s)",
        (issuer, subject, principal, identity, binding),
    ).fetchone()[0]
    return payload, principal, identity, binding


def _attach(
    connection: psycopg.Connection,
    tenant: str,
    identity: str,
    *,
    issuer: str = _ISSUER,
    subject: str = _SUBJECT,
    assignment: str | None = None,
) -> dict[str, object]:
    return connection.execute(
        "SELECT mtmf.onboarding_initial_steward_attach(%s, %s, %s, %s, %s)",
        (tenant, issuer, subject, identity, assignment or _uuid()),
    ).fetchone()[0]


def _insert_provisioning_tenant(
    connection: psycopg.Connection,
    owner_identity: str,
    *,
    scope: int = 2,
    lifecycle: int = 0,
    deletion_status: int = 2,
) -> str:
    tenant = _uuid()
    connection.execute(
        "INSERT INTO mtmf.tenant "
        "(id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s, 'PR23 Tenant', %s, %s, %s, %s)",
        (tenant, scope, owner_identity, lifecycle, deletion_status),
    )
    return tenant


def _seed_existing_subject(
    db: psycopg.Connection,
    *,
    issuer: str = _ISSUER,
    subject: str = _SUBJECT,
    origin: int = 2,
    identity_deleted: int = 2,
    principal_deleted: int = 2,
    lifecycle: int = 1,
) -> dict[str, str]:
    principal, identity, binding = _uuid(), _uuid(), _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'P', %s)",
        (principal, principal_deleted),
    )
    db.execute(
        "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
        "VALUES (%s, %s, 'I', %s, %s)",
        (identity, principal, origin, identity_deleted),
    )
    db.execute(
        "INSERT INTO mtmf.external_subject_identity "
        "(id, issuer, subject, identity_id, lifecycle, created_at) "
        "VALUES (%s, %s, %s, %s, %s, now())",
        (binding, issuer, subject, identity, lifecycle),
    )
    return {"principal": principal, "identity": identity, "binding": binding}


def _seed_application(db: psycopg.Connection, owner_identity: str) -> str:
    application = _uuid()
    added = db.execute(
        "SELECT mtmf.application_add(%s, %s, 'Application', %s, 1::smallint, '{}'::jsonb)",
        (application, f"app-{application[:8]}", owner_identity),
    ).fetchone()[0]
    assert added is True
    return application


def _seed_application_registration(
    db: psycopg.Connection, application: str, tenant: str, identity: str
) -> None:
    added = db.execute(
        "SELECT mtmf.application_tenant_registration_add(%s, %s, %s, %s, 1::smallint, now())",
        (_uuid(), application, tenant, identity),
    ).fetchone()[0]
    assert added is True


def _raise_sqlstate(exc_info: pytest.ExceptionInfo[psycopg.Error]) -> str:
    state = exc_info.value.sqlstate
    assert state is not None
    return state


# --- P23-I01: populated 0014 -> 0015 upgrade, no loss ------------------------


def test_p23_i01_populated_upgrade_to_0015_preserves_data(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    from alembic import command
    from alembic.config import Config

    from mtmf_core.persistence.postgres.resources import migrations_script_directory

    db.execute("DROP SCHEMA IF EXISTS mtmf CASCADE")
    with psycopg.connect(migrator_config.psycopg_dsn, autocommit=True) as connection:
        connection.execute("SET ROLE mtmf_owner")
        connection.execute("CREATE SCHEMA mtmf")

    cfg = Config()
    cfg.set_main_option("script_location", str(migrations_script_directory()))
    cfg.attributes["mtmf_url"] = migrator_config.sqlalchemy_url
    cfg.attributes["mtmf_owner_role"] = _OWNER
    command.upgrade(cfg, "0014")

    root = _bootstrap_root(db)
    existing = _seed_existing_subject(db)
    application = _seed_application(db, existing["identity"])
    entitlement = _uuid()
    operator = _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s, 'OP', 2)", (operator,)
    )
    granted = db.execute(
        "SELECT mtmf.application_onboarding_entitlement_grant(%s, %s, %s, %s, %s, %s)",
        (entitlement, application, operator, "pr23 populated", 4, _uuid()),
    ).fetchone()[0]
    assert granted is True

    manager = PostgresMigrationManager(migrator_config)
    manager.upgrade_to_head()
    assert manager.current_revision() == "0015"

    # Original rows survive verbatim and the audit taxonomy was extended in place.
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.principal WHERE id = %s", (existing["principal"],)
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.external_subject_identity WHERE id = %s",
            (existing["binding"],),
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.application_onboarding_entitlement WHERE id = %s",
            (entitlement,),
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.root_registry WHERE root_tenant_id = %s",
            (root["tenant"],),
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE operation = 'BOOTSTRAP'"
        ).fetchone()[0]
        == 1
    )


# --- P23-I02: fresh head, no-op migration and unchanged manifest -------------


def test_p23_i02_noop_upgrade_and_runtime_manifest_unchanged(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    manager = PostgresMigrationManager(migrator_config)
    assert manager.current_revision() == "0015"
    assert manager.head_revision == "0015"
    manager.upgrade_to_head()
    assert manager.current_revision() == "0015"
    executable = db.execute(
        "SELECT count(*) FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' "
        "AND pg_catalog.has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE')"
    ).fetchone()[0]
    assert executable == 78


# --- P23-I03/I18: owner/invoker/PUBLIC posture and runtime denial ------------


def test_p23_i03_participants_are_owner_invoker_and_public_revoked(
    db: psycopg.Connection,
) -> None:
    rows = db.execute(
        "SELECT p.proname, pg_catalog.pg_get_userbyid(p.proowner), "
        "       p.prosecdef, p.proconfig, "
        "       pg_catalog.has_function_privilege('mtmf_runtime', p.oid, 'EXECUTE'), "
        "       EXISTS (SELECT 1 FROM pg_catalog.aclexplode( "
        "           coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a "
        "           WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE') "
        "FROM pg_catalog.pg_proc p "
        "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
        "WHERE n.nspname = 'mtmf' "
        "AND p.proname IN ('onboarding_subject_prepare', 'onboarding_initial_steward_attach') "
        "ORDER BY 1"
    ).fetchall()
    assert {row[0] for row in rows} == {
        "onboarding_initial_steward_attach",
        "onboarding_subject_prepare",
    }
    for row in rows:
        assert row[1:] == (_OWNER, False, ['search_path=""'], False, False)


def test_p23_i18_runtime_cannot_execute_or_write_protected_tables(
    db: psycopg.Connection, runtime_connection: psycopg.Connection
) -> None:
    _bootstrap_root(db)
    caller = (_ISSUER, _SUBJECT, _uuid(), _uuid(), _uuid())
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(
            "SELECT mtmf.onboarding_subject_prepare(%s, %s, %s, %s, %s)", caller
        )
    runtime_connection.rollback()
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        runtime_connection.execute(
            "SELECT mtmf.onboarding_initial_steward_attach(%s, %s, %s, %s, %s)",
            (_uuid(), _ISSUER, _SUBJECT, _uuid(), _uuid()),
        )
    runtime_connection.rollback()
    for statement in (
        "INSERT INTO mtmf.external_subject_identity "
        "(id, issuer, subject, identity_id, lifecycle, created_at) "
        "VALUES (%s, 'i', 's', %s, 1, now())",
        "SELECT count(*) FROM mtmf.stewardship_designation",
        "INSERT INTO mtmf.stewardship_audit "
        "(tenant_id, operation, new_principal_id, new_identity_id) "
        "VALUES (%s, 'TRANSFER', %s, %s)",
        "UPDATE mtmf.identity_role_assignment SET role_urn = role_urn",
    ):
        params = ()
        if statement.count("%s") == 1:
            params = (_uuid(),)
        elif statement.count("%s") == 2:
            params = (_uuid(), _uuid())
        elif statement.count("%s") == 3:
            params = (_uuid(), _uuid(), _uuid())
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            runtime_connection.execute(statement, params)
        runtime_connection.rollback()


# --- P23-I04..I08: global subject semantics ---------------------------------


def test_p23_i04_new_subject_creates_exact_global_objects_only(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    root = _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        payload, principal, identity, binding = _prepare(owner)
        assert payload == {"status": "CREATED", "identity_id": identity, "principal_id": principal}
        owner.commit()

    assert db.execute(
        "SELECT id, name, deletion_status FROM mtmf.principal WHERE id = %s", (principal,)
    ).fetchone() == (uuid.UUID(principal), "Onboarded Principal", 2)
    assert db.execute(
        "SELECT id, principal_id, name, origin, deletion_status FROM mtmf.identity WHERE id = %s",
        (identity,),
    ).fetchone() == (uuid.UUID(identity), uuid.UUID(principal), "Onboarded Identity", 2, 2)
    assert db.execute(
        "SELECT id, issuer, subject, identity_id, lifecycle "
        "FROM mtmf.external_subject_identity WHERE id = %s",
        (binding,),
    ).fetchone() == (uuid.UUID(binding), _ISSUER, _SUBJECT, uuid.UUID(identity), 1)
    # No Tenant/membership/Role/registration/subscription/audit side effects.
    assert db.execute("SELECT count(*) FROM mtmf.tenant").fetchone()[0] == 1  # root only
    assert (
        db.execute("SELECT count(*) FROM mtmf.tenant WHERE id <> %s", (root["tenant"],)).fetchone()[
            0
        ]
        == 0
    )
    assert db.execute("SELECT count(*) FROM mtmf.principal_tenant_membership").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.identity_tenant_membership").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.identity_role_assignment").fetchone()[0] == 0
    assert db.execute("SELECT count(*) FROM mtmf.stewardship_designation").fetchone()[0] == 0
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE tenant_id <> %s", (root["tenant"],)
        ).fetchone()[0]
        == 0
    )


def test_p23_i05_repeat_subject_returns_existing_without_writes(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        first, principal, identity, _ = _prepare(owner)
        owner.commit()
    with _owner(migrator_config) as owner:
        second, other_principal, other_identity, _ = _prepare(owner)
        owner.commit()
    assert first["status"] == "CREATED"
    assert second == {"status": "EXISTING", "identity_id": identity, "principal_id": principal}
    assert db.execute("SELECT count(*) FROM mtmf.principal").fetchone()[0] == 2  # root + new
    assert db.execute("SELECT count(*) FROM mtmf.identity").fetchone()[0] == 2
    assert db.execute("SELECT count(*) FROM mtmf.external_subject_identity").fetchone()[0] == 1
    assert (
        db.execute("SELECT id FROM mtmf.principal WHERE id = %s", (other_principal,)).fetchone()
        is None
    )
    assert (
        db.execute("SELECT id FROM mtmf.identity WHERE id = %s", (other_identity,)).fetchone()
        is None
    )


def test_p23_i06_revoked_history_inactive_subject_and_malformed_input_fail_closed(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    _seed_existing_subject(db, lifecycle=2)
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _prepare(owner)
        assert _raise_sqlstate(exc) == "MT048"

    _seed_existing_subject(db, subject="deleted-identity", identity_deleted=1)
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _prepare(owner, subject="deleted-identity")
        assert _raise_sqlstate(exc) == "MT048"

    _seed_existing_subject(db, subject="local-identity", origin=1)
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _prepare(owner, subject="local-identity")
        assert _raise_sqlstate(exc) == "MT048"

    _seed_existing_subject(db, subject="deleted-principal", principal_deleted=1)
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _prepare(owner, subject="deleted-principal")
        assert _raise_sqlstate(exc) == "MT048"

    for issuer, subject in (("", _SUBJECT), ("   ", _SUBJECT), (_ISSUER, ""), (_ISSUER, "  ")):
        with _owner(migrator_config) as owner:
            with pytest.raises(psycopg.errors.DatabaseError) as exc:
                _prepare(owner, issuer=issuer, subject=subject)
            assert _raise_sqlstate(exc) == "MT047"
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _prepare(owner, issuer="i" * 513)
        assert _raise_sqlstate(exc) == "MT047"
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            owner.execute(
                "SELECT mtmf.onboarding_subject_prepare(%s, %s, NULL, %s, %s)",
                (_ISSUER, _SUBJECT, _uuid(), _uuid()),
            )
        assert _raise_sqlstate(exc) == "MT047"


def test_p23_i07_different_issuers_and_names_never_merge(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        first, principal_a, identity_a, _ = _prepare(owner, issuer=_ISSUER, subject="shared-sub")
        second, principal_b, identity_b, _ = _prepare(
            owner, issuer=_ISSUER_OTHER, subject="shared-sub"
        )
        owner.commit()
    assert first["status"] == "CREATED" and second["status"] == "CREATED"
    assert identity_a != identity_b and principal_a != principal_b
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.identity WHERE id IN (%s, %s)", (identity_a, identity_b)
        ).fetchone()[0]
        == 2
    )
    # Names are fixed non-PII placeholders; equal display text never correlates.
    names = db.execute(
        "SELECT DISTINCT name FROM mtmf.identity WHERE id IN (%s, %s)", (identity_a, identity_b)
    ).fetchall()
    assert names == [("Onboarded Identity",)]


def test_p23_i08_concurrent_same_key_creates_exactly_one_subject(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    barrier = threading.Barrier(2)
    results: list[dict[str, str]] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            with _owner(migrator_config) as owner:
                owner.execute("SET statement_timeout = '10s'")
                owner.execute("SET lock_timeout = '10s'")
                barrier.wait(timeout=10)
                payload, _, _, _ = _prepare(owner)
                owner.commit()
                results.append(payload)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors, errors
    assert sorted(result["status"] for result in results) == ["CREATED", "EXISTING"]
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.external_subject_identity WHERE lifecycle = 1"
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.identity WHERE name = 'Onboarded Identity'"
        ).fetchone()[0]
        == 1
    )


# --- P23-I09..I16: first-steward graph, rollback, root/tenant guards ---------


def test_p23_i09_single_owner_transaction_installs_exact_first_steward_graph(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    root = _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        prepared, principal, identity, _ = _prepare(owner)
        assert prepared["status"] == "CREATED"
        tenant = _insert_provisioning_tenant(owner, identity)
        result = _attach(owner, tenant, identity)
        assert result == {
            "tenant_id": tenant,
            "principal_id": principal,
            "identity_id": identity,
            "assignment_id": result["assignment_id"],
            "stewardship_version": 1,
        }
        assert owner.execute(
            "SELECT scope, lifecycle, deletion_status FROM mtmf.tenant WHERE id = %s", (tenant,)
        ).fetchone() == (2, 0, 2)
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.principal_tenant_membership WHERE tenant_id = %s",
                (tenant,),
            ).fetchone()[0]
            == 1
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.identity_tenant_membership WHERE tenant_id = %s",
                (tenant,),
            ).fetchone()[0]
            == 1
        )
        assert owner.execute(
            "SELECT role_urn, organization_id FROM mtmf.identity_role_assignment "
            "WHERE tenant_id = %s",
            (tenant,),
        ).fetchall() == [(_TENANT_ADMIN_URN, None)]
        assert owner.execute(
            "SELECT steward_principal_id, designated_identity_id, version "
            "FROM mtmf.stewardship_designation WHERE tenant_id = %s",
            (tenant,),
        ).fetchone() == (uuid.UUID(principal), uuid.UUID(identity), 1)
        assert owner.execute(
            "SELECT operation, previous_principal_id, new_principal_id, "
            "       previous_identity_id, new_identity_id, actor_provenance, reason "
            "FROM mtmf.stewardship_audit WHERE tenant_id = %s",
            (tenant,),
        ).fetchall() == [
            (
                "INITIAL_ONBOARDING",
                None,
                uuid.UUID(principal),
                None,
                uuid.UUID(identity),
                None,
                "initial pre-Tenant stewardship; request audit pending PR22B",
            )
        ]
        # Still PROVISIONING and never ACTIVE in the participant itself.
        owner.rollback()

    # Rollback removed the whole graph, including the PROVISIONING Tenant.
    assert (
        db.execute("SELECT count(*) FROM mtmf.tenant WHERE id = %s", (tenant,)).fetchone()[0] == 0
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]
        == 0
    )
    assert (
        db.execute("SELECT count(*) FROM mtmf.principal WHERE id = %s", (principal,)).fetchone()[0]
        == 0
    )
    assert (
        db.execute("SELECT count(*) FROM mtmf.identity WHERE id = %s", (identity,)).fetchone()[0]
        == 0
    )
    assert db.execute("SELECT root_tenant_id FROM mtmf.root_registry").fetchone()[0] == uuid.UUID(
        root["tenant"]
    )


def test_p23_i10_rollback_after_each_step_leaves_no_partial_state(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        payload, principal, identity, _ = _prepare(owner)
        assert payload["status"] == "CREATED"
        owner.rollback()
    assert (
        db.execute("SELECT count(*) FROM mtmf.principal WHERE id = %s", (principal,)).fetchone()[0]
        == 0
    )
    assert (
        db.execute("SELECT count(*) FROM mtmf.identity WHERE id = %s", (identity,)).fetchone()[0]
        == 0
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.external_subject_identity WHERE identity_id = %s",
            (identity,),
        ).fetchone()[0]
        == 0
    )

    with _owner(migrator_config) as owner:
        _, _, identity, _ = _prepare(owner)
        assert payload["status"] == "CREATED"
        tenant = _insert_provisioning_tenant(owner, identity)
        owner.rollback()
    assert (
        db.execute("SELECT count(*) FROM mtmf.tenant WHERE id = %s", (tenant,)).fetchone()[0] == 0
    )
    assert (
        db.execute("SELECT count(*) FROM mtmf.principal WHERE id = %s", (principal,)).fetchone()[0]
        == 0
    )

    with _owner(migrator_config) as owner:
        _, _, identity, _ = _prepare(owner)
        tenant = _insert_provisioning_tenant(owner, identity)
        _attach(owner, tenant, identity)
        owner.rollback()
    for statement, value in (
        ("SELECT count(*) FROM mtmf.principal WHERE id = %s", principal),
        ("SELECT count(*) FROM mtmf.identity WHERE id = %s", identity),
        (
            "SELECT count(*) FROM mtmf.external_subject_identity WHERE identity_id = %s",
            identity,
        ),
        ("SELECT count(*) FROM mtmf.tenant WHERE id = %s", tenant),
        (
            "SELECT count(*) FROM mtmf.principal_tenant_membership WHERE tenant_id = %s",
            tenant,
        ),
        (
            "SELECT count(*) FROM mtmf.identity_tenant_membership WHERE tenant_id = %s",
            tenant,
        ),
        (
            "SELECT count(*) FROM mtmf.identity_role_assignment WHERE tenant_id = %s",
            tenant,
        ),
        ("SELECT count(*) FROM mtmf.stewardship_designation WHERE tenant_id = %s", tenant),
        ("SELECT count(*) FROM mtmf.stewardship_audit WHERE tenant_id = %s", tenant),
    ):
        assert db.execute(statement, (value,)).fetchone()[0] == 0, statement


def test_p23_i11_root_objects_are_never_reachable(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    root = _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        for args in (
            (_ISSUER, _SUBJECT, root["principal"], _uuid(), _uuid()),
            (_ISSUER, _SUBJECT, _uuid(), root["identity"], _uuid()),
        ):
            with _savepoint(owner):
                with pytest.raises(psycopg.errors.DatabaseError) as exc:
                    owner.execute(
                        "SELECT mtmf.onboarding_subject_prepare(%s, %s, %s, %s, %s)", args
                    )
                assert _raise_sqlstate(exc) == "MT047"

        _, _, identity, _ = _prepare(owner)
        with _savepoint(owner):
            with pytest.raises(psycopg.errors.DatabaseError) as exc:
                _attach(owner, root["tenant"], identity)
            assert _raise_sqlstate(exc) == "MT047"
        owner.rollback()

    assert db.execute("SELECT count(*) FROM mtmf.root_registry").fetchone()[0] == 1
    assert db.execute(
        "SELECT root_tenant_id, root_principal_id, root_identity_id FROM mtmf.root_registry"
    ).fetchone() == (
        uuid.UUID(root["tenant"]),
        uuid.UUID(root["principal"]),
        uuid.UUID(root["identity"]),
    )


def test_p23_i12_wrong_tenant_lifecycle_or_owner_denied(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    root = _bootstrap_root(db)
    root_identity = root["identity"]
    with _owner(migrator_config) as owner:
        _, _, identity, _ = _prepare(owner)
        active = _insert_provisioning_tenant(owner, identity, lifecycle=1)
        deleted = _insert_provisioning_tenant(owner, identity, deletion_status=1)
        wrong_owner = _insert_provisioning_tenant(owner, root_identity)
        for tenant in (active, deleted, wrong_owner):
            with _savepoint(owner):
                with pytest.raises(psycopg.errors.DatabaseError) as exc:
                    _attach(owner, tenant, identity)
                assert _raise_sqlstate(exc) == "MT047"
        owner.rollback()


def test_p23_i13_binding_and_subject_integrity_denied(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        _, _, identity, _ = _prepare(owner)
        missing_binding = _insert_provisioning_tenant(owner, identity)
        with _savepoint(owner):
            with pytest.raises(psycopg.errors.DatabaseError) as exc:
                _attach(owner, missing_binding, identity, subject="not-bound")
            assert _raise_sqlstate(exc) == "MT047"

        _seed_existing_subject(db, subject="other-active")
        wrong_identity = _insert_provisioning_tenant(owner, identity)
        with _savepoint(owner):
            with pytest.raises(psycopg.errors.DatabaseError) as exc:
                _attach(owner, wrong_identity, identity, subject="other-active")
            assert _raise_sqlstate(exc) == "MT047"
        owner.rollback()

    with _owner(migrator_config) as owner:
        local = _seed_existing_subject(db, subject="local-only", origin=1)
        tenant = _insert_provisioning_tenant(owner, local["identity"])
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _attach(owner, tenant, local["identity"], subject="local-only")
        assert _raise_sqlstate(exc) == "MT047"
        owner.rollback()

    with _owner(migrator_config) as owner:
        deleted = _seed_existing_subject(db, subject="deleted-principal-2", principal_deleted=1)
        tenant = _insert_provisioning_tenant(owner, deleted["identity"])
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _attach(owner, tenant, deleted["identity"], subject="deleted-principal-2")
        assert _raise_sqlstate(exc) == "MT047"
        owner.rollback()


def test_p23_i14_dirty_new_tenant_and_duplicate_assignment_denied(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    application_owner = _seed_existing_subject(db, subject="app-owner")
    application = _seed_application(db, application_owner["identity"])

    with _owner(migrator_config) as owner:
        _, principal, identity, _ = _prepare(owner, subject="dirty")
        tenant = _insert_provisioning_tenant(owner, identity)
        owner.commit()
    with _owner(migrator_config) as owner:
        # Pre-existing membership in the supposedly fresh Tenant.
        inserted = owner.execute(
            "SELECT mtmf.principal_tenant_membership_add(%s, %s)", (principal, tenant)
        ).fetchone()[0]
        assert inserted is True
        owner.commit()
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _attach(owner, tenant, identity, subject="dirty")
        assert _raise_sqlstate(exc) == "MT048"
        owner.rollback()

    # Existing registration/subscription in a second fresh Tenant.
    with _owner(migrator_config) as owner:
        _, _, identity2, _ = _prepare(owner, subject="registered")
        tenant2 = _insert_provisioning_tenant(owner, identity2)
        owner.commit()
    _seed_application_registration(db, application, tenant2, identity2)
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _attach(owner, tenant2, identity2, subject="registered")
        assert _raise_sqlstate(exc) == "MT048"
        owner.rollback()

    # Successful attach once, then a duplicate re-attach is never idempotent.
    with _owner(migrator_config) as owner:
        _, _, identity3, _ = _prepare(owner, subject="attached")
        tenant3 = _insert_provisioning_tenant(owner, identity3)
        _attach(owner, tenant3, identity3, subject="attached")
        owner.commit()
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _attach(owner, tenant3, identity3, subject="attached")
        assert _raise_sqlstate(exc) == "MT048"
        owner.rollback()

    # Duplicate assignment UUID used by an unrelated Tenant's existing grant.
    with _owner(migrator_config) as owner:
        _, principal4, identity4, _ = _prepare(owner, subject="dup-assignment")
        tenant4 = _insert_provisioning_tenant(owner, identity4)
        other_tenant = _insert_provisioning_tenant(owner, identity4)
        # Build a second eligible graph only to own the colliding assignment id.
        owner.execute(
            "INSERT INTO mtmf.principal_tenant_membership "
            "(principal_id, tenant_id) VALUES (%s, %s)",
            (principal4, other_tenant),
        )
        owner.execute(
            "INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id) VALUES (%s, %s)",
            (identity4, other_tenant),
        )
        duplicate_assignment = _uuid()
        owner.execute(
            "INSERT INTO mtmf.identity_role_assignment "
            "(id, tenant_id, identity_id, role_urn, organization_id) "
            "VALUES (%s, %s, %s, %s, NULL)",
            (duplicate_assignment, other_tenant, identity4, _TENANT_ADMIN_URN),
        )
        owner.commit()
    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _attach(
                owner,
                tenant4,
                identity4,
                subject="dup-assignment",
                assignment=duplicate_assignment,
            )
        assert _raise_sqlstate(exc) == "MT048"
        owner.rollback()


def test_p23_i15_missing_tenant_administrator_seed_fails_closed(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        _, _, identity, _ = _prepare(owner)
        tenant = _insert_provisioning_tenant(owner, identity)
        owner.execute("DELETE FROM mtmf.builtin_role WHERE role_urn = %s", (_TENANT_ADMIN_URN,))
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _attach(owner, tenant, identity)
        assert _raise_sqlstate(exc) == "MT047"
        owner.rollback()


def test_p23_i16_concurrent_attachment_allows_one_designation(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        _, _, identity, _ = _prepare(owner, subject="concurrent-attach")
        tenant = _insert_provisioning_tenant(owner, identity)
        owner.commit()

    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            with _owner(migrator_config) as owner:
                owner.execute("SET statement_timeout = '10s'")
                owner.execute("SET lock_timeout = '10s'")
                barrier.wait(timeout=10)
                try:
                    _attach(owner, tenant, identity, subject="concurrent-attach")
                    owner.commit()
                    outcomes.append("OK")
                except psycopg.Error as exc:
                    owner.rollback()
                    outcomes.append(exc.sqlstate or "ERROR")
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors, errors
    assert outcomes.count("OK") == 1
    assert outcomes.count("MT048") == 1
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_designation WHERE tenant_id = %s", (tenant,)
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit "
            "WHERE tenant_id = %s AND operation = 'INITIAL_ONBOARDING'",
            (tenant,),
        ).fetchone()[0]
        == 1
    )
    assert (
        db.execute("SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant,)).fetchone()[0] == 0
    )


# --- P23-I17: audit taxonomy and append-only guards -------------------------


def test_p23_i17_audit_operations_and_append_only_guards(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    root = _bootstrap_root(db)
    with _owner(migrator_config) as owner:
        for operation in (
            "BOOTSTRAP",
            "TRANSFER",
            "RECOVERY",
            "ROOT_IDENTITY_RECOVERY",
            "INITIAL_ONBOARDING",
        ):
            owner.execute(
                "INSERT INTO mtmf.stewardship_audit "
                "(tenant_id, operation, new_principal_id, new_identity_id) "
                "VALUES (%s, %s, %s, %s)",
                (root["tenant"], operation, _uuid(), _uuid()),
            )
        owner.commit()

    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE operation IN "
            "('BOOTSTRAP','TRANSFER','RECOVERY','ROOT_IDENTITY_RECOVERY','INITIAL_ONBOARDING')"
        ).fetchone()[0]
        == 6
    )
    with pytest.raises(psycopg.errors.CheckViolation):
        db.execute(
            "INSERT INTO mtmf.stewardship_audit "
            "(tenant_id, operation, new_principal_id, new_identity_id) "
            "VALUES (%s, 'ARBITRARY', %s, %s)",
            (root["tenant"], _uuid(), _uuid()),
        )
    with pytest.raises(psycopg.errors.DatabaseError) as update_exc:
        db.execute("UPDATE mtmf.stewardship_audit SET reason = 'x'")
    assert _raise_sqlstate(update_exc) == "MT033"
    with pytest.raises(psycopg.errors.DatabaseError) as delete_exc:
        db.execute("DELETE FROM mtmf.stewardship_audit")
    assert _raise_sqlstate(delete_exc) == "MT033"


# --- P23-I19/I20: cross-Tenant non-inheritance and legacy guards ------------


def test_p23_i19_existing_membership_in_another_tenant_is_not_inherited(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    existing = _seed_existing_subject(db, subject="tenant-a-member")
    tenant_a = _insert_provisioning_tenant(db, existing["identity"])
    db.execute(
        "INSERT INTO mtmf.principal_tenant_membership (principal_id, tenant_id) VALUES (%s, %s)",
        (existing["principal"], tenant_a),
    )
    db.execute(
        "INSERT INTO mtmf.identity_tenant_membership (identity_id, tenant_id) VALUES (%s, %s)",
        (existing["identity"], tenant_a),
    )
    before = db.execute(
        "SELECT count(*) FROM mtmf.identity_tenant_membership WHERE identity_id = %s",
        (existing["identity"],),
    ).fetchone()[0]
    with _owner(migrator_config) as owner:
        payload, _, _, _ = _prepare(owner, subject="tenant-a-member")
        owner.commit()
    assert payload == {
        "status": "EXISTING",
        "identity_id": existing["identity"],
        "principal_id": existing["principal"],
    }
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.identity_tenant_membership WHERE identity_id = %s",
            (existing["identity"],),
        ).fetchone()[0]
        == before
        == 1
    )


def test_p23_i20_legacy_final_steward_deletion_guards_still_deny(
    db: psycopg.Connection, postgres_spi
) -> None:
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
        Tenant,
        TenantLifecycle,
    )

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
            IdentityRoleAssignment(
                DomainId.generate(),
                tenant.id,
                identity.id,
                RoleUrn(_TENANT_ADMIN_URN),
            )
        )
        uow.commit()
    db.execute(
        "SELECT mtmf.designate_steward(%s, %s, %s, NULL, 'RECOVERY', 'initial', 'legacy-fixture')",
        (tenant.id.value, principal.id.value, identity.id.value),
    )
    db.execute("SELECT mtmf.activate_tenant(%s)", (tenant.id.value,))
    assert (
        db.execute(
            "SELECT lifecycle FROM mtmf.tenant WHERE id = %s", (tenant.id.value,)
        ).fetchone()[0]
        == 1
    )

    with pytest.raises(psycopg.errors.DatabaseError) as membership_exc:
        db.execute(
            "SELECT mtmf.remove_identity_tenant_membership(%s, %s, %s)",
            (identity.id.value, tenant.id.value, None),
        )
    assert _raise_sqlstate(membership_exc) == "MT032"
    with pytest.raises(psycopg.errors.DatabaseError) as role_exc:
        db.execute(
            "DELETE FROM mtmf.identity_role_assignment WHERE tenant_id = %s", (tenant.id.value,)
        )
    assert _raise_sqlstate(role_exc) == "MT032"


# --- P23-I21/I22: adverse privilege drift and failure classification -------


def test_p23_i21_privilege_drift_fails_the_noop_postflight(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    from mtmf_core.persistence.postgres.migration import MigrationError

    db.execute("REVOKE EXECUTE ON FUNCTION mtmf.tenant_get(uuid) FROM mtmf_runtime")
    with pytest.raises(MigrationError):
        PostgresMigrationManager(migrator_config).upgrade_to_head()


def test_p23_i22_structural_sqlstates_stay_fail_closed() -> None:
    class StructuralError(Exception):
        def __init__(self, state: str) -> None:
            super().__init__(state)
            self.sqlstate = state

    for state in ("MT047", "MT048"):
        translated = translate_operation_error(StructuralError(state))  # type: ignore[arg-type]
        assert isinstance(translated, PersistenceError)
        assert translated.__class__.__name__ in {
            "PersistenceTransactionError",
            "PersistenceIntegrityError",
        }


# --- PR 23 independent-review fixup: F1/F2 acceptance ----------------------

_SYSTEM_TENANT_MANAGEMENT_URN = "urn:mtmf:iam:roles:system:tenant-management"


def _tenant_defined_role_urn(tenant: str) -> str:
    return f"urn:mtmf:iam:roles:tenant:{tenant}:pr23-fixup-dirty"


def _seed_dirty_tenant_state(
    owner: psycopg.Connection,
    kind: str,
    tenant: str,
    identity: str,
) -> tuple[str, tuple[object, ...]]:
    """Seed one prohibited current-state category; return its intact-state query."""
    if kind == "organization":
        organization = _uuid()
        owner.execute(
            "INSERT INTO mtmf.organization "
            "(id, tenant_id, name, owner_identity_id, deletion_status) "
            "VALUES (%s, %s, 'Dirty Org', %s, 2)",
            (organization, tenant, identity),
        )
        return "SELECT count(*) FROM mtmf.organization WHERE tenant_id = %s", (tenant,)
    if kind == "group":
        group = _uuid()
        owner.execute(
            "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) "
            "VALUES (%s, %s, 'Dirty Group', 2)",
            (group, tenant),
        )
        return "SELECT count(*) FROM mtmf.group WHERE tenant_id = %s", (tenant,)
    if kind == "group_tenant_membership":
        group = _uuid()
        owner.execute(
            "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) "
            "VALUES (%s, %s, 'Dirty Group', 2)",
            (group, tenant),
        )
        owner.execute(
            "INSERT INTO mtmf.group_tenant_membership (group_id, tenant_id) VALUES (%s, %s)",
            (group, tenant),
        )
        return "SELECT count(*) FROM mtmf.group_tenant_membership WHERE tenant_id = %s", (tenant,)
    if kind == "group_role_assignment":
        group = _uuid()
        owner.execute(
            "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) "
            "VALUES (%s, %s, 'Dirty Group', 2)",
            (group, tenant),
        )
        owner.execute(
            "INSERT INTO mtmf.group_tenant_membership (group_id, tenant_id) VALUES (%s, %s)",
            (group, tenant),
        )
        owner.execute(
            "INSERT INTO mtmf.group_role_assignment "
            "(id, tenant_id, group_id, role_urn, organization_id) "
            "VALUES (%s, %s, %s, %s, NULL)",
            (_uuid(), tenant, group, _TENANT_ADMIN_URN),
        )
        return "SELECT count(*) FROM mtmf.group_role_assignment WHERE tenant_id = %s", (tenant,)
    if kind == "tenant_defined_role":
        owner.execute(
            "INSERT INTO mtmf.role (urn, name, defining_tenant_id) "
            "VALUES (%s, 'Dirty Tenant Role', %s)",
            (_tenant_defined_role_urn(tenant), tenant),
        )
        return "SELECT count(*) FROM mtmf.role WHERE defining_tenant_id = %s", (tenant,)
    if kind == "tenant_as_manager":
        owner.execute(
            "INSERT INTO mtmf.tenant_management_group "
            "(id, manager_tenant_id, management_role_urn, scope) "
            "VALUES (%s, %s, %s, 1)",
            (_uuid(), tenant, _SYSTEM_TENANT_MANAGEMENT_URN),
        )
        return (
            "SELECT count(*) FROM mtmf.tenant_management_group WHERE manager_tenant_id = %s",
            (tenant,),
        )
    if kind == "tenant_as_managed_target":
        manager_tenant = _insert_provisioning_tenant(owner, identity)
        management_group = _uuid()
        owner.execute(
            "INSERT INTO mtmf.tenant_management_group "
            "(id, manager_tenant_id, management_role_urn, scope) "
            "VALUES (%s, %s, %s, 1)",
            (management_group, manager_tenant, _SYSTEM_TENANT_MANAGEMENT_URN),
        )
        owner.execute(
            "INSERT INTO mtmf.tenant_management_group_membership "
            "(id, management_group_id, tenant_id) "
            "VALUES (%s, %s, %s)",
            (_uuid(), management_group, tenant),
        )
        return (
            "SELECT count(*) FROM mtmf.tenant_management_group_membership WHERE tenant_id = %s",
            (tenant,),
        )
    raise AssertionError(f"unknown F1 category {kind!r}")


@pytest.mark.parametrize(
    "kind",
    (
        "organization",
        "group",
        "group_tenant_membership",
        "group_role_assignment",
        "tenant_defined_role",
        "tenant_as_manager",
        "tenant_as_managed_target",
    ),
)
def test_p23_fixup_f1_fresh_tenant_graph_rejected(
    db: psycopg.Connection, migrator_config: PostgresConfig, kind: str
) -> None:
    _bootstrap_root(db)
    subject = f"f1-{kind}"
    with _owner(migrator_config) as owner:
        _, _, identity, _ = _prepare(owner, subject=subject)
        tenant = _insert_provisioning_tenant(owner, identity)
        intact_statement, intact_params = _seed_dirty_tenant_state(owner, kind, tenant, identity)
        assert owner.execute(intact_statement, intact_params).fetchone()[0] >= 1

        with _savepoint(owner):
            with pytest.raises(psycopg.errors.DatabaseError) as exc:
                _attach(owner, tenant, identity, subject=subject)
            assert _raise_sqlstate(exc) == "MT048"

        # The seeded dirty state survives, but no B2 write was staged.
        assert owner.execute(intact_statement, intact_params).fetchone()[0] >= 1
        assert owner.execute(
            "SELECT scope, lifecycle FROM mtmf.tenant WHERE id = %s", (tenant,)
        ).fetchone() == (2, 0)
        for statement in (
            "SELECT count(*) FROM mtmf.principal_tenant_membership WHERE tenant_id = %s",
            "SELECT count(*) FROM mtmf.identity_tenant_membership WHERE tenant_id = %s",
            "SELECT count(*) FROM mtmf.identity_role_assignment WHERE tenant_id = %s",
            "SELECT count(*) FROM mtmf.stewardship_designation WHERE tenant_id = %s",
            "SELECT count(*) FROM mtmf.stewardship_audit "
            "WHERE tenant_id = %s AND operation = 'INITIAL_ONBOARDING'",
        ):
            assert owner.execute(statement, (tenant,)).fetchone()[0] == 0, statement
        owner.rollback()

    assert (
        db.execute("SELECT count(*) FROM mtmf.tenant WHERE id = %s", (tenant,)).fetchone()[0] == 0
    )
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.external_subject_identity "
            "WHERE issuer = %s AND subject = %s",
            (_ISSUER, subject),
        ).fetchone()[0]
        == 0
    )


def test_p23_fixup_f1_cross_tenant_state_is_not_inherited(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    subject = "f1-cross-tenant-positive"
    with _owner(migrator_config) as owner:
        _, _, identity, _ = _prepare(owner, subject=subject)
        tenant_a = _insert_provisioning_tenant(owner, identity)
        organization = _uuid()
        owner.execute(
            "INSERT INTO mtmf.organization "
            "(id, tenant_id, name, owner_identity_id, deletion_status) "
            "VALUES (%s, %s, 'Tenant A Org', %s, 2)",
            (organization, tenant_a, identity),
        )
        group = _uuid()
        owner.execute(
            "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) "
            "VALUES (%s, %s, 'Tenant A Group', 2)",
            (group, tenant_a),
        )
        owner.execute(
            "INSERT INTO mtmf.group_tenant_membership (group_id, tenant_id) VALUES (%s, %s)",
            (group, tenant_a),
        )
        owner.execute(
            "INSERT INTO mtmf.role (urn, name, defining_tenant_id) "
            "VALUES (%s, 'Tenant A Role', %s)",
            (_tenant_defined_role_urn(tenant_a), tenant_a),
        )

        tenant_b = _insert_provisioning_tenant(owner, identity)
        result = _attach(owner, tenant_b, identity, subject=subject)
        assert result["tenant_id"] == tenant_b

        # Tenant B received the exact normal first-steward graph.
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.principal_tenant_membership WHERE tenant_id = %s",
                (tenant_b,),
            ).fetchone()[0]
            == 1
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.identity_tenant_membership WHERE tenant_id = %s",
                (tenant_b,),
            ).fetchone()[0]
            == 1
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.identity_role_assignment WHERE tenant_id = %s",
                (tenant_b,),
            ).fetchone()[0]
            == 1
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.stewardship_designation WHERE tenant_id = %s",
                (tenant_b,),
            ).fetchone()[0]
            == 1
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.stewardship_audit "
                "WHERE tenant_id = %s AND operation = 'INITIAL_ONBOARDING'",
                (tenant_b,),
            ).fetchone()[0]
            == 1
        )

        # Tenant A's unrelated current state is untouched and was not inherited.
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.organization WHERE tenant_id = %s", (tenant_a,)
            ).fetchone()[0]
            == 1
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.group WHERE tenant_id = %s", (tenant_a,)
            ).fetchone()[0]
            == 1
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.role WHERE defining_tenant_id = %s", (tenant_a,)
            ).fetchone()[0]
            == 1
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.stewardship_designation WHERE tenant_id = %s",
                (tenant_a,),
            ).fetchone()[0]
            == 0
        )
        owner.rollback()


_F2_CASES = [
    (slot, root_key)
    for slot in ("principal", "identity", "binding")
    for root_key in ("tenant", "principal", "identity")
]


@pytest.mark.parametrize(("slot", "root_key"), _F2_CASES)
def test_p23_fixup_f2_canonical_root_uuid_cross_type_rejected(
    db: psycopg.Connection,
    migrator_config: PostgresConfig,
    slot: str,
    root_key: str,
) -> None:
    root = _bootstrap_root(db)
    subject = f"f2-{slot}-{root_key}"
    root_values = set(root.values())
    while True:
        principal, identity, binding = _uuid(), _uuid(), _uuid()
        if len({principal, identity, binding}) == 3 and not (
            {principal, identity, binding} & root_values
        ):
            break
    targets = {"principal": principal, "identity": identity, "binding": binding}
    targets[slot] = root[root_key]

    with _owner(migrator_config) as owner:
        with pytest.raises(psycopg.errors.DatabaseError) as exc:
            _prepare(
                owner,
                subject=subject,
                principal=targets["principal"],
                identity=targets["identity"],
                binding=targets["binding"],
            )
        assert _raise_sqlstate(exc) == "MT047"
        owner.rollback()

    # No B1 mutation, no subject row, canonical root unchanged.
    assert db.execute("SELECT count(*) FROM mtmf.principal").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.identity").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.tenant").fetchone()[0] == 1
    assert db.execute("SELECT count(*) FROM mtmf.external_subject_identity").fetchone()[0] == 0
    assert (
        db.execute(
            "SELECT count(*) FROM mtmf.stewardship_audit WHERE operation = 'BOOTSTRAP'"
        ).fetchone()[0]
        == 1
    )
    assert db.execute(
        "SELECT root_tenant_id, root_principal_id, root_identity_id FROM mtmf.root_registry"
    ).fetchone() == (
        uuid.UUID(root["tenant"]),
        uuid.UUID(root["principal"]),
        uuid.UUID(root["identity"]),
    )


def test_p23_fixup_f2_ordinary_non_root_uuids_create_and_reuse(
    db: psycopg.Connection, migrator_config: PostgresConfig
) -> None:
    _bootstrap_root(db)
    subject = "f2-positive-control"
    with _owner(migrator_config) as owner:
        first, principal, identity, _ = _prepare(owner, subject=subject)
        assert first == {"status": "CREATED", "identity_id": identity, "principal_id": principal}
        second, other_principal, other_identity, other_binding = _prepare(owner, subject=subject)
        assert second == {
            "status": "EXISTING",
            "identity_id": identity,
            "principal_id": principal,
        }
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.principal WHERE id = %s", (other_principal,)
            ).fetchone()[0]
            == 0
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.identity WHERE id = %s", (other_identity,)
            ).fetchone()[0]
            == 0
        )
        assert (
            owner.execute(
                "SELECT count(*) FROM mtmf.external_subject_identity WHERE id = %s",
                (other_binding,),
            ).fetchone()[0]
            == 0
        )
        owner.rollback()
