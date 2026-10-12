"""Real-PostgreSQL acceptance for the PR 17 development initializer.

Exercises the concrete privileged provisioner against a freshly migrated
empty ``mtmf`` schema: fresh initialization, restart idempotency, and
concurrent serialization. The Keycloak credential port is doubled here;
the live issuer acceptance is covered by the PR 14 live suite.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
from pathlib import Path

import pytest

from mtmf_core.persistence.postgres import PostgresConfig
from mtmf_service.development_bootstrap import (
    ApplicationFixture,
    BootstrapError,
    BootstrapFixture,
    DevelopmentBootstrap,
    TenantFixture,
    UserFixture,
)
from mtmf_service.settings import DeploymentMode

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-initialize.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_initialize", _SCRIPT)
assert _spec is not None and _spec.loader is not None
_script = importlib.util.module_from_spec(_spec)
sys.modules["mtmf_dev_initialize"] = _script
_spec.loader.exec_module(_script)


class _NoopCredentials:
    def ensure_client(self, fixture, application):  # type: ignore[no-untyped-def]
        return f"mtmf-{application.application_key}"

    def verify_issuer(self, fixture):  # type: ignore[no-untyped-def]
        return None


def _fixture() -> BootstrapFixture:
    return BootstrapFixture(
        tenant=TenantFixture("dev", "Development Tenant", "Dev Principal", "Dev Steward"),
        user=UserFixture("mtmf-dev-user", "Dev User Principal", "Dev User Identity"),
        applications=(ApplicationFixture("sample-app", "Sample Application"),),
        issuer="https://127.0.0.1:28443/realms/mtmf-pr14-dev",
        service_audience="mtmf-service-api",
        user_audience="mtmf-user-api",
        realm="mtmf-pr14-dev",
    )


def _run(migrator_config: PostgresConfig) -> None:
    provisioner = _script.PostgresProvisioner(migrator_config)
    DevelopmentBootstrap(
        mode=DeploymentMode.DEVELOPMENT,
        fixture=_fixture(),
        provisioning=provisioner,
        credentials=_NoopCredentials(),
        lock=provisioner,
    ).run()


def _counts(db) -> tuple[int, int, int, int]:  # type: ignore[no-untyped-def]
    return (
        db.execute("SELECT count(*) FROM mtmf.root_registry").fetchone()[0],
        db.execute("SELECT count(*) FROM mtmf.tenant WHERE scope = 2").fetchone()[0],
        db.execute("SELECT count(*) FROM mtmf.application").fetchone()[0],
        db.execute("SELECT count(*) FROM mtmf.tenant_application_subscription").fetchone()[0],
    )


def test_dev17_initializer_fresh_and_idempotent(db, migrator_config):  # type: ignore[no-untyped-def]
    _run(migrator_config)
    first = _counts(db)
    assert first == (1, 1, 1, 1)
    tenant = db.execute("SELECT lifecycle, scope FROM mtmf.tenant WHERE scope = 2").fetchone()
    assert tenant == (1, 2)  # ACTIVE ordinary Tenant
    # A second run must validate/reuse without duplicating or resetting state.
    _run(migrator_config)
    assert _counts(db) == first
    binding = db.execute(
        "SELECT count(*) FROM mtmf.service_credential_application WHERE lifecycle = 1"
    ).fetchone()[0]
    subject = db.execute(
        "SELECT count(*) FROM mtmf.external_subject_identity WHERE lifecycle = 1"
    ).fetchone()[0]
    assert binding == 1
    assert subject == 1


def test_dev17_initializer_concurrent_attempts_serialize(db, migrator_config):  # type: ignore[no-untyped-def]
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            _run(migrator_config)
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert _counts(db) == (1, 1, 1, 1)


def test_dev17_initializer_rejects_conflicting_root(db, migrator_config):  # type: ignore[no-untyped-def]
    # Pre-seed a different canonical root; the initializer must fail closed.
    db.execute(
        "SELECT mtmf.bootstrap_root(%s, %s, %s, 'Other', 'Other P', 'Other I')",
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "cccccccc-cccc-cccc-cccc-cccccccccccc",
        ),
    )
    with pytest.raises(BootstrapError):
        _run(migrator_config)
