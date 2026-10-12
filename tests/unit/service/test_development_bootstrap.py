"""Development initializer orchestration (idempotent, fail-closed) unit tests."""

from __future__ import annotations

import pytest

from mtmf_service.development_bootstrap import (
    ApplicationFixture,
    BootstrapError,
    BootstrapFixture,
    DevelopmentBootstrap,
    TenantFixture,
    UserFixture,
)
from mtmf_service.settings import DeploymentMode


def _fixture() -> BootstrapFixture:
    return BootstrapFixture(
        tenant=TenantFixture("dev", "Dev", "Dev Principal", "Dev Identity"),
        user=UserFixture("user-1", "User Principal", "User Identity"),
        applications=(ApplicationFixture("sample-app", "Sample"),),
        issuer="https://127.0.0.1:28443/realms/mtmf-pr14-dev",
        service_audience="mtmf-service-api",
        user_audience="mtmf-user-api",
        realm="mtmf-pr14-dev",
    )


class RecordingProvisioner:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fail: str | None = None

    def _record(self, name: str) -> None:
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError("provider failed")

    def apply_migrations_and_verify(self) -> None:
        self._record("migrate")

    def ensure_root(self, fixture: BootstrapFixture) -> None:
        self._record("root")

    def ensure_ordinary_tenant(self, fixture: BootstrapFixture) -> None:
        self._record("tenant")

    def ensure_user_binding(self, fixture: BootstrapFixture) -> None:
        self._record("user")

    def ensure_application(
        self, fixture: BootstrapFixture, application: ApplicationFixture
    ) -> None:
        self._record(f"app:{application.application_key}")

    def ensure_registration_and_subscription(
        self, fixture: BootstrapFixture, application: ApplicationFixture
    ) -> None:
        self._record(f"subscription:{application.application_key}")

    def ensure_service_binding(
        self,
        fixture: BootstrapFixture,
        application: ApplicationFixture,
        *,
        client_id: str,
    ) -> None:
        self._record(f"binding:{application.application_key}:{client_id}")


class RecordingCredentials:
    def __init__(self) -> None:
        self.clients: list[str] = []
        self.verified = False

    def ensure_client(self, fixture: BootstrapFixture, application: ApplicationFixture) -> str:
        self.clients.append(application.application_key)
        return f"client-{application.application_key}"

    def verify_issuer(self, fixture: BootstrapFixture) -> None:
        self.verified = True


class RecordingLock:
    def __init__(self) -> None:
        self.events: list[str] = []

    def acquire(self) -> None:
        self.events.append("acquire")

    def release(self) -> None:
        self.events.append("release")


def test_full_sequence_order_and_lock():
    provisioning = RecordingProvisioner()
    credentials = RecordingCredentials()
    lock = RecordingLock()
    DevelopmentBootstrap(
        mode=DeploymentMode.DEVELOPMENT,
        fixture=_fixture(),
        provisioning=provisioning,
        credentials=credentials,
        lock=lock,
    ).run()
    assert provisioning.calls == [
        "migrate",
        "root",
        "tenant",
        "user",
        "app:sample-app",
        "binding:sample-app:client-sample-app",
        "subscription:sample-app",
    ]
    assert credentials.verified is True
    assert lock.events == ["acquire", "release"]


def test_production_mode_is_refused_before_any_work():
    provisioning = RecordingProvisioner()
    lock = RecordingLock()
    with pytest.raises(BootstrapError):
        DevelopmentBootstrap(
            mode=DeploymentMode.PRODUCTION,
            fixture=_fixture(),
            provisioning=provisioning,
            credentials=RecordingCredentials(),
            lock=lock,
        ).run()
    assert provisioning.calls == []
    assert lock.events == []


def test_provider_failure_is_wrapped_and_lock_released():
    provisioning = RecordingProvisioner()
    provisioning.fail = "tenant"
    lock = RecordingLock()
    with pytest.raises(BootstrapError, match="partially"):
        DevelopmentBootstrap(
            mode=DeploymentMode.DEVELOPMENT,
            fixture=_fixture(),
            provisioning=provisioning,
            credentials=RecordingCredentials(),
            lock=lock,
        ).run()
    assert provisioning.calls == ["migrate", "root", "tenant"]
    assert lock.events == ["acquire", "release"]


def test_bootstrap_error_propagates_unchanged():
    class Failing(RecordingProvisioner):
        def apply_migrations_and_verify(self) -> None:
            raise BootstrapError("postflight failed")

    with pytest.raises(BootstrapError, match="postflight failed"):
        DevelopmentBootstrap(
            mode=DeploymentMode.DEVELOPMENT,
            fixture=_fixture(),
            provisioning=Failing(),
            credentials=RecordingCredentials(),
        ).run()


def test_fixture_validation():
    with pytest.raises(BootstrapError):
        TenantFixture("", "name", "p", "i")
    with pytest.raises(BootstrapError):
        UserFixture("s", "", "i")
    with pytest.raises(BootstrapError):
        ApplicationFixture("key", "")
    with pytest.raises(BootstrapError):
        BootstrapFixture(
            tenant=TenantFixture("dev", "Dev", "P", "I"),
            user=UserFixture("s", "UP", "UI"),
            applications=(),
            issuer="iss",
            service_audience="a",
            user_audience="b",
            realm="r",
        )
    with pytest.raises(BootstrapError):
        BootstrapFixture(
            tenant=TenantFixture("dev", "Dev", "P", "I"),
            user=UserFixture("s", "UP", "UI"),
            applications=(
                ApplicationFixture("dup", "One"),
                ApplicationFixture("dup", "Two"),
            ),
            issuer="iss",
            service_audience="a",
            user_audience="b",
            realm="r",
        )
