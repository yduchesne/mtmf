"""ASGI entry point for the PR 17 HTTP PDP.

The runtime uses the restricted ``mtmf_runtime`` PostgreSQL identity
only. Migration, owner, bootstrap and issuer-admin credentials must never
appear in this process's environment; the development initializer is a
separate privileged one-shot.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from mtmf_core.persistence.postgres import PostgresConfig, PostgresMtmfSpi, PostgresRole
from mtmf_service.app import create_app
from mtmf_service.authentication.config import IssuerConfig
from mtmf_service.composition import build_dependencies
from mtmf_service.observability.persistence import MetricsPersistenceTelemetry
from mtmf_service.observability.runtime import build_telemetry
from mtmf_service.settings import DeploymentMode, ServiceSettings

__all__ = ["app", "create_app_from_env"]


def _initialization_complete() -> bool:
    """Return whether the development initializer marked completion."""
    return os.environ.get("MTMF_SERVICE_INITIALIZED", "").strip() == "1"


def create_app_from_env() -> FastAPI:
    """Build the ASGI application from explicit environment configuration."""
    settings = ServiceSettings.from_env()
    issuer_config = IssuerConfig.from_env()
    telemetry = build_telemetry(settings)
    spi = PostgresMtmfSpi(
        PostgresConfig.from_env(PostgresRole.RUNTIME),
        telemetry=MetricsPersistenceTelemetry(telemetry),
    )
    dependencies = build_dependencies(
        spi=spi,
        issuer_config=issuer_config,
        settings=settings,
        initialization_complete=_initialization_complete,
        require_initialization=settings.deployment_mode is DeploymentMode.DEVELOPMENT,
        telemetry=telemetry,
    )
    return create_app(
        settings=settings,
        authorization_service=dependencies.authorization_service,
        management_membership_service=dependencies.management_membership_service,
        readiness=dependencies.readiness,
        rate_limiter=dependencies.rate_limiter,
        admission=dependencies.admission,
        telemetry=dependencies.telemetry,
        on_shutdown=dependencies.telemetry.shutdown,
    )


app = create_app_from_env()
