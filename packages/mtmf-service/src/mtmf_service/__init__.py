"""MTMF optional HTTP deployment package (PR 17 authenticated PDP)."""

from __future__ import annotations

from mtmf_service.app import create_app
from mtmf_service.settings import (
    DeploymentMode,
    ServiceConfigurationError,
    ServiceSettings,
)

__all__ = [
    "DeploymentMode",
    "ServiceConfigurationError",
    "ServiceSettings",
    "__version__",
    "create_app",
]

__version__ = "0.1.0"
