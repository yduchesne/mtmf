"""``python -m mtmf_service`` Uvicorn host for local development.

Binds loopback only. Remote TLS termination and the production transport
profile remain a separate release gate.
"""

from __future__ import annotations

import uvicorn

from mtmf_service.asgi import app
from mtmf_service.settings import ServiceSettings

__all__ = ["main"]


def main() -> None:
    """Run the development ASGI server on the configured loopback binding."""
    settings = ServiceSettings.from_env()
    settings.validate_startup()
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
