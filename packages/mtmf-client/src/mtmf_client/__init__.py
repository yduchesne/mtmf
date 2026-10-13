"""Official, HTTP-only Python client for the MTMF v1 authorization API (PR 18).

``mtmf-client`` is a consumer convenience library, not an authorization
authority. It:

- obtains a *service* access token via OAuth 2.0 Client Credentials;
- propagates an independently authenticated *end-user* access token;
- calls the frozen v1 ``POST /v1/authorization/evaluate`` endpoint;
- strictly validates the response against the original request;
- issues one immutable, context-bound, monotonic authorization snapshot;
- exposes fail-closed ``is_allowed`` / ``require`` PEP helpers.

It imports only ``mtmf-api`` and ``httpx`` plus the standard library: it
never imports ``mtmf-core``, ``mtmf-service``, FastAPI, PostgreSQL,
Alembic, or the Rust native module, and it never evaluates policy locally.
"""

from __future__ import annotations

from mtmf_client.client import HttpMtmfClient
from mtmf_client.config import (
    USER_AUTHORIZATION_HEADER,
    ClientConfig,
    FileSecretProvider,
    SecretProvider,
)
from mtmf_client.errors import (
    ActorContextError,
    AuthorizationDenied,
    ClientAuthenticationError,
    ClientClosedError,
    ClientConfigurationError,
    DependencyUnavailableError,
    MtmfClientError,
    RemoteAuthenticationError,
    RemoteEligibilityError,
    RemoteProtocolError,
)
from mtmf_client.snapshot import (
    AuthorizationSnapshot,
    TrustedActorContext,
    is_allowed,
    require,
)

__all__ = [
    "USER_AUTHORIZATION_HEADER",
    "ActorContextError",
    "AuthorizationDenied",
    "AuthorizationSnapshot",
    "ClientAuthenticationError",
    "ClientClosedError",
    "ClientConfig",
    "ClientConfigurationError",
    "DependencyUnavailableError",
    "FileSecretProvider",
    "HttpMtmfClient",
    "MtmfClientError",
    "RemoteAuthenticationError",
    "RemoteEligibilityError",
    "RemoteProtocolError",
    "SecretProvider",
    "TrustedActorContext",
    "is_allowed",
    "require",
]

__version__ = "0.1.0"
