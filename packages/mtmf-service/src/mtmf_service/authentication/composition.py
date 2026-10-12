"""Development composition seam for PR 14 authenticated actor context.

Wires the provider-neutral actor service to the service-layer transport:
bounded JWKS verification and fresh live configuration attestation. No HTTP
application or route is created here (PR 17 owns transport).
"""

from __future__ import annotations

from mtmf_core.application.authentication import AuthenticatedActorContextService
from mtmf_core.authentication.contracts import IssuerProfile
from mtmf_core.persistence.spi import MtmfSpi
from mtmf_service.authentication.attestation import (
    BaselineConfigurationAttestor,
    HttpAdminRestReader,
)
from mtmf_service.authentication.config import IssuerConfig
from mtmf_service.authentication.jwt_verifier import JwksKeyProvider, PyJWTTokenVerifier

__all__ = ["build_actor_context_service"]


def build_actor_context_service(
    spi: MtmfSpi, config: IssuerConfig
) -> AuthenticatedActorContextService:
    """Build the verified D1 actor-context service for the dev issuer."""
    algorithms = frozenset({config.algorithm})
    service_profile = IssuerProfile(
        issuer=config.issuer,
        audience=config.service_audience,
        jwks_uri=config.jwks_uri,
        algorithms=algorithms,
    )
    user_profile = IssuerProfile(
        issuer=config.issuer,
        audience=config.user_audience,
        jwks_uri=config.jwks_uri,
        algorithms=algorithms,
    )
    key_provider = JwksKeyProvider(
        config.jwks_uri,
        timeout=config.transport_timeout_seconds,
        max_bytes=config.max_jwks_bytes,
        cache_seconds=config.jwks_cache_seconds,
        min_refresh_seconds=config.jwks_min_refresh_seconds,
    )
    verifier = PyJWTTokenVerifier(key_provider, max_token_bytes=config.max_token_bytes)
    reader = HttpAdminRestReader(
        config.admin_base_url,
        config.admin_realm,
        config.attestation_client_id,
        config.attestation_client_secret,
        timeout=config.transport_timeout_seconds,
        max_bytes=config.max_jwks_bytes,
    )
    attestor = BaselineConfigurationAttestor(
        reader,
        config.admin_realm,
        config.expected_manifest_path,
        config.expected_client_policy_path,
    )
    return AuthenticatedActorContextService(
        spi=spi,
        attestor=attestor,
        service_verifier=verifier,
        service_profile=service_profile,
        user_verifier=verifier,
        user_profile=user_profile,
    )
