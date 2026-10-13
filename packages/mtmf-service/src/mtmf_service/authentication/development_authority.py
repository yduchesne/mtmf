"""Approved development authentication authority validation (PR 17-C).

The service layer treats the authentication issuer and the Keycloak Admin REST
base as *development-only* trust anchors. Before PR 17-C only loopback hosts
were accepted because the development stack ran the HTTP service with host
networking. PR 17-C moves the standard development stack onto an isolated
Compose network with one canonical, TLS-verified authority,
``keycloak.mtmf.test:28443``, so containers resolve the canonical hostname
through the MTMF-owned network alias instead of host loopback.

This module centralises the approved-authority check so the exact allowed host
set has a single definition and every call site stays fail-closed for any
other host. It deliberately does **not** weaken any OIDC/TLS check: callers
still require HTTPS, signature/JWKS verification, strict issuer equality, and
Keycloak realm/client attestation.
"""

from __future__ import annotations

import urllib.parse

__all__ = [
    "APPROVED_DEVELOPMENT_HOSTS",
    "CANONICAL_DEVELOPMENT_HOST",
    "approved_development_host",
    "is_approved_development_authority",
]

#: Canonical development issuer hostname used by the standard Compose stack.
CANONICAL_DEVELOPMENT_HOST = "keycloak.mtmf.test"

#: Loopback hosts retained for the documented host-network fallback and local
#: unit/integration fixtures.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: Exactly the hosts a development authentication authority may use.
APPROVED_DEVELOPMENT_HOSTS: frozenset[str] = _LOOPBACK_HOSTS | {CANONICAL_DEVELOPMENT_HOST}


def approved_development_host(url: str) -> str | None:
    """Return the approved host of ``url``, or ``None`` when it is not approved."""
    try:
        host = urllib.parse.urlparse(url).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower()
    return host if host in APPROVED_DEVELOPMENT_HOSTS else None


def is_approved_development_authority(url: str, *, require_https: bool = False) -> bool:
    """Return whether ``url`` names an approved development authority.

    When ``require_https`` is true the scheme must be HTTPS; the default keeps
    the historical host-only check for call sites that enforce HTTPS
    separately.
    """
    if require_https and urllib.parse.urlparse(url).scheme != "https":
        return False
    return approved_development_host(url) is not None
