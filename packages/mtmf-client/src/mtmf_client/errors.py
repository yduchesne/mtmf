"""Typed, redacted exceptions for the official MTMF client (PR 18).

Exception semantics are deliberately split so that a *policy* denial is
never confused with an *operational* failure:

- :class:`AuthorizationDenied` is the only local-helper denial raised by
  :func:`mtmf_client.require`; it is derived exclusively from an already
  validated, context-bound snapshot.
- :class:`ClientAuthenticationError` is an OAuth 2.0 service-token
  acquisition/renewal failure (token endpoint unreachable, malformed,
  rejected). It never downgrades authentication.
- :class:`RemoteAuthenticationError` and :class:`RemoteEligibilityError`
  are the MTMF service rejecting the service credential or the verified
  actor/Application context.
- :class:`RemoteProtocolError` is a malformed, non-conformant, oversized
  or otherwise unusable response. It is never a policy decision.
- :class:`DependencyUnavailableError` is a transient remote dependency or
  transport failure (including rate limiting and server faults).
- :class:`ClientClosedError` is use of a closed client.
- :class:`ClientConfigurationError` is an invalid local configuration.

No exception message contains a token, secret, response body, policy
detail, or credential. Messages are short, static and non-sensitive.
"""

from __future__ import annotations

__all__ = [
    "ActorContextError",
    "AuthorizationDenied",
    "ClientAuthenticationError",
    "ClientClosedError",
    "ClientConfigurationError",
    "DependencyUnavailableError",
    "MtmfClientError",
    "RemoteAuthenticationError",
    "RemoteEligibilityError",
    "RemoteProtocolError",
]


class MtmfClientError(Exception):
    """Base class for every non-policy MTMF client failure."""


class ClientConfigurationError(MtmfClientError, ValueError):
    """The local :class:`~mtmf_client.config.ClientConfig` is invalid.

    Raised before any network call; never carries a secret value.
    """


class ClientClosedError(MtmfClientError):
    """The client has been closed and refuses further operations."""


class ClientAuthenticationError(MtmfClientError):
    """OAuth 2.0 service-token acquisition or renewal failed.

    The client never continues with a known-expired or unverifiable
    service token, and never falls back to an unauthenticated call.
    """


class ActorContextError(MtmfClientError, ValueError):
    """The trusted local actor/session binding or user token is invalid.

    This is raised when the consumer did not supply a genuinely
    authenticated end-user access token plus a stable local session/actor
    binding, or when the requested Tenant/Organization does not match the
    authenticated local context.
    """


class RemoteAuthenticationError(MtmfClientError):
    """The MTMF service rejected the service credential (HTTP 401)."""


class RemoteEligibilityError(MtmfClientError):
    """The MTMF service rejected the actor, Application or subscription (HTTP 403)."""


class RemoteProtocolError(MtmfClientError):
    """The MTMF response was malformed, non-conformant, or unusable.

    This includes malformed error envelopes, unexpected content types,
    oversized bodies, reordered/omitted decisions, Tenant/Organization
    mismatch, invalid timestamps and unknown effects. It never grants a
    snapshot.
    """


class DependencyUnavailableError(MtmfClientError):
    """A remote dependency or the transport failed transiently (HTTP 5xx/429/timeout)."""


class AuthorizationDenied(MtmfClientError):  # noqa: N818 - plan-mandated public name
    """A local ``require`` check denied access.

    Raised only by :func:`mtmf_client.require` when the bound snapshot has
    no exact, unexpired, matching ``ALLOW`` occurrence. It is never raised
    for a malformed response or a transport failure.
    """
