"""Validated, immutable client configuration and secret references.

Configuration is validated entirely at construction, before any network
call. Endpoints must be HTTPS, must not carry userinfo or a fragment, and
the client never follows redirects. The service secret is held behind an
explicit :class:`SecretProvider` (a file reference by default) and is
never rendered by ``repr`` or any log line.

``mtmf-client`` does **not** decode JWTs. Any issuer/audience value here is
local operator trust configuration passed to the consumer; it is not a
claim that the client cryptographically verified a token. The MTMF service
remains the authority that verifies issuer, audience and signature.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit
from uuid import UUID

from mtmf_client.errors import ClientConfigurationError

__all__ = [
    "USER_AUTHORIZATION_HEADER",
    "ClientConfig",
    "FileSecretProvider",
    "SecretProvider",
]

#: Frozen PR 17 transport carrier for the separately verified end-user token.
USER_AUTHORIZATION_HEADER = "X-MTMF-User-Authorization"

#: Defaults chosen conservatively. ``max_snapshot_ttl_seconds`` defaults to
#: the security-sensitive ceiling because the authoritative sensitivity
#: classifier is not a public contract.
_DEFAULT_MAX_SNAPSHOT_TTL = 15
_ABSOLUTE_MAX_SNAPSHOT_TTL = 300
_DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024


@runtime_checkable
class SecretProvider(Protocol):
    """A source of the OAuth 2.0 client secret, read on demand only."""

    def read(self) -> str:
        """Return the non-empty client secret."""
        ...


@dataclass(frozen=True, slots=True, repr=False)
class FileSecretProvider:
    """Read a client secret from a regular, private file.

    The file contents are never placed on the instance, in ``repr``, or in
    an exception message. Reading is deferred until a token is actually
    required.
    """

    path: Path

    def __repr__(self) -> str:
        return f"FileSecretProvider(path={str(self.path)!r})"

    def read(self) -> str:
        """Return the stripped secret or raise :class:`ClientConfigurationError`."""
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ClientConfigurationError("the client secret file could not be read") from exc
        secret = text.strip()
        if not secret:
            raise ClientConfigurationError("the client secret file is empty")
        return secret


def _validate_https_url(value: object, field_name: str) -> str:
    """Validate an HTTPS endpoint URL and return it without a trailing slash."""
    if not isinstance(value, str) or not value:
        raise ClientConfigurationError(f"{field_name} must be a non-empty HTTPS URL")
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise ClientConfigurationError(f"{field_name} must use HTTPS")
    if not parts.hostname:
        raise ClientConfigurationError(f"{field_name} must include a host")
    if parts.username is not None or parts.password is not None:
        raise ClientConfigurationError(f"{field_name} must not include userinfo")
    if parts.fragment:
        raise ClientConfigurationError(f"{field_name} must not include a fragment")
    return value.rstrip("/")


def _validate_ca_bundle(value: object) -> str | None:
    """Validate an optional CA bundle path."""
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ClientConfigurationError("ca_bundle must be a non-empty path when set")
    if not os.path.isfile(value):
        raise ClientConfigurationError("ca_bundle must reference a regular file")
    return value


def _validate_secret_file(path: Path) -> None:
    """Require a regular, private secret file.

    A symlink to a regular file is accepted (Podman secrets are commonly
    symlinked). Group/other access on POSIX is rejected so a wide secret
    cannot be read by another local user.
    """
    try:
        info = path.stat()
    except OSError as exc:
        raise ClientConfigurationError("the client secret file does not exist") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ClientConfigurationError("the client secret reference must be a regular file")
    if os.name == "posix" and info.st_mode & 0o077:
        raise ClientConfigurationError(
            "the client secret file must not be group- or world-accessible"
        )


@dataclass(frozen=True, slots=True, repr=False)
class ClientConfig:
    """Validated, immutable ``mtmf-client`` configuration.

    :param base_url: HTTPS base URL of the MTMF PDP (no trailing slash needed).
    :param token_endpoint: HTTPS OAuth 2.0 token endpoint.
    :param application_id: Local Application binding expected for this client.
        This is a local binding, **not** proof of the verified server-side
        Application (the v1 response echoes no Application UUID).
    :param client_id: OAuth 2.0 client identifier for the service credential.
    :param client_secret_file: Secret file reference (preferred).
    :param secret_provider: Explicit secret provider seam (alternative).
    :param expected_issuer: Optional local issuer trust configuration.
    :param scope: Optional OAuth scope, only if the issuer supports it.
    :param audience: Optional OAuth audience, only if the issuer supports it.
    :param ca_bundle: Optional CA bundle path (development trust).
    :param connect_timeout: Per-connection timeout in seconds.
    :param read_timeout: Per-read timeout in seconds.
    :param write_timeout: Per-write timeout in seconds.
    :param pool_timeout: Connection-pool acquisition timeout in seconds.
    :param max_response_bytes: Maximum accepted response body size.
    :param renewal_leeway_seconds: Bounded proactive service-token renewal margin.
    :param max_snapshot_ttl_seconds: Client-side maximum snapshot lifetime.
    :param clock_uncertainty_seconds: Conservative clock uncertainty allowance.
    """

    base_url: str
    token_endpoint: str
    application_id: UUID
    client_id: str
    client_secret_file: Path | None = None
    secret_provider: SecretProvider | None = field(default=None, repr=False)
    expected_issuer: str | None = None
    scope: str | None = None
    audience: str | None = None
    ca_bundle: str | None = None
    connect_timeout: float = 5.0
    read_timeout: float = 15.0
    write_timeout: float = 10.0
    pool_timeout: float = 5.0
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES
    renewal_leeway_seconds: float = 5.0
    max_snapshot_ttl_seconds: int = _DEFAULT_MAX_SNAPSHOT_TTL
    clock_uncertainty_seconds: float = 5.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "base_url", _validate_https_url(self.base_url, "base_url"))
        object.__setattr__(
            self, "token_endpoint", _validate_https_url(self.token_endpoint, "token_endpoint")
        )
        if not isinstance(self.application_id, UUID) or self.application_id.int == 0:
            raise ClientConfigurationError("application_id must be a non-nil UUID")
        if not isinstance(self.client_id, str) or not self.client_id.strip():
            raise ClientConfigurationError("client_id must be a non-empty string")
        if self.expected_issuer is not None:
            _validate_https_url(self.expected_issuer, "expected_issuer")
        if self.scope is not None and (not isinstance(self.scope, str) or not self.scope.strip()):
            raise ClientConfigurationError("scope must be a non-empty string when set")
        if self.audience is not None and (
            not isinstance(self.audience, str) or not self.audience.strip()
        ):
            raise ClientConfigurationError("audience must be a non-empty string when set")
        object.__setattr__(self, "ca_bundle", _validate_ca_bundle(self.ca_bundle))
        _validate_secret_source(self.client_secret_file, self.secret_provider)
        for name in ("connect_timeout", "read_timeout", "write_timeout", "pool_timeout"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value <= 0:
                raise ClientConfigurationError(f"{name} must be a positive number")
        if (
            not isinstance(self.max_response_bytes, int)
            or isinstance(self.max_response_bytes, bool)
            or self.max_response_bytes < 1
        ):
            raise ClientConfigurationError("max_response_bytes must be a positive integer")
        if (
            not isinstance(self.renewal_leeway_seconds, (int, float))
            or isinstance(self.renewal_leeway_seconds, bool)
            or self.renewal_leeway_seconds < 0
        ):
            raise ClientConfigurationError("renewal_leeway_seconds must be non-negative")
        if (
            not isinstance(self.max_snapshot_ttl_seconds, int)
            or isinstance(self.max_snapshot_ttl_seconds, bool)
            or not 0 < self.max_snapshot_ttl_seconds <= _ABSOLUTE_MAX_SNAPSHOT_TTL
        ):
            raise ClientConfigurationError("max_snapshot_ttl_seconds must satisfy 0 < ttl <= 300")
        if (
            not isinstance(self.clock_uncertainty_seconds, (int, float))
            or isinstance(self.clock_uncertainty_seconds, bool)
            or self.clock_uncertainty_seconds < 0
        ):
            raise ClientConfigurationError("clock_uncertainty_seconds must be non-negative")

    def __repr__(self) -> str:
        return (
            "ClientConfig("
            f"base_url={self.base_url!r}, "
            f"token_endpoint={self.token_endpoint!r}, "
            f"application_id={self.application_id!r}, "
            f"client_id={self.client_id!r}, "
            f"expected_issuer={self.expected_issuer!r}, "
            f"ca_bundle={self.ca_bundle!r})"
        )

    def read_client_secret(self) -> str:
        """Read the client secret from the configured source.

        :raises ClientConfigurationError: when no usable secret is configured.
        """
        source: SecretProvider | None = self.secret_provider
        if source is not None:
            secret = source.read()
        elif self.client_secret_file is not None:
            secret = FileSecretProvider(self.client_secret_file).read()
        else:  # pragma: no cover - guarded in __post_init__
            raise ClientConfigurationError("no client secret source is configured")
        if not isinstance(secret, str) or not secret.strip():
            raise ClientConfigurationError("the client secret is empty")
        return secret


def _validate_secret_source(
    client_secret_file: Path | None,
    secret_provider: SecretProvider | None,
) -> None:
    """Require exactly one secret source and validate the file reference."""
    if (client_secret_file is None) == (secret_provider is None):
        raise ClientConfigurationError(
            "exactly one of client_secret_file or secret_provider must be configured"
        )
    if client_secret_file is not None:
        if not isinstance(client_secret_file, Path):
            raise ClientConfigurationError("client_secret_file must be a pathlib.Path")
        _validate_secret_file(client_secret_file)
