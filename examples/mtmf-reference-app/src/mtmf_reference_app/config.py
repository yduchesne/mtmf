"""Strict, fail-closed configuration for the reference application.

Every value is validated at startup before the app accepts a request. Endpoints
must use HTTPS (except the loopback-only fixture loader); the trusted issuer,
user audience, Application UUID, secret/CA paths, and subject-to-Tenant fixture
mapping are all explicit configuration, never caller input. No insecure TLS or
untrusted issuer default exists.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from mtmf_reference_app.models import FixtureMapping, SubjectTenantBinding

__all__ = [
    "ConfigurationError",
    "ReferenceAppConfig",
    "load_fixture_mapping",
]


class ConfigurationError(RuntimeError):
    """The reference application configuration is missing or unsafe."""


def _require_env(source: dict[str, str], name: str) -> str:
    raw = source.get(name)
    if raw is None or not raw.strip():
        raise ConfigurationError(f"{name} is required")
    return raw.strip()


def _https_url(value: str, name: str) -> str:
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise ConfigurationError(f"{name} must use HTTPS")
    if not parts.hostname:
        raise ConfigurationError(f"{name} must include a host")
    if parts.username is not None or parts.password is not None:
        raise ConfigurationError(f"{name} must not include userinfo")
    if parts.fragment:
        raise ConfigurationError(f"{name} must not include a fragment")
    return value.rstrip("/")


def _private_file(value: str, name: str) -> Path:
    path = Path(value)
    try:
        info = path.stat()
    except OSError as exc:
        raise ConfigurationError(f"{name} does not reference a readable file") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigurationError(f"{name} must reference a regular file")
    if os.name == "posix" and info.st_mode & 0o077:
        raise ConfigurationError(f"{name} must not be group- or world-accessible")
    return path


def _readable_file(value: str, name: str) -> Path:
    path = Path(value)
    try:
        info = path.stat()
    except OSError as exc:
        raise ConfigurationError(f"{name} does not reference a readable file") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ConfigurationError(f"{name} must reference a regular file")
    return path


def _positive_float(source: dict[str, str], name: str, default: float) -> float:
    raw = source.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be a number") from exc
    if value <= 0:
        raise ConfigurationError(f"{name} must be positive")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class ReferenceAppConfig:
    """Validated, immutable reference-application configuration."""

    issuer: str
    user_audience: str
    mtmf_base_url: str
    token_endpoint: str
    application_id: UUID
    client_id: str
    client_secret_file: Path
    ca_bundle: Path
    sqlite_path: Path
    fixture_mapping_path: Path
    jwks_cache_seconds: float = 300.0
    mtmf_timeout_seconds: float = 10.0
    jwks_timeout_seconds: float = 5.0
    #: Proactive service-token renewal margin. It must absorb the token
    #: endpoint round-trip so the client never presents a token the service
    #: considers expired.
    renewal_leeway_seconds: float = 30.0
    _fixture_mapping: FixtureMapping = field(repr=False, default_factory=lambda: _empty_mapping())

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> ReferenceAppConfig:
        """Parse and validate configuration from the environment.

        :raises ConfigurationError: on any missing, malformed, or unsafe value.
        """
        source = dict(os.environ if environ is None else environ)
        issuer = _https_url(_require_env(source, "MTMF_REFERENCE_APP_ISSUER"), "issuer")
        user_audience = _require_env(source, "MTMF_REFERENCE_APP_USER_AUDIENCE")
        mtmf_base_url = _https_url(
            _require_env(source, "MTMF_REFERENCE_APP_MTMF_BASE_URL"), "mtmf_base_url"
        )
        token_endpoint = _https_url(
            _require_env(source, "MTMF_REFERENCE_APP_TOKEN_ENDPOINT"), "token_endpoint"
        )
        raw_application_id = _require_env(source, "MTMF_REFERENCE_APP_APPLICATION_ID")
        try:
            application_id = UUID(raw_application_id)
        except ValueError as exc:
            raise ConfigurationError("application_id must be a UUID") from exc
        if application_id.int == 0:
            raise ConfigurationError("application_id must not be the nil UUID")
        client_id = _require_env(source, "MTMF_REFERENCE_APP_CLIENT_ID")
        client_secret_file = _private_file(
            _require_env(source, "MTMF_REFERENCE_APP_CLIENT_SECRET_FILE"), "client_secret_file"
        )
        ca_bundle = _readable_file(
            _require_env(source, "MTMF_REFERENCE_APP_CA_BUNDLE"), "ca_bundle"
        )
        sqlite_path = Path(_require_env(source, "MTMF_REFERENCE_APP_SQLITE_PATH"))
        fixture_mapping_path = _readable_file(
            _require_env(source, "MTMF_REFERENCE_APP_FIXTURE_MAPPING_PATH"),
            "fixture_mapping_path",
        )
        mapping = load_fixture_mapping(fixture_mapping_path)
        if mapping.application_id != application_id:
            raise ConfigurationError(
                "the configured application_id does not match the fixture mapping"
            )
        if not mapping.subjects:
            raise ConfigurationError("the fixture mapping contains no trustable subjects")
        return cls(
            issuer=issuer,
            user_audience=user_audience,
            mtmf_base_url=mtmf_base_url,
            token_endpoint=token_endpoint,
            application_id=application_id,
            client_id=client_id,
            client_secret_file=client_secret_file,
            ca_bundle=ca_bundle,
            sqlite_path=sqlite_path,
            fixture_mapping_path=fixture_mapping_path,
            jwks_cache_seconds=_positive_float(
                source, "MTMF_REFERENCE_APP_JWKS_CACHE_SECONDS", 300.0
            ),
            mtmf_timeout_seconds=_positive_float(
                source, "MTMF_REFERENCE_APP_MTMF_TIMEOUT_SECONDS", 10.0
            ),
            jwks_timeout_seconds=_positive_float(
                source, "MTMF_REFERENCE_APP_JWKS_TIMEOUT_SECONDS", 5.0
            ),
            renewal_leeway_seconds=_positive_float(
                source, "MTMF_REFERENCE_APP_RENEWAL_LEEWAY_SECONDS", 30.0
            ),
            _fixture_mapping=mapping,
        )

    @property
    def fixture_mapping(self) -> FixtureMapping:
        """The validated subject/Application/Tenant fixture mapping."""
        return self._fixture_mapping

    @property
    def jwks_uri(self) -> str:
        """The pinned issuer's JWKS URI."""
        return f"{self.issuer}/protocol/openid-connect/certs"

    def __repr__(self) -> str:
        return (
            "ReferenceAppConfig("
            f"issuer={self.issuer!r}, "
            f"user_audience={self.user_audience!r}, "
            f"mtmf_base_url={self.mtmf_base_url!r}, "
            f"application_id={self.application_id!r}, "
            f"client_id={self.client_id!r})"
        )


def _empty_mapping() -> FixtureMapping:
    return FixtureMapping(
        application_id=UUID(int=0),
        tenant_id=UUID(int=0),
        subjects={},
    )


def load_fixture_mapping(path: Path) -> FixtureMapping:
    """Load and strictly validate the initializer-generated fixture mapping.

    :raises ConfigurationError: on malformed JSON, a wrong version, missing or
        malformed UUIDs, a non-object subject map, or a malformed subject key.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("the fixture mapping could not be read") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("the fixture mapping must be a JSON object")
    if raw.get("version") != 1:
        raise ConfigurationError("unsupported fixture mapping version")
    application_id = _mapping_uuid(raw.get("application_id"), "application_id")
    tenant_id = _mapping_uuid(raw.get("tenant_id"), "tenant_id")
    subjects_raw = raw.get("subjects")
    if not isinstance(subjects_raw, dict) or not subjects_raw:
        raise ConfigurationError("the fixture mapping must contain a non-empty subjects object")
    subjects: dict[str, SubjectTenantBinding] = {}
    for subject, value in subjects_raw.items():
        if not isinstance(subject, str) or not subject.strip():
            raise ConfigurationError("a fixture subject key must be a non-empty string")
        if not isinstance(value, str):
            raise ConfigurationError("a fixture tenant value must be a UUID string")
        mapped_tenant = _mapping_uuid(value, f"tenant for subject {subject!r}")
        if mapped_tenant != tenant_id:
            raise ConfigurationError("a fixture subject maps to a different Tenant")
        subjects[subject] = SubjectTenantBinding(subject=subject, tenant_id=mapped_tenant)
    return FixtureMapping(
        application_id=application_id,
        tenant_id=tenant_id,
        subjects=subjects,
        version=1,
    )


def _mapping_uuid(value: Any, label: str) -> UUID:
    if not isinstance(value, str):
        raise ConfigurationError(f"the fixture mapping {label} must be a UUID string")
    try:
        parsed = UUID(value)
    except ValueError as exc:
        raise ConfigurationError(f"the fixture mapping {label} is not a UUID") from exc
    if parsed.int == 0:
        raise ConfigurationError(f"the fixture mapping {label} must not be the nil UUID")
    return parsed
