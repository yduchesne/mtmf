"""Shared fixtures and fakes for the reference-app unit suite.

The fake client and token verifier exercise the PEP's *own* ordering and error
mapping deterministically. The real cryptographic verifier and real official
client are exercised by the deployed acceptance suite, never here.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from mtmf_reference_app.app import (
    BoundedWorker,
    CreateDependencies,
    DocumentReader,
    create_app,
)
from mtmf_reference_app.auth import AuthenticationError, SessionKeyDeriver, VerifiedUser
from mtmf_reference_app.config import ReferenceAppConfig
from mtmf_reference_app.store import DocumentStore

from mtmf_api.authorization import AuthorizationBatchRequest, ResourceTarget
from mtmf_client import AuthorizationDenied, DependencyUnavailableError

APPLICATION_ID = UUID("33333333-3333-4333-8333-333333333333")
TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT_ID = UUID("22222222-2222-4222-8222-222222222222")
ALLOWED_SUBJECT = "allowed-subject"
DENIED_SUBJECT = "denied-subject"
ALLOWED_TOKEN = "allowed-token"
DENIED_TOKEN = "denied-token"
DOCUMENT_ID = "44444444-4444-4444-8444-444444444444"
OTHER_DOCUMENT_ID = "55555555-5555-4555-8555-555555555555"


def _write_self_signed_ca(path: Path) -> None:
    """Write a throwaway self-signed CA certificate so SSLContext can load it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "reference-app-test-ca")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def write_config_files(tmp_path: Path) -> dict[str, str]:
    """Create a secret, CA, and fixture mapping, returning a valid env mapping."""
    secret = tmp_path / "client.secret"
    secret.write_text("test-secret", encoding="utf-8")
    os.chmod(secret, 0o600)
    ca = tmp_path / "ca.pem"
    _write_self_signed_ca(ca)
    mapping = tmp_path / "fixture.json"
    mapping.write_text(
        json.dumps(
            {
                "version": 1,
                "application_id": str(APPLICATION_ID),
                "tenant_id": str(TENANT_ID),
                "subjects": {
                    ALLOWED_SUBJECT: str(TENANT_ID),
                    DENIED_SUBJECT: str(TENANT_ID),
                },
            }
        ),
        encoding="utf-8",
    )
    return {
        "MTMF_REFERENCE_APP_ISSUER": "https://issuer.example.test/realms/app",
        "MTMF_REFERENCE_APP_USER_AUDIENCE": "app-api",
        "MTMF_REFERENCE_APP_MTMF_BASE_URL": "https://mtmf.example.test",
        "MTMF_REFERENCE_APP_TOKEN_ENDPOINT": (
            "https://issuer.example.test/realms/app/protocol/openid-connect/token"
        ),
        "MTMF_REFERENCE_APP_APPLICATION_ID": str(APPLICATION_ID),
        "MTMF_REFERENCE_APP_CLIENT_ID": "mtmf-reference-app",
        "MTMF_REFERENCE_APP_CLIENT_SECRET_FILE": str(secret),
        "MTMF_REFERENCE_APP_CA_BUNDLE": str(ca),
        "MTMF_REFERENCE_APP_SQLITE_PATH": str(tmp_path / "documents.db"),
        "MTMF_REFERENCE_APP_FIXTURE_MAPPING_PATH": str(mapping),
    }


def make_config(
    tmp_path: Path, overrides: dict[str, str | None] | None = None
) -> ReferenceAppConfig:
    """Build a validated config from the standard fixture files."""
    env = write_config_files(tmp_path)
    if overrides:
        for key, value in overrides.items():
            if value is None:
                env.pop(key, None)
            else:
                env[key] = value
    return ReferenceAppConfig.from_env(env)


@dataclass
class SeedRow:
    document_id: str
    tenant_id: str
    title: str
    body: str


class FakeVerifier:
    """Deterministic stand-in for the cryptographic verifier."""

    def __init__(self, subjects: dict[str, str]) -> None:
        self._subjects = subjects
        self.calls: list[str] = []
        self.fail = False

    def verify(self, token: str) -> VerifiedUser:
        self.calls.append(token)
        if self.fail:
            raise AuthenticationError("unverifiable")
        subject = self._subjects.get(token)
        if subject is None:
            raise AuthenticationError("unknown token")
        return VerifiedUser(issuer="https://issuer.example.test/realms/app", subject=subject)


class FakeClient:
    """Deterministic stand-in for the official HTTP client."""

    def __init__(self, *, allowed: bool = True, error: Exception | None = None) -> None:
        self.allowed = allowed
        self.error = error
        self.calls: list[tuple[AuthorizationBatchRequest, str, Any]] = []
        self.required: list[tuple[str, ResourceTarget, str | None]] = []
        self.closed = False

    def evaluate(
        self,
        request: AuthorizationBatchRequest,
        *,
        user_access_token: str,
        context: Any,
    ) -> Any:
        self.calls.append((request, user_access_token, context))
        if self.error is not None:
            raise self.error
        return _FakeSnapshot(allowed=self.allowed)

    def require(
        self,
        snapshot: Any,
        *,
        context: Any,
        action: str,
        resource: ResourceTarget,
        request_id: str | None = None,
    ) -> None:
        self.required.append((action, resource, request_id))
        if not snapshot.allowed:
            raise AuthorizationDenied("denied")

    def close(self) -> None:
        self.closed = True


class BlockingEvaluateClient:
    """A client whose ``evaluate`` blocks until explicitly released."""

    def __init__(self, release: threading.Event) -> None:
        self._release = release
        self.calls = 0
        self.closed = False

    def evaluate(
        self,
        request: AuthorizationBatchRequest,
        *,
        user_access_token: str,
        context: Any,
    ) -> Any:
        self.calls += 1
        self._release.wait(10.0)
        return _FakeSnapshot(allowed=True)

    def require(
        self,
        snapshot: Any,
        *,
        context: Any,
        action: str,
        resource: ResourceTarget,
        request_id: str | None = None,
    ) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class PolicyClient:
    """Deterministic client with per-Action decisions and per-request overrides.

    ``evaluate`` returns the exact request as the snapshot; ``require`` denies
    any Action absent from ``allowed_actions`` or any ``request_id`` recorded in
    ``deny_request_ids``. This exercises the PEP's own ordering and
    atomic-disclosure logic without reimplementing client wire semantics.
    """

    def __init__(
        self,
        *,
        allowed_actions: frozenset[str] | set[str] = frozenset(),
        deny_request_ids: frozenset[str] = frozenset(),
        error: Exception | None = None,
    ) -> None:
        self._allowed = set(allowed_actions)
        self._denied_requests = set(deny_request_ids)
        self._error = error
        self.calls: list[tuple[AuthorizationBatchRequest, str, Any]] = []
        self.required: list[tuple[str, ResourceTarget, str | None]] = []
        self.closed = False

    def evaluate(
        self, request: AuthorizationBatchRequest, *, user_access_token: str, context: Any
    ) -> Any:
        self.calls.append((request, user_access_token, context))
        if self._error is not None:
            raise self._error
        return request

    def require(
        self,
        snapshot: Any,
        *,
        context: Any,
        action: str,
        resource: ResourceTarget,
        request_id: str | None = None,
    ) -> None:
        self.required.append((action, resource, request_id))
        if request_id in self._denied_requests or action not in self._allowed:
            raise AuthorizationDenied("denied")

    def close(self) -> None:
        self.closed = True


@dataclass
class _FakeSnapshot:
    allowed: bool


def make_reader(
    config: ReferenceAppConfig,
    *,
    verifier: FakeVerifier,
    client: FakeClient,
    evaluate_worker: BoundedWorker | None = None,
) -> DocumentReader:
    return DocumentReader(
        config=config,
        store=DocumentStore(config.sqlite_path),
        token_verifier=verifier,
        session_keys=SessionKeyDeriver(),
        client=client,
        evaluate_worker=evaluate_worker,
    )


def make_test_client(reader: DocumentReader, client: FakeClient) -> TestClient:
    return TestClient(create_app(CreateDependencies(reader=reader, client=client)))  # type: ignore[arg-type]


def dependency_error() -> Exception:
    return DependencyUnavailableError("unavailable")
