"""Fresh, zero-cache issuer-configuration attestation (development-only).

The trusted baseline is a reviewed repository artifact. Every ``attest`` call
performs a fresh live Admin REST read and a full canonical-manifest
comparison; a prior success, startup check, or persisted record never
authorizes a later operation. Any unreadable/absent baseline, transport
failure, timeout, or drift raises a typed authentication failure.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Protocol

from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    IssuerProfile,
)

__all__ = [
    "AdminRestReader",
    "BaselineConfigurationAttestor",
    "HttpAdminRestReader",
    "canonical_manifest",
    "manifest_hash",
]

_CLIENT_FIELDS = (
    "enabled",
    "publicClient",
    "serviceAccountsEnabled",
    "standardFlowEnabled",
    "directAccessGrantsEnabled",
    "implicitFlowEnabled",
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every HTTP redirect for the privileged configuration read."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


class AdminRestReader(Protocol):
    """Minimal privileged read path for the live issuer configuration."""

    def get(self, path: str) -> Any:
        """Return the JSON document at ``path`` or raise."""
        ...


class HttpAdminRestReader:
    """Keycloak Admin REST reader authenticated with a separate credential."""

    def __init__(
        self,
        base_url: str,
        realm: str,
        username: str,
        password: str,
        *,
        timeout: float = 5.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._realm = realm
        self._username = username
        self._password = password
        self._timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirectHandler())

    def _open(self, request: urllib.request.Request) -> Any:
        """Open only an http(s) request through the redirect-rejecting opener."""
        scheme = urllib.parse.urlparse(request.full_url).scheme
        if scheme not in ("http", "https"):
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "unsupported admin URL scheme"
            )
        return self._opener.open(request, timeout=self._timeout)

    def _token(self) -> str:
        data = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": self._username,
                "password": self._password,
            }
        ).encode()
        request = urllib.request.Request(
            f"{self._base}/realms/master/protocol/openid-connect/token",
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with self._open(request) as response:
                payload: dict[str, Any] = json.loads(response.read())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "attestation credential failed"
            ) from exc
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "attestation credential failed"
            )
        return token

    def get(self, path: str) -> Any:
        request = urllib.request.Request(
            f"{self._base}{path}",
            headers={"Authorization": f"Bearer {self._token()}", "Accept": "application/json"},
        )
        try:
            with self._open(request) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "live configuration read failed"
            ) from exc


def _normalize_mappers(mappers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized = [
        {
            "name": mapper.get("name"),
            "protocolMapper": mapper.get("protocolMapper"),
            "config": {
                str(k): str(v)
                for k, v in sorted((mapper.get("config") or {}).items())
                if v is not None
            },
        }
        for mapper in mappers
    ]
    return sorted(normalized, key=lambda m: (str(m["name"]), str(m["protocolMapper"])))


def canonical_manifest(reader: AdminRestReader, realm: str) -> dict[str, Any]:
    """Build the canonical security-relevant manifest from the live realm."""
    clients = []
    for client in reader.get(f"/admin/realms/{realm}/clients") or []:
        uuid = client["id"]
        clients.append(
            {
                "clientId": client.get("clientId"),
                **{field: client.get(field) for field in _CLIENT_FIELDS},
                "defaultClientScopes": sorted(
                    s["name"]
                    for s in reader.get(
                        f"/admin/realms/{realm}/clients/{uuid}/default-client-scopes"
                    )
                    or []
                ),
                "optionalClientScopes": sorted(
                    s["name"]
                    for s in reader.get(
                        f"/admin/realms/{realm}/clients/{uuid}/optional-client-scopes"
                    )
                    or []
                ),
                "protocolMappers": _normalize_mappers(
                    reader.get(f"/admin/realms/{realm}/clients/{uuid}/protocol-mappers/models")
                    or []
                ),
            }
        )
    scopes = []
    for scope in reader.get(f"/admin/realms/{realm}/client-scopes") or []:
        scopes.append(
            {
                "name": scope.get("name"),
                "protocol": scope.get("protocol"),
                "attributes": {
                    str(k): str(v)
                    for k, v in sorted((scope.get("attributes") or {}).items())
                    if v is not None
                },
                "protocolMappers": _normalize_mappers(
                    reader.get(
                        f"/admin/realms/{realm}/client-scopes/{scope['id']}/protocol-mappers/models"
                    )
                    or []
                ),
            }
        )
    return {
        "realm": realm,
        "clients": sorted(clients, key=lambda c: str(c["clientId"])),
        "clientScopes": sorted(scopes, key=lambda s: str(s["name"])),
    }


def manifest_hash(manifest: dict[str, Any]) -> str:
    """Return the canonical SHA-256 of a manifest."""
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _diff(expected: Any, actual: Any, path: str = "") -> bool:
    """Return whether two manifests are structurally identical."""
    if type(expected) is not type(actual) and not (
        isinstance(expected, (int, float)) and isinstance(actual, (int, float))
    ):
        return False
    if isinstance(expected, dict):
        if set(expected) != set(actual):
            return False
        return all(_diff(expected[k], actual[k], f"{path}.{k}") for k in expected)
    if isinstance(expected, list):
        return len(expected) == len(actual) and all(
            _diff(e, a, path) for e, a in zip(expected, actual, strict=True)
        )
    return bool(expected == actual)


class BaselineConfigurationAttestor:
    """Compare a fresh live manifest to a reviewed repository baseline."""

    def __init__(self, reader: AdminRestReader, realm: str, baseline_path: str) -> None:
        self._reader = reader
        self._realm = realm
        self._baseline_path = baseline_path

    def attest(self, profile: IssuerProfile) -> None:
        """Fail closed unless the live configuration exactly matches the baseline."""
        del profile  # the profile is validated by construction; realm drives the read
        expected = self._load_baseline()
        try:
            actual = canonical_manifest(self._reader, self._realm)
        except AuthenticationError:
            raise
        except Exception as exc:  # any read failure is fail-closed
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "live configuration was unavailable"
            ) from exc
        if not _diff(expected, actual):
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_DRIFT,
                "live issuer configuration drifted from the trusted baseline",
            )

    def _load_baseline(self) -> dict[str, Any]:
        try:
            payload = json.loads(Path(self._baseline_path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "trusted baseline is unreadable"
            ) from exc
        if not isinstance(payload, dict):
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "trusted baseline is malformed"
            )
        return payload
