"""Fresh, zero-cache issuer-configuration attestation (development-only).

The trusted expectations are two **independently maintained, committed
reviewed artifacts**:

- a *realm-security projection* baseline (realm-wide settings plus
  realm-level client scopes) in ``expected-config-manifest.json``; and
- an *expected-client policy* (``expected-client-policy.json``) enumerating
  each client admitted into MTMF's authenticated D1 path with its exact
  security-relevant effective configuration.

Every ``attest``/``attest_client`` call performs a fresh live Admin REST read
and a full canonical comparison; a prior success, startup check, or persisted
record never authorizes a later operation. Neither expectation is ever
generated from, or reconciled to, live Keycloak state; the initializer may
create a client only when it matches the approved policy exactly.

The realm projection deliberately does **not** compare the set of unrelated
realm clients. Unrelated clients cannot be admitted because MTMF resolves the
authenticated client from verified signed claims and requires an exact
approved policy entry; a token from any other client fails closed.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    IssuerProfile,
)

__all__ = [
    "AdminRestReader",
    "BaselineConfigurationAttestor",
    "ExpectedClientPolicy",
    "ExpectedClientPolicyError",
    "HttpAdminRestReader",
    "canonical_client_projection",
    "canonical_manifest",
    "manifest_hash",
    "realm_security_projection",
]

#: Realm-representation fields that can affect token issuance, class,
#: lifetimes, revocation or signing trust. Only these are projected; the
#: full realm representation (hundreds of presentation fields) is not.
_REALM_SECURITY_FIELDS = (
    "enabled",
    "sslRequired",
    "defaultSignatureAlgorithm",
    "accessTokenLifespan",
    "accessTokenLifespanForImplicitFlow",
    "ssoSessionIdleTimeout",
    "ssoSessionMaxLifespan",
    "offlineSessionIdleTimeout",
    "browserFlow",
    "registrationFlow",
    "directGrantFlow",
    "resetCredentialsFlow",
    "clientAuthenticationFlow",
    "dockerAuthenticationFlow",
    "firstBrokerLoginFlow",
    "revokeRefreshToken",
    "refreshTokenMaxReuse",
    "notBefore",
)

_CLIENT_FIELDS = (
    "clientId",
    "enabled",
    "protocol",
    "clientAuthenticatorType",
    "publicClient",
    "serviceAccountsEnabled",
    "standardFlowEnabled",
    "directAccessGrantsEnabled",
    "implicitFlowEnabled",
)

_CLIENT_LIST_FIELDS = ("redirectUris", "webOrigins")

_SUPPORTED_POLICY_VERSION = 1


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


def realm_security_projection(realm: Mapping[str, Any]) -> dict[str, Any]:
    """Project only security-relevant realm-representation fields."""
    return {field: realm.get(field) for field in _REALM_SECURITY_FIELDS}


def _scope_projection(scope: Mapping[str, Any], mappers: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": scope.get("name"),
        "protocol": scope.get("protocol"),
        "attributes": {
            str(k): str(v)
            for k, v in sorted((scope.get("attributes") or {}).items())
            if v is not None
        },
        "protocolMappers": _normalize_mappers(mappers),
    }


def canonical_manifest(reader: AdminRestReader, realm: str) -> dict[str, Any]:
    """Build the canonical realm-security manifest from the live realm.

    The unrelated-realm-client set is intentionally **not** included; admitted
    clients are verified independently by :meth:`BaselineConfigurationAttestor.attest_client`.
    """
    try:
        representation = reader.get(f"/admin/realms/{realm}")
    except AuthenticationError:
        raise
    except Exception as exc:
        raise AuthenticationError(
            AuthenticationFailure.ATTESTATION_UNAVAILABLE, "live configuration was unavailable"
        ) from exc
    scopes = []
    for scope in reader.get(f"/admin/realms/{realm}/client-scopes") or []:
        scopes.append(
            _scope_projection(
                scope,
                reader.get(
                    f"/admin/realms/{realm}/client-scopes/{scope['id']}/protocol-mappers/models"
                )
                or [],
            )
        )
    return {
        "realm": realm,
        "realmSecurity": realm_security_projection(representation),
        "clientScopes": sorted(scopes, key=lambda s: str(s["name"])),
    }


def canonical_client_projection(
    reader: AdminRestReader,
    realm: str,
    client: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the canonical effective projection for one live client."""
    uuid = client["id"]
    projection: dict[str, Any] = {field: client.get(field) for field in _CLIENT_FIELDS}
    for field in _CLIENT_LIST_FIELDS:
        projection[field] = sorted(str(value) for value in (client.get(field) or []))
    projection["defaultClientScopes"] = sorted(
        s["name"]
        for s in reader.get(f"/admin/realms/{realm}/clients/{uuid}/default-client-scopes") or []
    )
    projection["optionalClientScopes"] = sorted(
        s["name"]
        for s in reader.get(f"/admin/realms/{realm}/clients/{uuid}/optional-client-scopes") or []
    )
    projection["protocolMappers"] = _normalize_mappers(
        reader.get(f"/admin/realms/{realm}/clients/{uuid}/protocol-mappers/models") or []
    )
    return projection


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


class ExpectedClientPolicyError(ValueError):
    """The independently approved expected-client policy is unusable."""


@dataclass(frozen=True)
class ExpectedClientPolicy:
    """An immutable, independently approved expected-client policy."""

    entries: Mapping[str, Mapping[str, Any]]

    @classmethod
    def load(cls, path: str) -> ExpectedClientPolicy:
        """Load and strictly validate a policy file.

        :raises ExpectedClientPolicyError: on unreadable, malformed,
            unsupported-version, duplicate-id, or invalid-entry content.
        """
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ExpectedClientPolicyError("expected-client policy is unreadable") from exc
        if not isinstance(payload, dict):
            raise ExpectedClientPolicyError("expected-client policy must be a JSON object")
        version = payload.get("version")
        if version != _SUPPORTED_POLICY_VERSION:
            raise ExpectedClientPolicyError(
                f"expected-client policy version must be {_SUPPORTED_POLICY_VERSION}"
            )
        clients = payload.get("clients")
        if not isinstance(clients, list) or not clients:
            raise ExpectedClientPolicyError("expected-client policy must list clients")
        entries: dict[str, Mapping[str, Any]] = {}
        for entry in clients:
            if not isinstance(entry, dict):
                raise ExpectedClientPolicyError("each expected client must be an object")
            client_id = entry.get("clientId")
            if not isinstance(client_id, str) or not client_id:
                raise ExpectedClientPolicyError("each expected client needs a clientId")
            if client_id in entries:
                raise ExpectedClientPolicyError(f"duplicate expected clientId {client_id!r}")
            entries[client_id] = MappingProxyType(dict(entry))
        return cls(MappingProxyType(entries))

    def require(self, client_id: str) -> Mapping[str, Any]:
        """Return the approved entry or fail closed for an unapproved client."""
        try:
            return self.entries[client_id]
        except KeyError as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_DRIFT,
                "the authenticated client is not in the approved expected-client policy",
            ) from exc


class BaselineConfigurationAttestor:
    """Compare fresh live realm/client configuration to reviewed expectations."""

    def __init__(
        self,
        reader: AdminRestReader,
        realm: str,
        baseline_path: str,
        client_policy_path: str,
    ) -> None:
        self._reader = reader
        self._realm = realm
        self._baseline_path = baseline_path
        self._client_policy_path = client_policy_path

    # -- realm projection --------------------------------------------------
    def attest(self, profile: IssuerProfile) -> None:
        """Fail closed unless the live realm projection matches the baseline."""
        del profile  # the profile is validated by construction; realm drives the read
        expected = self._load_json(self._baseline_path, "trusted baseline")
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

    # -- per-admitted-client projection ------------------------------------
    def attest_client(self, profile: IssuerProfile, client_id: str) -> None:
        """Fail closed unless one admitted live client matches its approved entry.

        :raises AuthenticationError: ``ATTESTATION_DRIFT`` for an unapproved,
            missing, or ambiguous client or a field mismatch;
            ``ATTESTATION_UNAVAILABLE`` for an unreadable policy or live read.
        """
        del profile
        policy = self._load_policy()
        expected = policy.require(client_id)
        query = urllib.parse.quote(client_id, safe="")
        try:
            rows = self._reader.get(f"/admin/realms/{self._realm}/clients?clientId={query}")
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE,
                "live client configuration was unavailable",
            ) from exc
        if not isinstance(rows, list) or len(rows) != 1:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_DRIFT,
                "the authenticated client is missing or ambiguous in the live realm",
            )
        try:
            actual = canonical_client_projection(self._reader, self._realm, rows[0])
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE,
                "live client configuration was unavailable",
            ) from exc
        if not _diff(dict(expected), actual):
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_DRIFT,
                "the authenticated client configuration drifted from the approved policy",
            )

    # -- loaders -----------------------------------------------------------
    def _load_json(self, path: str, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, f"{label} is unreadable"
            ) from exc
        if not isinstance(payload, dict):
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, f"{label} is malformed"
            )
        return payload

    def _load_policy(self) -> ExpectedClientPolicy:
        try:
            return ExpectedClientPolicy.load(self._client_policy_path)
        except ExpectedClientPolicyError as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE,
                "the approved expected-client policy is unusable",
            ) from exc
