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
from mtmf_service.authentication.development_authority import (
    is_approved_development_authority,
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
    """Keycloak Admin REST reader using a dedicated least-privilege client.

    Authentication is a non-interactive OAuth 2.0 **client-credentials** grant
    for a dedicated service-account client provisioned read-only roles
    (``view-realm``/``view-clients``/``query-clients``). No human/admin password
    grant, no anonymous request, and no fallback exist. Both the token response
    and every configuration response are read with a hard byte bound, redirects
    are rejected, and the token endpoint must be the configured loopback issuer.
    """

    def __init__(
        self,
        base_url: str,
        realm: str,
        client_id: str,
        client_secret: str,
        *,
        timeout: float = 5.0,
        max_bytes: int = 262144,
        opener: Any | None = None,
    ) -> None:
        if not client_id or not client_secret:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE,
                "the attestation reader client credential is not configured",
            )
        if not is_approved_development_authority(base_url, require_https=True):
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE,
                "the attestation reader requires the approved development HTTPS authority",
            )
        if not realm:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE,
                "the attestation realm is not configured",
            )
        if timeout <= 0 or max_bytes <= 0:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "invalid attestation reader bounds"
            )
        self._base = base_url.rstrip("/")
        self._realm = realm
        self._client_id = client_id
        self._client_secret = client_secret
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._opener = opener or urllib.request.build_opener(_NoRedirectHandler())

    def _open(self, request: urllib.request.Request) -> Any:
        """Open only an https request through the redirect-rejecting opener."""
        parsed = urllib.parse.urlparse(request.full_url)
        if parsed.scheme != "https":
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "unsupported admin URL scheme"
            )
        return self._opener.open(request, timeout=self._timeout)

    def _read(self, request: urllib.request.Request, *, what: str) -> Any:
        """Perform one bounded, redirect-free read and parse strict JSON."""
        try:
            with self._open(request) as response:
                payload = response.read(self._max_bytes + 1)
        except AuthenticationError:
            raise
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, f"{what} failed"
            ) from exc
        if len(payload) > self._max_bytes:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, f"{what} exceeded the size bound"
            )
        try:
            return json.loads(payload, object_pairs_hook=_reject_duplicate_pairs)
        except AuthenticationError:
            raise
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, f"{what} was malformed"
            ) from exc

    def _token(self) -> str:
        data = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
        ).encode()
        request = urllib.request.Request(
            f"{self._base}/realms/{self._realm}/protocol/openid-connect/token",
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        payload = self._read(request, what="attestation credential request")
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token or len(token.encode()) > self._max_bytes:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, "attestation credential failed"
            )
        return token

    def get(self, path: str) -> Any:
        request = urllib.request.Request(
            f"{self._base}{path}",
            headers={"Authorization": f"Bearer {self._token()}", "Accept": "application/json"},
        )
        return self._read(request, what="live configuration read")


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE,
                "duplicate JSON member in attestation document",
            )
        result[key] = value
    return result


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


#: Exact fields produced by ``canonical_client_projection`` and therefore
#: required (no more, no less) on every approved policy entry.
_CLIENT_ENTRY_FIELDS = frozenset(
    {
        *_CLIENT_FIELDS,
        *_CLIENT_LIST_FIELDS,
        "defaultClientScopes",
        "optionalClientScopes",
        "protocolMappers",
    }
)
_MAPPER_FIELDS = frozenset({"name", "protocolMapper", "config"})
_BOOL_CLIENT_FIELDS = (
    "enabled",
    "publicClient",
    "serviceAccountsEnabled",
    "standardFlowEnabled",
    "directAccessGrantsEnabled",
    "implicitFlowEnabled",
)
_STRING_CLIENT_FIELDS = ("clientId", "protocol", "clientAuthenticatorType")
_LIST_CLIENT_FIELDS = (
    "redirectUris",
    "webOrigins",
    "defaultClientScopes",
    "optionalClientScopes",
)


def _reject_duplicate_policy_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while rejecting duplicate member names."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExpectedClientPolicyError(f"duplicate JSON member {key!r} in policy")
        result[key] = value
    return result


def _validate_mapper(mapper: Any) -> None:
    """Validate one protocol-mapper entry against the exact projected shape."""
    if not isinstance(mapper, dict) or set(mapper) != _MAPPER_FIELDS:
        raise ExpectedClientPolicyError(
            "each policy mapper must have exactly name/protocolMapper/config"
        )
    for field in ("name", "protocolMapper"):
        value = mapper[field]
        if not isinstance(value, str) or not value:
            raise ExpectedClientPolicyError(f"policy mapper {field} must be a non-empty string")
    config = mapper["config"]
    if not isinstance(config, dict):
        raise ExpectedClientPolicyError("policy mapper config must be an object")
    for key, value in config.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ExpectedClientPolicyError("policy mapper config must map strings to strings")


def _validate_client_entry(entry: Any) -> dict[str, Any]:
    """Validate one approved client entry against the exact projected schema."""
    if not isinstance(entry, dict):
        raise ExpectedClientPolicyError("each expected client must be an object")
    if set(entry) != _CLIENT_ENTRY_FIELDS:
        raise ExpectedClientPolicyError(
            "expected client fields must exactly match the canonical projection"
        )
    for field in _STRING_CLIENT_FIELDS:
        value = entry[field]
        if not isinstance(value, str) or not value:
            raise ExpectedClientPolicyError(f"expected client {field} must be a non-empty string")
    for field in _BOOL_CLIENT_FIELDS:
        if type(entry[field]) is not bool:
            raise ExpectedClientPolicyError(f"expected client {field} must be a JSON boolean")
    for field in _LIST_CLIENT_FIELDS:
        value = entry[field]
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value
        ):
            raise ExpectedClientPolicyError(
                f"expected client {field} must be a list of non-empty strings"
            )
        if len(set(value)) != len(value):
            raise ExpectedClientPolicyError(f"expected client {field} must not contain duplicates")
    mappers = entry["protocolMappers"]
    if not isinstance(mappers, list):
        raise ExpectedClientPolicyError("expected client protocolMappers must be a list")
    seen: set[tuple[str, str]] = set()
    for mapper in mappers:
        _validate_mapper(mapper)
        identity = (mapper["name"], mapper["protocolMapper"])
        if identity in seen:
            raise ExpectedClientPolicyError("expected client contains a duplicate mapper identity")
        seen.add(identity)
    return dict(entry)


@dataclass(frozen=True)
class ExpectedClientPolicy:
    """An immutable, independently approved expected-client policy."""

    entries: Mapping[str, Mapping[str, Any]]

    @classmethod
    def load(cls, path: str) -> ExpectedClientPolicy:
        """Load and strictly validate a policy file.

        :raises ExpectedClientPolicyError: on unreadable, malformed,
            duplicate-member, unsupported-version, duplicate-id, invalid
            field/value/type, or duplicate-identity content.
        """
        try:
            text = Path(path).read_text(encoding="utf-8")
            payload = json.loads(text, object_pairs_hook=_reject_duplicate_policy_pairs)
        except ExpectedClientPolicyError:
            raise
        except (OSError, ValueError) as exc:
            raise ExpectedClientPolicyError("expected-client policy is unreadable") from exc
        if not isinstance(payload, dict) or set(payload) != {"version", "clients"}:
            raise ExpectedClientPolicyError(
                "expected-client policy must have exactly 'version' and 'clients'"
            )
        if payload["version"] != _SUPPORTED_POLICY_VERSION:
            raise ExpectedClientPolicyError(
                f"expected-client policy version must be {_SUPPORTED_POLICY_VERSION}"
            )
        clients = payload["clients"]
        if not isinstance(clients, list) or not clients:
            raise ExpectedClientPolicyError("expected-client policy must list clients")
        entries: dict[str, Mapping[str, Any]] = {}
        for entry in clients:
            validated = _validate_client_entry(entry)
            client_id = validated["clientId"]
            if client_id in entries:
                raise ExpectedClientPolicyError(f"duplicate expected clientId {client_id!r}")
            entries[client_id] = MappingProxyType(validated)
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
            payload = json.loads(
                Path(path).read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_pairs,
            )
        except AuthenticationError as exc:
            raise AuthenticationError(
                AuthenticationFailure.ATTESTATION_UNAVAILABLE, f"{label} is malformed"
            ) from exc
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
