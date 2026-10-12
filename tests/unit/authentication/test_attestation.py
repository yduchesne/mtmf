"""Unit tests for the approved realm + expected-client attestation classes.

Only the external Admin REST reader is faked; ``canonical_manifest``,
``canonical_client_projection``, ``ExpectedClientPolicy`` and
``BaselineConfigurationAttestor`` are the production classes.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from mtmf_core.authentication.contracts import (
    AuthenticationError,
    AuthenticationFailure,
    IssuerProfile,
)
from mtmf_service.authentication.attestation import (
    BaselineConfigurationAttestor,
    ExpectedClientPolicy,
    ExpectedClientPolicyError,
    canonical_client_projection,
    canonical_manifest,
    manifest_hash,
)

REALM = "mtmf-pr14-dev"
PROFILE = IssuerProfile(
    issuer=f"https://127.0.0.1:28443/realms/{REALM}",
    audience="mtmf-service-api",
    jwks_uri=f"https://127.0.0.1:28443/realms/{REALM}/protocol/openid-connect/certs",
)

_CLIENT_A = "mtmf-evidence-same-client"
_CLIENT_B = "mtmf-evidence-same-client-b"


class FakeReader:
    """Controllable Admin REST reader covering the projected paths."""

    def __init__(
        self,
        *,
        realm: dict[str, Any],
        clients: list[dict[str, Any]],
        scopes: list[dict[str, Any]],
        default_scopes: dict[str, list[str]] | None = None,
        optional_scopes: dict[str, list[str]] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.realm = realm
        self.clients = clients
        self.scopes = scopes
        self.default_scopes = default_scopes or {}
        self.optional_scopes = optional_scopes or {}
        self.error = error
        self.calls = 0

    def _find(self, uuid: str) -> dict[str, Any] | None:
        return next((c for c in self.clients if c["id"] == uuid), None)

    def get(self, path: str) -> Any:
        self.calls += 1
        if self.error is not None:
            raise self.error
        if path == f"/admin/realms/{REALM}":
            return self.realm
        if "?" in path and path.split("?", 1)[0].endswith("/clients"):
            query = path.split("clientId=", 1)[1]
            return [c for c in self.clients if c["clientId"] == query]
        if path.endswith("/clients"):
            return self.clients
        if path.endswith("/client-scopes"):
            return self.scopes
        if "/clients/" in path:
            uuid = path.split("/clients/")[1].split("/")[0]
            if path.endswith("/default-client-scopes"):
                return [{"name": n} for n in self.default_scopes.get(uuid, [])]
            if path.endswith("/optional-client-scopes"):
                return [{"name": n} for n in self.optional_scopes.get(uuid, [])]
            if path.endswith("/protocol-mappers/models"):
                found = self._find(uuid)
                if found is not None:
                    return found.get("protocolMappers", [])
            raise AssertionError(f"unexpected path {path}")
        if "/client-scopes/" in path and path.endswith("/protocol-mappers/models"):
            scope_id = path.split("/client-scopes/")[1].split("/")[0]
            for scope in self.scopes:
                if scope["id"] == scope_id:
                    return scope.get("protocolMappers", [])
        raise AssertionError(f"unexpected path {path}")


def _realm(**overrides: Any) -> dict[str, Any]:
    realm = {
        "realm": REALM,
        "enabled": True,
        "sslRequired": "none",
        "defaultSignatureAlgorithm": "RS256",
        "accessTokenLifespan": 300,
        "accessTokenLifespanForImplicitFlow": 900,
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 3600,
        "offlineSessionIdleTimeout": 2592000,
        "browserFlow": "browser",
        "registrationFlow": "registration",
        "directGrantFlow": "direct grant",
        "resetCredentialsFlow": "reset credentials",
        "clientAuthenticationFlow": "clients",
        "dockerAuthenticationFlow": "docker auth",
        "firstBrokerLoginFlow": "first broker login",
        "revokeRefreshToken": False,
        "refreshTokenMaxReuse": 0,
        "notBefore": 0,
    }
    realm.update(overrides)
    return realm


def _client(client_id: str = _CLIENT_A, uuid: str = "uuid-a", **overrides: Any) -> dict[str, Any]:
    client = {
        "id": uuid,
        "clientId": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "clientAuthenticatorType": "client-secret",
        "publicClient": False,
        "serviceAccountsEnabled": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "redirectUris": ["http://127.0.0.1:28400/callback"],
        "webOrigins": [],
        "protocolMappers": [
            {
                "name": "aud-mtmf-same-client-api",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": "mtmf-same-client-api"},
            }
        ],
    }
    client.update(overrides)
    return client


def _scope() -> dict[str, Any]:
    return {
        "id": "scope-uuid-1",
        "name": "service_account",
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "false"},
        "protocolMappers": [
            {
                "name": "Client ID",
                "protocolMapper": "oidc-usersessionmodel-note-mapper",
                "config": {"user.session.note": "client_id"},
            }
        ],
    }


def _reader(**kwargs: Any) -> FakeReader:
    clients = kwargs.pop("clients", [_client()])
    scopes = kwargs.pop("scopes", [_scope()])
    realm = kwargs.pop("realm", _realm())
    default_scopes = kwargs.pop("default_scopes", {c["id"]: ["service_account"] for c in clients})
    return FakeReader(
        realm=realm, clients=clients, scopes=scopes, default_scopes=default_scopes, **kwargs
    )


def _write(tmp_path: Path, name: str, payload: dict[str, Any]) -> str:
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def _policy_for(reader: FakeReader, client_ids: list[str]) -> dict[str, Any]:
    entries = []
    for client_id in client_ids:
        client = next(c for c in reader.clients if c["clientId"] == client_id)
        entries.append(canonical_client_projection(reader, REALM, client))
    return {"version": 1, "clients": entries}


def _baseline(tmp_path: Path, reader: FakeReader) -> str:
    return _write(tmp_path, "expected.json", canonical_manifest(reader, REALM))


def _policy(tmp_path: Path, reader: FakeReader, client_ids: list[str]) -> str:
    return _write(tmp_path, "policy.json", _policy_for(reader, client_ids))


# -- realm projection ---------------------------------------------------------


def test_canonical_manifest_is_deterministic_and_includes_realm_security():
    reader = _reader()
    first = canonical_manifest(reader, REALM)
    assert first["realmSecurity"]["enabled"] is True
    assert first["realmSecurity"]["accessTokenLifespan"] == 300
    assert first["clientScopes"][0]["name"] == "service_account"
    assert "clients" not in first  # unrelated clients are not part of the projection
    assert manifest_hash(first) == manifest_hash(canonical_manifest(reader, REALM))


def test_realm_attestation_succeeds_on_matching_baseline(tmp_path: Path):
    reader = _reader()
    BaselineConfigurationAttestor(
        reader, REALM, _baseline(tmp_path, reader), _policy(tmp_path, reader, [_CLIENT_A])
    ).attest(PROFILE)


def test_missing_and_malformed_baseline_fail_closed(tmp_path: Path):
    reader = _reader()
    policy = _policy(tmp_path, reader, [_CLIENT_A])
    with pytest.raises(AuthenticationError) as missing:
        BaselineConfigurationAttestor(reader, REALM, str(tmp_path / "absent.json"), policy).attest(
            PROFILE
        )
    assert missing.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    with pytest.raises(AuthenticationError) as malformed:
        BaselineConfigurationAttestor(reader, REALM, str(bad), policy).attest(PROFILE)
    assert malformed.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


@pytest.mark.parametrize(
    "mutate",
    [
        lambda realm: realm.update({"enabled": False}),
        lambda realm: realm.update({"sslRequired": "external"}),
        lambda realm: realm.update({"accessTokenLifespan": 60}),
        lambda realm: realm.update({"defaultSignatureAlgorithm": "HS256"}),
        lambda realm: realm.update({"browserFlow": "evil"}),
        lambda realm: realm.update({"notBefore": 1234}),
    ],
)
def test_realm_security_drift_is_detected(tmp_path: Path, mutate: Any):
    reader = _reader()
    baseline = _baseline(tmp_path, reader)
    policy = _policy(tmp_path, reader, [_CLIENT_A])
    evolved = _reader()
    mutate(evolved.realm)
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(evolved, REALM, baseline, policy).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_client_scope_mapper_drift_is_detected(tmp_path: Path):
    reader = _reader()
    baseline = _baseline(tmp_path, reader)
    policy = _policy(tmp_path, reader, [_CLIENT_A])
    changed = _reader()
    changed.scopes[0]["protocolMappers"].append(
        {
            "name": "scope-spoof-azp",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {"claim.name": "azp", "claim.value": "service"},
        }
    )
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(changed, REALM, baseline, policy).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_attestation_never_reuses_a_prior_success(tmp_path: Path):
    reader = _reader()
    baseline = _baseline(tmp_path, reader)
    policy = _policy(tmp_path, reader, [_CLIENT_A])
    attestor = BaselineConfigurationAttestor(reader, REALM, baseline, policy)
    attestor.attest(PROFILE)
    first_calls = reader.calls
    reader.realm["accessTokenLifespan"] = 60
    with pytest.raises(AuthenticationError) as exc:
        attestor.attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT
    assert reader.calls > first_calls


def test_reader_transport_failure_fail_closed(tmp_path: Path):
    reader = _reader()
    baseline = _baseline(tmp_path, reader)
    policy = _policy(tmp_path, reader, [_CLIENT_A])
    broken = _reader(error=RuntimeError("connection reset"))
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(broken, REALM, baseline, policy).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


# -- expected-client policy ---------------------------------------------------


def test_attest_client_succeeds_for_approved_client(tmp_path: Path):
    reader = _reader()
    BaselineConfigurationAttestor(
        reader, REALM, _baseline(tmp_path, reader), _policy(tmp_path, reader, [_CLIENT_A])
    ).attest_client(PROFILE, _CLIENT_A)


def test_attest_client_rejects_unapproved_client(tmp_path: Path):
    reader = _reader()
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(
            reader, REALM, _baseline(tmp_path, reader), _policy(tmp_path, reader, [_CLIENT_A])
        ).attest_client(PROFILE, "mtmf-sample-app")
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_attest_client_rejects_duplicate_client_id(tmp_path: Path):
    reader = _reader()
    policy = _policy(tmp_path, reader, [_CLIENT_A])
    duplicated = _reader(clients=[_client(), _client(uuid="uuid-a2")])
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(
            duplicated, REALM, _baseline(tmp_path, reader), policy
        ).attest_client(PROFILE, _CLIENT_A)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


@pytest.mark.parametrize(
    "mutate",
    [
        lambda client: client.update({"enabled": False}),
        lambda client: client.update({"standardFlowEnabled": False}),
        lambda client: client.update({"clientAuthenticatorType": "none"}),
        lambda client: client.update({"publicClient": True}),
        lambda client: client["protocolMappers"][0]["config"].update(
            {"included.custom.audience": "other"}
        ),
        lambda client: client["protocolMappers"].append(
            {
                "name": "spoof-client-id",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {"claim.name": "client_id", "claim.value": "evil"},
            }
        ),
    ],
)
def test_attest_client_detects_security_field_drift(tmp_path: Path, mutate: Any):
    reader = _reader()
    baseline = _baseline(tmp_path, reader)
    policy = _policy(tmp_path, reader, [_CLIENT_A])
    evolved = _reader()
    mutate(evolved.clients[0])
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(evolved, REALM, baseline, policy).attest_client(
            PROFILE, _CLIENT_A
        )
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_two_clients_are_independently_bound(tmp_path: Path):
    reader = _reader(
        clients=[
            _client(_CLIENT_A, "uuid-a"),
            _client(_CLIENT_B, "uuid-b"),
        ]
    )
    baseline = _baseline(tmp_path, reader)
    policy = _policy(tmp_path, reader, [_CLIENT_A, _CLIENT_B])
    attestor = BaselineConfigurationAttestor(reader, REALM, baseline, policy)
    attestor.attest(PROFILE)
    attestor.attest_client(PROFILE, _CLIENT_A)
    attestor.attest_client(PROFILE, _CLIENT_B)
    drifted = _reader(clients=[_client(_CLIENT_A, "uuid-a"), _client(_CLIENT_B, "uuid-b")])
    drifted.clients[1]["standardFlowEnabled"] = False
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(drifted, REALM, baseline, policy).attest_client(
            PROFILE, _CLIENT_B
        )
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_u11_duplicate_json_member_in_policy_rejected(tmp_path: Path):
    path = tmp_path / "dup.json"
    path.write_text('{"version":1,"version":1,"clients":[]}', encoding="utf-8")
    with pytest.raises(ExpectedClientPolicyError):
        ExpectedClientPolicy.load(str(path))


def test_u12_missing_and_extra_client_fields_rejected(tmp_path: Path):
    reader = _reader()
    base = _policy_for(reader, [_CLIENT_A])["clients"][0]
    for mutate in (
        lambda c: c.pop("enabled"),
        lambda c: c.update({"unexpected": 1}),
    ):
        entry = copy.deepcopy(base)
        mutate(entry)
        path = _write(tmp_path, "p.json", {"version": 1, "clients": [entry]})
        with pytest.raises(ExpectedClientPolicyError):
            ExpectedClientPolicy.load(path)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update({"enabled": 1}),
        lambda c: c.update({"enabled": "true"}),
        lambda c: c.update({"protocol": ""}),
        lambda c: c.update({"redirectUris": "http://x"}),
        lambda c: c.update({"redirectUris": [1]}),
        lambda c: c.update({"defaultClientScopes": ["a", "a"]}),
        lambda c: c.update({"protocolMappers": [{"name": "x"}]}),
        lambda c: c["protocolMappers"][0]["config"].update({"k": None}),
    ],
)
def test_u13_wrong_types_rejected(tmp_path: Path, mutate: Any):
    reader = _reader()
    entry = copy.deepcopy(_policy_for(reader, [_CLIENT_A])["clients"][0])
    mutate(entry)
    path = _write(tmp_path, "p.json", {"version": 1, "clients": [entry]})
    with pytest.raises(ExpectedClientPolicyError):
        ExpectedClientPolicy.load(path)


def test_u11_duplicate_mapper_identity_rejected(tmp_path: Path):
    reader = _reader()
    entry = copy.deepcopy(_policy_for(reader, [_CLIENT_A])["clients"][0])
    entry["protocolMappers"] = [entry["protocolMappers"][0], dict(entry["protocolMappers"][0])]
    path = _write(tmp_path, "p.json", {"version": 1, "clients": [entry]})
    with pytest.raises(ExpectedClientPolicyError):
        ExpectedClientPolicy.load(path)


def test_u14_unsupported_version_and_empty_id_rejected(tmp_path: Path):
    reader = _reader()
    entry = copy.deepcopy(_policy_for(reader, [_CLIENT_A])["clients"][0])
    for payload in ({"version": 2, "clients": [entry]}, {"version": 1, "clients": []}):
        path = _write(tmp_path, "p.json", payload)
        with pytest.raises(ExpectedClientPolicyError):
            ExpectedClientPolicy.load(path)
    entry_empty = copy.deepcopy(entry)
    entry_empty["clientId"] = ""
    path = _write(tmp_path, "p2.json", {"version": 1, "clients": [entry_empty]})
    with pytest.raises(ExpectedClientPolicyError):
        ExpectedClientPolicy.load(path)


def test_u25_read_skew_in_client_projection_is_detected(tmp_path: Path):
    """A read that changes mid-request must fail the final comparison."""
    reader = _reader()
    baseline = _baseline(tmp_path, reader)
    policy = _policy(tmp_path, reader, [_CLIENT_A])
    skew = _reader()
    original_get = skew.get
    state = {"client_reads": 0}

    def skewed_get(path: str) -> Any:
        value = original_get(path)
        if path.endswith("/protocol-mappers/models") and "client-scopes" not in path:
            state["client_reads"] += 1
            if state["client_reads"] >= 1:
                return [*value, {"name": "late", "protocolMapper": "x", "config": {}}]
        return value

    skew.get = skewed_get  # type: ignore[method-assign]
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(skew, REALM, baseline, policy).attest_client(
            PROFILE, _CLIENT_A
        )
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_policy_validation_fails_closed(tmp_path: Path):
    good = _reader()
    with pytest.raises(ExpectedClientPolicyError):
        ExpectedClientPolicy.load(str(tmp_path / "absent.json"))
    for payload in (
        {"clients": []},
        {"version": 99, "clients": [{"clientId": "x"}]},
        {"version": 1, "clients": []},
        {"version": 1, "clients": [{"clientId": "x"}, {"clientId": "x"}]},
        {"version": 1, "clients": ["not-an-object"]},
    ):
        path = _write(tmp_path, "bad-policy.json", payload)
        with pytest.raises(ExpectedClientPolicyError):
            ExpectedClientPolicy.load(path)
    # A malformed policy fails closed at attestation time.
    reader = good
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(
            reader, REALM, _baseline(tmp_path, reader), str(tmp_path / "absent.json")
        ).attest_client(PROFILE, _CLIENT_A)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE
