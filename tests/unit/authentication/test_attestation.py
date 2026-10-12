"""Unit tests for the shipped configuration attestation classes.

Only the external Admin REST reader is faked; ``canonical_manifest`` and
``BaselineConfigurationAttestor`` are the production classes.
"""

from __future__ import annotations

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
    canonical_manifest,
    manifest_hash,
)

REALM = "mtmf-pr14-dev"
PROFILE = IssuerProfile(
    issuer=f"https://127.0.0.1:28443/realms/{REALM}",
    audience="mtmf-service-api",
    jwks_uri=f"https://127.0.0.1:28443/realms/{REALM}/protocol/openid-connect/certs",
)


class FakeReader:
    """Controllable Admin REST reader covering the manifest paths."""

    def __init__(
        self,
        *,
        clients: list[dict[str, Any]],
        scopes: list[dict[str, Any]],
        default_scopes: dict[str, list[str]] | None = None,
        optional_scopes: dict[str, list[str]] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.clients = clients
        self.scopes = scopes
        self.default_scopes = default_scopes or {}
        self.optional_scopes = optional_scopes or {}
        self.error = error
        self.calls = 0

    def get(self, path: str) -> Any:
        self.calls += 1
        if self.error is not None:
            raise self.error
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
                for client in self.clients:
                    if client["id"] == uuid:
                        return client.get("protocolMappers", [])
        if "/client-scopes/" in path and path.endswith("/protocol-mappers/models"):
            scope_id = path.split("/client-scopes/")[1].split("/")[0]
            for scope in self.scopes:
                if scope["id"] == scope_id:
                    return scope.get("protocolMappers", [])
        raise AssertionError(f"unexpected path {path}")


def _client(**overrides: Any) -> dict[str, Any]:
    client = {
        "id": "client-uuid-1",
        "clientId": "mtmf-evidence-user",
        "enabled": True,
        "publicClient": False,
        "serviceAccountsEnabled": False,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "implicitFlowEnabled": False,
        "protocolMappers": [
            {
                "name": "aud-mtmf-user-api",
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": "mtmf-user-api"},
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
    return FakeReader(
        clients=clients,
        scopes=scopes,
        default_scopes={"client-uuid-1": ["service_account"]},
        **kwargs,
    )


def _baseline(tmp_path: Path, manifest: dict[str, Any]) -> str:
    path = tmp_path / "expected.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return str(path)


def test_canonical_manifest_is_deterministic_and_sorted():
    reader = _reader()
    first = canonical_manifest(reader, REALM)
    assert first["clients"][0]["clientId"] == "mtmf-evidence-user"
    assert first["clientScopes"][0]["name"] == "service_account"
    assert manifest_hash(first) == manifest_hash(canonical_manifest(reader, REALM))


def test_attestation_succeeds_on_matching_baseline(tmp_path: Path):
    reader = _reader()
    baseline = _baseline(tmp_path, canonical_manifest(reader, REALM))
    BaselineConfigurationAttestor(reader, REALM, baseline).attest(PROFILE)


def test_missing_and_malformed_baseline_fail_closed(tmp_path: Path):
    reader = _reader()
    with pytest.raises(AuthenticationError) as missing:
        BaselineConfigurationAttestor(reader, REALM, str(tmp_path / "absent.json")).attest(PROFILE)
    assert missing.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE
    bad = tmp_path / "bad.json"
    bad.write_text("not json")
    with pytest.raises(AuthenticationError) as malformed:
        BaselineConfigurationAttestor(reader, REALM, str(bad)).attest(PROFILE)
    assert malformed.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


@pytest.mark.parametrize(
    "mutate",
    [
        lambda clients, scopes: clients[0].update({"standardFlowEnabled": False}),
        lambda clients, scopes: clients[0]["protocolMappers"].append(
            {
                "name": "spoof-client-id",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {"claim.name": "client_id", "claim.value": "evil"},
            }
        ),
        lambda clients, scopes: clients[0]["protocolMappers"][0]["config"].update(
            {"included.custom.audience": "other-audience"}
        ),
    ],
)
def test_client_drift_is_detected(tmp_path: Path, mutate: Any):
    reader = _reader()
    baseline = _baseline(tmp_path, canonical_manifest(reader, REALM))
    evolve = _reader()
    mutate(evolve.clients, evolve.scopes)
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(evolve, REALM, baseline).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_scope_and_mapper_drift_is_detected(tmp_path: Path):
    reader = _reader()
    baseline = _baseline(tmp_path, canonical_manifest(reader, REALM))
    changed = _reader()
    changed.scopes[0]["protocolMappers"].append(
        {
            "name": "scope-spoof-azp",
            "protocolMapper": "oidc-hardcoded-claim-mapper",
            "config": {"claim.name": "azp", "claim.value": "service"},
        }
    )
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(changed, REALM, baseline).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_reader_error_and_transport_failure_fail_closed(tmp_path: Path):
    reader = _reader()
    baseline = _baseline(tmp_path, canonical_manifest(reader, REALM))
    broken = _reader(error=RuntimeError("connection reset"))
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(broken, REALM, baseline).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_UNAVAILABLE


def test_attestation_never_reuses_a_prior_success(tmp_path: Path):
    reader = _reader()
    baseline = _baseline(tmp_path, canonical_manifest(reader, REALM))
    attestor = BaselineConfigurationAttestor(reader, REALM, baseline)
    attestor.attest(PROFILE)
    first_calls = reader.calls
    reader.clients[0]["standardFlowEnabled"] = False
    with pytest.raises(AuthenticationError) as exc:
        attestor.attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT
    assert reader.calls > first_calls


def test_equivalent_order_is_accepted(tmp_path: Path):
    reader = _reader()
    baseline = _baseline(tmp_path, canonical_manifest(reader, REALM))
    reordered = _reader(clients=[_client()])
    reordered.clients[0]["protocolMappers"] = list(
        reversed(reordered.clients[0]["protocolMappers"])
    )
    BaselineConfigurationAttestor(reordered, REALM, baseline).attest(PROFILE)


def _two_client_reader() -> FakeReader:
    return FakeReader(
        clients=[
            _client(id="uuid-a", clientId="client-a"),
            _client(id="uuid-b", clientId="client-b"),
        ],
        scopes=[_scope()],
        default_scopes={"uuid-a": ["service_account"], "uuid-b": ["service_account"]},
    )


def test_at03_unknown_extra_client_is_rejected(tmp_path: Path):
    """A client the baseline does not approve makes the whole configuration drift."""
    baseline = _baseline(tmp_path, canonical_manifest(_reader(), REALM))
    extra = FakeReader(
        clients=[
            _client(),
            _client(id="uuid-sample", clientId="mtmf-sample-app"),
        ],
        scopes=[_scope()],
        default_scopes={"client-uuid-1": ["service_account"], "uuid-sample": []},
    )
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(extra, REALM, baseline).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_at13_two_clients_are_independently_bound(tmp_path: Path):
    """Mutating either approved client independently fails the whole attestation."""
    baseline = _baseline(tmp_path, canonical_manifest(_two_client_reader(), REALM))
    BaselineConfigurationAttestor(_two_client_reader(), REALM, baseline).attest(PROFILE)
    drifted = _two_client_reader()
    drifted.clients[1]["standardFlowEnabled"] = False
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(drifted, REALM, baseline).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT


def test_at04_duplicate_client_identity_is_detected_as_drift(tmp_path: Path):
    """A duplicated client record cannot match a single-entry baseline.

    The current verifier has no explicit duplicate-id guard; it detects the
    duplicate as a structural list difference. Explicit duplicate rejection is
    a D2 design item, so this test only characterizes today's fail-closed
    behaviour.
    """
    baseline = _baseline(tmp_path, canonical_manifest(_reader(), REALM))
    duplicated = FakeReader(
        clients=[_client(), _client()],
        scopes=[_scope()],
        default_scopes={"client-uuid-1": ["service_account"]},
    )
    with pytest.raises(AuthenticationError) as exc:
        BaselineConfigurationAttestor(duplicated, REALM, baseline).attest(PROFILE)
    assert exc.value.failure is AuthenticationFailure.ATTESTATION_DRIFT
