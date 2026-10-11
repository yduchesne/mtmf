#!/usr/bin/env python3
"""PR 14 G0-A remediation — Keycloak mapper lockdown and attestation.

Development-fixture-only evidence tooling. It builds a canonical,
security-relevant manifest of the isolated Keycloak realm's client-scope,
client, grant and protocol-mapper configuration, compares the live realm
against a trusted expected manifest, and runs the R01-R12 adversarial matrix.
It contains no MTMF production verifier code and never prints secrets or raw
tokens.

Subcommands::

    manifest --out FILE                 # build canonical manifest from the live realm
    attest --expected FILE [--record FILE] [--max-age-seconds N] [--check-record]
    matrix --expected FILE --report FILE

The expected manifest is a reviewed repository artifact; ``attest`` never
learns the baseline from the live realm.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# --- evidence module (token issuance, verification, class predicates) --------
_EVIDENCE = Path(__file__).resolve().parent / "pr14-keycloak-evidence.py"
_spec = importlib.util.spec_from_file_location("pr14_keycloak_evidence", _EVIDENCE)
assert _spec is not None and _spec.loader is not None
ev = importlib.util.module_from_spec(_spec)
sys.modules["pr14_keycloak_evidence"] = ev
_spec.loader.exec_module(ev)

DEFAULT_BASE = "https://127.0.0.1:28443"
DEFAULT_REALM = "mtmf-pr14-dev"
REDIRECT_URI = "http://127.0.0.1:28400/callback"
SECRETS = {
    "service": "mtmf-evidence-service-dev-secret",
    "user": "mtmf-evidence-user-dev-secret",
    "same": "mtmf-evidence-same-client-dev-secret",
    "svc_cross": "mtmf-evidence-service-cross-dev-secret",
    "user_cross": "mtmf-evidence-user-cross-dev-secret",
}

#: Fields of the security-relevant manifest. Instance-generated UUIDs, realm
#: signing keys and secrets are intentionally excluded (see the report).
CLIENT_FIELDS = (
    "enabled",
    "publicClient",
    "serviceAccountsEnabled",
    "standardFlowEnabled",
    "directAccessGrantsEnabled",
    "implicitFlowEnabled",
)


class AttestationError(RuntimeError):
    """The live issuer configuration could not be read or attested."""


class Admin:
    """Minimal Admin REST client for the isolated fixture."""

    def __init__(self, base: str, realm: str, token: str, context: Any) -> None:
        self.base = base.rstrip("/")
        self.realm = realm
        self._token = token
        self._context = context

    def request(self, method: str, path: str, body: Any | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"{self.base}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, context=self._context) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            raise AttestationError(f"admin {method} {path}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise AttestationError(f"admin {method} {path}: {type(exc).__name__}") from exc
        return json.loads(payload) if payload else None

    # -- lookups -----------------------------------------------------------
    def find_client(self, client_id: str) -> dict[str, Any]:
        rows = self.request("GET", f"/admin/realms/{self.realm}/clients?clientId={client_id}")
        if not rows:
            raise AttestationError(f"client {client_id} not found")
        return rows[0]

    def find_client_scope(self, name: str) -> dict[str, Any]:
        for scope in self.request("GET", f"/admin/realms/{self.realm}/client-scopes") or []:
            if scope.get("name") == name:
                return scope
        raise AttestationError(f"client scope {name} not found")

    # -- mutations (used only by the R matrix) -----------------------------
    def add_hardcoded_mapper(self, owner: str, name: str, claim: str, value: str) -> None:
        self.request(
            "POST",
            f"/admin/realms/{self.realm}/{owner}/protocol-mappers/models",
            {
                "name": name,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {
                    "claim.name": claim,
                    "claim.value": value,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            },
        )

    def delete_mapper(self, owner: str, name: str) -> None:
        for mapper in (
            self.request("GET", f"/admin/realms/{self.realm}/{owner}/protocol-mappers/models") or []
        ):
            if mapper.get("name") == name:
                self.request(
                    "DELETE",
                    f"/admin/realms/{self.realm}/{owner}/protocol-mappers/models/{mapper['id']}",
                )
                return
        raise AttestationError(f"mapper {name} not found on {owner}")

    def get_mappers(self, owner: str) -> list[dict[str, Any]]:
        return (
            self.request("GET", f"/admin/realms/{self.realm}/{owner}/protocol-mappers/models") or []
        )

    def update_client(self, client_id: str, patch: dict[str, Any]) -> None:
        client = self.find_client(client_id)
        self.request("PUT", f"/admin/realms/{self.realm}/clients/{client['id']}", patch)


def admin_token(base: str, username: str, password: str, context: Any) -> str:
    data = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        }
    ).encode()
    request = urllib.request.Request(
        f"{base.rstrip('/')}/realms/master/protocol/openid-connect/token",
        data=data,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request, context=context) as response:
            return json.loads(response.read())["access_token"]
    except (urllib.error.HTTPError, urllib.error.URLError, OSError, KeyError) as exc:
        raise AttestationError("admin authentication failed") from exc


# --- canonical manifest ------------------------------------------------------
def normalize_mappers(mappers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a deterministic, secret-free projection of protocol mappers."""
    normalized = []
    for mapper in mappers:
        config = {
            str(k): str(v) for k, v in sorted((mapper.get("config") or {}).items()) if v is not None
        }
        normalized.append(
            {
                "name": mapper.get("name"),
                "protocolMapper": mapper.get("protocolMapper"),
                "config": config,
            }
        )
    return sorted(normalized, key=lambda m: (str(m["name"]), str(m["protocolMapper"])))


def normalize_attributes(attributes: dict[str, Any] | None) -> dict[str, str]:
    return {str(k): str(v) for k, v in sorted((attributes or {}).items()) if v is not None}


def canonical_manifest(admin: Admin) -> dict[str, Any]:
    """Build the canonical security-relevant manifest from the live realm."""
    clients = []
    for client in admin.request("GET", f"/admin/realms/{admin.realm}/clients") or []:
        uuid = client["id"]
        clients.append(
            {
                "clientId": client.get("clientId"),
                **{field: client.get(field) for field in CLIENT_FIELDS},
                "defaultClientScopes": sorted(
                    s["name"]
                    for s in admin.request(
                        "GET", f"/admin/realms/{admin.realm}/clients/{uuid}/default-client-scopes"
                    )
                    or []
                ),
                "optionalClientScopes": sorted(
                    s["name"]
                    for s in admin.request(
                        "GET", f"/admin/realms/{admin.realm}/clients/{uuid}/optional-client-scopes"
                    )
                    or []
                ),
                "protocolMappers": normalize_mappers(admin.get_mappers(f"clients/{uuid}")),
            }
        )
    scopes = []
    for scope in admin.request("GET", f"/admin/realms/{admin.realm}/client-scopes") or []:
        scopes.append(
            {
                "name": scope.get("name"),
                "protocol": scope.get("protocol"),
                "attributes": normalize_attributes(scope.get("attributes")),
                "protocolMappers": normalize_mappers(
                    admin.get_mappers(f"client-scopes/{scope['id']}")
                ),
            }
        )
    return {
        "realm": admin.realm,
        "clients": sorted(clients, key=lambda c: str(c["clientId"])),
        "clientScopes": sorted(scopes, key=lambda s: str(s["name"])),
    }


def manifest_hash(manifest: dict[str, Any]) -> str:
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def diff_manifests(expected: Any, actual: Any, path: str = "") -> list[dict[str, Any]]:
    """Return a deterministic list of ``{path, expected, actual}`` drift entries."""
    if type(expected) is not type(actual) and not (
        isinstance(expected, (int, float)) and isinstance(actual, (int, float))
    ):
        return [{"path": path or "$", "expected": expected, "actual": actual}]
    if isinstance(expected, dict):
        drift: list[dict[str, Any]] = []
        for key in sorted(set(expected) | set(actual)):
            child = f"{path}.{key}" if path else str(key)
            if key not in expected:
                drift.append({"path": child, "expected": "<absent>", "actual": actual[key]})
            elif key not in actual:
                drift.append({"path": child, "expected": expected[key], "actual": "<absent>"})
            else:
                drift.extend(diff_manifests(expected[key], actual[key], child))
        return drift
    if isinstance(expected, list):
        if expected == actual:
            return []
        return [{"path": path or "$", "expected": expected, "actual": actual}]
    if expected != actual:
        return [{"path": path or "$", "expected": expected, "actual": actual}]
    return []


# --- attestation -------------------------------------------------------------
@dataclass
class AttestationResult:
    """Outcome of one attestation attempt."""

    ok: bool
    hash: str = ""
    drift: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""


def build_admin(args: argparse.Namespace) -> Admin:
    context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else None
    token = admin_token(args.base, args.admin_username, args.admin_password, context)
    return Admin(args.base, args.realm, token, context)


def attest(admin: Admin, expected: dict[str, Any]) -> AttestationResult:
    """Compare the live canonical manifest against the trusted expected manifest."""
    try:
        live = canonical_manifest(admin)
    except AttestationError as exc:
        return AttestationResult(ok=False, error=str(exc))
    live_hash = manifest_hash(live)
    drift = diff_manifests(expected, live)
    return AttestationResult(ok=not drift, hash=live_hash, drift=drift)


def record_attestation(path: str, hash_value: str) -> None:
    record = {
        "hash": hash_value,
        "observed_at": datetime.now(UTC).isoformat(),
        "observed_at_epoch": time.time(),
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)


def check_record(path: str, max_age_seconds: float) -> AttestationResult:
    """Fail closed on a missing, unreadable, or stale attestation record."""
    try:
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
    except OSError, ValueError:
        return AttestationResult(ok=False, error="attestation record missing or unreadable")
    age = time.time() - float(record.get("observed_at_epoch", 0))
    if max_age_seconds > 0 and age > max_age_seconds:
        return AttestationResult(
            ok=False, error=f"attestation record stale ({age:.0f}s > {max_age_seconds:.0f}s)"
        )
    return AttestationResult(ok=True, hash=str(record.get("hash", "")))


def read_expected(path: str) -> dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise AttestationError(f"expected manifest unreadable: {path}") from exc


def _issuer(args: argparse.Namespace) -> ev.Issuer:
    return ev.Issuer(base=args.base, realm=args.realm, ca_file=args.ca_file)


def _service_token(args: argparse.Namespace, client: str, secret: str) -> str:
    return ev.client_credentials_token(_issuer(args), client, secret)["access_token"]


def _user_token(args: argparse.Namespace, client: str, secret: str, username: str) -> str:
    return ev.authorization_code_token(
        _issuer(args), client, secret, username, args.user_password, REDIRECT_URI, 28400
    )["access_token"]


def _claims(token: str) -> dict[str, Any]:
    return ev.decode_unverified(token)[1]


def _scope_mapper(admin: Admin, scope_name: str, mapper_name: str) -> dict[str, Any] | None:
    scope = admin.find_client_scope(scope_name)
    for mapper in admin.get_mappers(f"client-scopes/{scope['id']}"):
        if mapper.get("name") == mapper_name:
            return mapper
    return None


def _add_scope_mapper(admin: Admin, scope_name: str, payload: dict[str, Any]) -> None:
    scope = admin.find_client_scope(scope_name)
    admin.request(
        "POST",
        f"/admin/realms/{admin.realm}/client-scopes/{scope['id']}/protocol-mappers/models",
        payload,
    )


def _delete_scope_mapper(admin: Admin, scope_name: str, mapper_name: str) -> None:
    scope = admin.find_client_scope(scope_name)
    for mapper in admin.get_mappers(f"client-scopes/{scope['id']}"):
        if mapper.get("name") == mapper_name:
            admin.request(
                "DELETE",
                f"/admin/realms/{admin.realm}/client-scopes/{scope['id']}/protocol-mappers/models/{mapper['id']}",
            )
            return
    raise AttestationError(f"scope mapper {mapper_name} not found")


def _set_client_field(admin: Admin, client_id: str, field: str, value: Any, secret: str) -> None:
    client = admin.find_client(client_id)
    client[field] = value
    client["secret"] = secret
    admin.request("PUT", f"/admin/realms/{admin.realm}/clients/{client['id']}", client)


def _result(
    report: list[dict[str, Any]], rid: str, status: str, detail: dict[str, Any], evidence: str
) -> None:
    report.append({"id": rid, "status": status, "detail": detail, "evidence": evidence})


def run_matrix(args: argparse.Namespace) -> int:
    """Execute the R01-R11 adversarial attestation matrix on the live fixture."""
    expected = read_expected(args.expected)
    expected_hash = manifest_hash(expected)
    admin = build_admin(args)
    report: list[dict[str, Any]] = []

    def attest_state() -> AttestationResult:
        return attest(admin, expected)

    # R01 — clean fixture matches the trusted expected manifest
    state = attest_state()
    _result(
        report,
        "R01",
        "PASS" if state.ok and state.hash == expected_hash else "FAIL",
        {
            "expected_hash": expected_hash,
            "observed_hash": state.hash,
            "drift_count": len(state.drift),
        },
        "expected and observed canonical manifest agree",
    )

    # R02/R03 — genuine class acceptance (independently verified)
    issuer = _issuer(args)
    service_t = _service_token(args, "mtmf-evidence-service", SECRETS["service"])
    user_t = _user_token(args, "mtmf-evidence-user", SECRETS["user"], "mtmf-user-alice")
    service_p = ev.verify_token(issuer, service_t, "mtmf-service-api")
    user_p = ev.verify_token(issuer, user_t, "mtmf-user-api")
    _result(
        report,
        "R02",
        "PASS" if ev.service_class_ok(service_p) and not ev.user_class_ok(service_p) else "FAIL",
        {
            "service_class": ev.service_class_ok(service_p),
            "user_class": ev.user_class_ok(service_p),
        },
        "genuine service token accepted by the service predicate only",
    )
    _result(
        report,
        "R03",
        "PASS" if ev.user_class_ok(user_p) and not ev.service_class_ok(user_p) else "FAIL",
        {"service_class": ev.service_class_ok(user_p), "user_class": ev.user_class_ok(user_p)},
        "genuine user token accepted by the user predicate only",
    )

    # R04/R05 — audience crossover cannot bypass class separation
    user_cross_p = ev.verify_token(
        issuer,
        _user_token(args, "mtmf-evidence-user-cross", SECRETS["user_cross"], "mtmf-user-alice"),
        "mtmf-user-api",
    )
    svc_cross_p = ev.verify_token(
        issuer,
        _service_token(args, "mtmf-evidence-service-cross", SECRETS["svc_cross"]),
        "mtmf-service-api",
    )
    _result(
        report,
        "R04",
        "PASS"
        if "mtmf-service-api" in (user_cross_p.get("aud") or [])
        and not ev.service_class_ok(user_cross_p)
        else "FAIL",
        {"aud": user_cross_p.get("aud"), "service_class": ev.service_class_ok(user_cross_p)},
        "user token with the service audience rejected by the service predicate",
    )
    _result(
        report,
        "R05",
        "PASS"
        if "mtmf-user-api" in (svc_cross_p.get("aud") or []) and not ev.user_class_ok(svc_cross_p)
        else "FAIL",
        {"aud": svc_cross_p.get("aud"), "user_class": ev.user_class_ok(svc_cross_p)},
        "service token with the user audience rejected by the user predicate",
    )

    # R06 — reproduce G0-T09 and prove attestation detects it
    user_client = admin.find_client("mtmf-evidence-user")
    try:
        admin.add_hardcoded_mapper(
            f"clients/{user_client['id']}", "g0a-spoof-client-id", "client_id", "mtmf-evidence-user"
        )
        spoof_p = _claims(
            _user_token(args, "mtmf-evidence-user", SECRETS["user"], "mtmf-user-alice")
        )
        drift = attest_state()
        _result(
            report,
            "R06",
            "PASS"
            if drift.ok is False and ev.service_class_ok(spoof_p) and drift.hash != expected_hash
            else "FAIL",
            {
                "claim_only_predicate_spoofed": ev.service_class_ok(spoof_p),
                "attestation_detected_drift": not drift.ok,
                "drift_count": len(drift.drift),
            },
            "hardcoded mapper spoofs the claim predicate but attestation detects the drift",
        )
    finally:
        admin.delete_mapper(f"clients/{user_client['id']}", "g0a-spoof-client-id")

    # R07 — override another security-critical claim / scope-level mapper
    try:
        admin.add_hardcoded_mapper(
            f"clients/{user_client['id']}", "g0a-spoof-sub", "sub", "attacker"
        )
        admin.add_hardcoded_mapper(f"clients/{user_client['id']}", "g0a-spoof-typ", "typ", "ID")
        admin.add_hardcoded_mapper(
            f"clients/{user_client['id']}", "g0a-spoof-azp", "azp", "mtmf-evidence-service"
        )
        _add_scope_mapper(
            admin,
            "service_account",
            {
                "name": "g0a-scope-spoof-azp",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-hardcoded-claim-mapper",
                "config": {
                    "claim.name": "azp",
                    "claim.value": "mtmf-evidence-service",
                    "access.token.claim": "true",
                },
            },
        )
        drift = attest_state()
    finally:
        admin.delete_mapper(f"clients/{user_client['id']}", "g0a-spoof-sub")
        admin.delete_mapper(f"clients/{user_client['id']}", "g0a-spoof-typ")
        admin.delete_mapper(f"clients/{user_client['id']}", "g0a-spoof-azp")
        _delete_scope_mapper(admin, "service_account", "g0a-scope-spoof-azp")
    _result(
        report,
        "R07",
        "PASS" if not drift.ok else "FAIL",
        {"attestation_detected_drift": not drift.ok, "drift_count": len(drift.drift)},
        "direct and scope-level security-critical claim overrides are detected",
    )

    # R08 — remove the required built-in service-account mapper
    original = _scope_mapper(admin, "service_account", "Client ID")
    try:
        _delete_scope_mapper(admin, "service_account", "Client ID")
        drift = attest_state()
        svc_p = ev.verify_token(
            issuer,
            _service_token(args, "mtmf-evidence-service", SECRETS["service"]),
            "mtmf-service-api",
        )
        _result(
            report,
            "R08",
            "PASS" if not drift.ok and not ev.service_class_ok(svc_p) else "FAIL",
            {
                "attestation_detected_drift": not drift.ok,
                "service_class_after_removal": ev.service_class_ok(svc_p),
                "client_id_present": "client_id" in svc_p,
            },
            "removing the built-in Client ID mapper is detected and the service token "
            "fails class checks",
        )
    finally:
        if original is not None:
            _add_scope_mapper(
                admin,
                "service_account",
                {
                    "name": original["name"],
                    "protocol": original.get("protocol", "openid-connect"),
                    "protocolMapper": original["protocolMapper"],
                    "config": original.get("config", {}),
                },
            )

    # R09 — alter audience and grant settings
    service_client = admin.find_client("mtmf-evidence-service")
    try:
        admin.add_hardcoded_mapper(
            f"clients/{service_client['id']}", "g0a-extra-aud", "aud", "mtmf-user-api"
        )
        _set_client_field(
            admin, "mtmf-evidence-service", "standardFlowEnabled", True, SECRETS["service"]
        )
        drift = attest_state()
    finally:
        admin.delete_mapper(f"clients/{service_client['id']}", "g0a-extra-aud")
        _set_client_field(
            admin, "mtmf-evidence-service", "standardFlowEnabled", False, SECRETS["service"]
        )
    _result(
        report,
        "R09",
        "PASS" if not drift.ok else "FAIL",
        {"attestation_detected_drift": not drift.ok, "drift_count": len(drift.drift)},
        "audience and grant-setting changes are detected",
    )

    # R10 — fail-closed preflight on unavailable/untrusted inputs
    r10: dict[str, Any] = {}
    try:
        admin_token(args.base, args.admin_username, "wrong-password", None)
        r10["bad_admin_credentials"] = False
    except AttestationError:
        r10["bad_admin_credentials"] = True
    try:
        read_expected("/nonexistent/expected.json")
        r10["missing_expected_manifest"] = False
    except AttestationError:
        r10["missing_expected_manifest"] = True
    stale = "/tmp/g0a-stale-record.json"
    Path(stale).write_text(
        json.dumps({"hash": expected_hash, "observed_at_epoch": time.time() - 10_000}),
        encoding="utf-8",
    )
    r10["stale_attestation_record"] = not check_record(stale, max_age_seconds=1).ok
    Path(stale).unlink(missing_ok=True)
    _result(
        report,
        "R10",
        "PASS" if all(r10.values()) else "FAIL",
        r10,
        "unavailable credentials, missing baseline and stale attestation all fail closed",
    )

    # R11 — restore canonical config; attestation recovers
    state = attest_state()
    service_p = ev.verify_token(
        issuer,
        _service_token(args, "mtmf-evidence-service", SECRETS["service"]),
        "mtmf-service-api",
    )
    user_p = ev.verify_token(
        issuer,
        _user_token(args, "mtmf-evidence-user", SECRETS["user"], "mtmf-user-alice"),
        "mtmf-user-api",
    )
    _result(
        report,
        "R11",
        "PASS"
        if state.ok
        and state.hash == expected_hash
        and ev.service_class_ok(service_p)
        and ev.user_class_ok(user_p)
        else "FAIL",
        {"observed_hash": state.hash, "expected_hash": expected_hash},
        "attestation recovers after restoring canonical configuration",
    )

    # R12 is performed as a separate clean-recreate shell step (see the report).
    _result(
        report,
        "R12",
        "NOT EXECUTED",
        {
            "note": (
                "clean recreate is performed separately; see "
                "PR14_G0A_MAPPER_LOCKDOWN_EVIDENCE_REPORT.md"
            )
        },
        "operator clean-recreate step",
    )

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        Path(args.report).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if all(r["status"] in {"PASS", "NOT EXECUTED"} for r in report) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("manifest", "attest", "matrix"))
    parser.add_argument("--base", default=os.environ.get("MTMF_PR14_KC_BASE", DEFAULT_BASE))
    parser.add_argument("--realm", default=os.environ.get("MTMF_PR14_KC_REALM", DEFAULT_REALM))
    parser.add_argument("--ca-file", default=os.environ.get("MTMF_PR14_KC_CA_FILE", ""))
    parser.add_argument(
        "--admin-username", default=os.environ.get("MTMF_PR14_KC_ADMIN_USERNAME", "")
    )
    parser.add_argument(
        "--admin-password", default=os.environ.get("MTMF_PR14_KC_ADMIN_PASSWORD", "")
    )
    parser.add_argument("--user-password", default=os.environ.get("MTMF_PR14_KC_USER_PASSWORD", ""))
    parser.add_argument("--expected", default="")
    parser.add_argument("--out", default="")
    parser.add_argument("--record", default="")
    parser.add_argument("--check-record", action="store_true")
    parser.add_argument("--max-age-seconds", type=float, default=0.0)
    parser.add_argument("--report", default="")
    args = parser.parse_args()

    if args.command == "manifest":
        admin = build_admin(args)
        manifest = canonical_manifest(admin)
        rendered = json.dumps(manifest, indent=2, sort_keys=True)
        if args.out:
            Path(args.out).write_text(rendered + "\n", encoding="utf-8")
        print(json.dumps({"hash": manifest_hash(manifest), "out": args.out}))
        return 0

    if args.command == "attest":
        if args.check_record and args.record:
            record_result = check_record(args.record, args.max_age_seconds)
            if not record_result.ok:
                print(json.dumps({"status": "fail_closed", "error": record_result.error}))
                return 2
        try:
            expected = read_expected(args.expected)
        except AttestationError as exc:
            print(json.dumps({"status": "fail_closed", "error": str(exc)}))
            return 2
        admin = build_admin(args)
        result = attest(admin, expected)
        if args.record and result.ok:
            record_attestation(args.record, result.hash)
        print(
            json.dumps(
                {
                    "status": "ok" if result.ok else "drift",
                    "hash": result.hash,
                    "error": result.error,
                    "drift": result.drift[:20],
                    "drift_count": len(result.drift),
                }
            )
        )
        return 0 if result.ok else 1

    return run_matrix(args)


if __name__ == "__main__":
    raise SystemExit(main())
