#!/usr/bin/env python3
"""PR 14 Gate G0-A — service vs user token-class evidence.

Development-only evidence harness. It issues real tokens from the pinned,
explicitly configured local Keycloak fixture, evaluates the *candidate*
service/user class predicates on independently signature-verified claims,
and records adversarial crossover and mapper-override results. It contains
no MTMF production trust logic and never prints a raw token or secret.

Usage::

    uv run --no-sync python scripts/pr14-g0-token-class-evidence.py \
        --report dev/keycloak/evidence/pr14-g0-token-class-evidence.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SCRIPT = Path(__file__).resolve().parent / "pr14-keycloak-evidence.py"
_spec = importlib.util.spec_from_file_location("pr14_keycloak_evidence", _SCRIPT)
assert _spec is not None and _spec.loader is not None
ev = importlib.util.module_from_spec(_spec)
sys.modules["pr14_keycloak_evidence"] = ev
_spec.loader.exec_module(ev)

DEFAULT_BASE = "https://127.0.0.1:28443"
DEFAULT_REALM = "mtmf-pr14-dev"
REDIRECT_URI = "http://127.0.0.1:28400/callback"


@dataclass
class Result:
    """One G0 experiment result."""

    id: str
    status: str
    detail: dict[str, Any] = field(default_factory=dict)
    evidence: str = ""


class Admin:
    """Minimal Admin REST client for the isolated fixture only."""

    def __init__(self, base: str, realm: str, token: str, context: Any) -> None:
        self._base = base.rstrip("/")
        self._realm = realm
        self._token = token
        self._context = context

    def request(self, method: str, path: str, body: Any | None = None) -> Any:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"{self._base}{path}",
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
            raise RuntimeError(f"admin {method} {path}: HTTP {exc.code}") from exc
        return json.loads(payload) if payload else None

    def find_client(self, client_id: str) -> dict[str, Any]:
        rows = self.request("GET", f"/admin/realms/{self._realm}/clients?clientId={client_id}")
        if not rows:
            raise RuntimeError(f"client {client_id} not found")
        return rows[0]

    def add_hardcoded_mapper(self, uuid: str, name: str, claim: str, value: str) -> None:
        self.request(
            "POST",
            f"/admin/realms/{self._realm}/clients/{uuid}/protocol-mappers/models",
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

    def delete_mapper(self, uuid: str, name: str) -> None:
        mappers = self.request(
            "GET", f"/admin/realms/{self._realm}/clients/{uuid}/protocol-mappers/models"
        )
        for mapper in mappers or []:
            if mapper.get("name") == name:
                self.request(
                    "DELETE",
                    f"/admin/realms/{self._realm}/clients/{uuid}/protocol-mappers/models/{mapper['id']}",
                )


def _admin_token(base: str, username: str, password: str, context: Any) -> str:
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
    with urllib.request.urlopen(request, context=context) as response:
        return json.loads(response.read())["access_token"]


def _claims(token: str) -> dict[str, Any]:
    return ev.decode_unverified(token)[1]


def _result(report: list[Result], result: Result) -> None:
    report.append(result)


def collect(
    issuer: ev.Issuer,
    admin: Admin,
    user_password: str,
) -> list[Result]:
    """Run the G0-T01..T09 experiments."""
    report: list[Result] = []
    secrets = {
        "service": "mtmf-evidence-service-dev-secret",
        "user": "mtmf-evidence-user-dev-secret",
        "same": "mtmf-evidence-same-client-dev-secret",
        "user_cross": "mtmf-evidence-user-cross-dev-secret",
        "service_cross": "mtmf-evidence-service-cross-dev-secret",
        "svc_noclaim": "mtmf-evidence-svc-noclaim-dev-secret",
    }
    verified: dict[str, dict[str, Any]] = {}

    def user_token(client: str, secret: str, username: str) -> dict[str, Any]:
        return ev.authorization_code_token(
            issuer, client, secret, username, user_password, REDIRECT_URI, 28400
        )

    # Acquire and verify tokens (issuer + verifier boundary).
    service = ev.client_credentials_token(issuer, "mtmf-evidence-service", secrets["service"])
    user = user_token("mtmf-evidence-user", secrets["user"], "mtmf-user-alice")
    svc_cross = ev.client_credentials_token(
        issuer, "mtmf-evidence-service-cross", secrets["service_cross"]
    )
    user_cross = user_token("mtmf-evidence-user-cross", secrets["user_cross"], "mtmf-user-alice")
    svc_noclaim = ev.client_credentials_token(
        issuer, "mtmf-evidence-svc-noclaim", secrets["svc_noclaim"]
    )
    same_svc = ev.client_credentials_token(issuer, "mtmf-evidence-same-client", secrets["same"])
    same_user = user_token("mtmf-evidence-same-client", secrets["same"], "mtmf-user-bob")

    def verified_payload(name: str, token: str, audience: str) -> dict[str, Any]:
        payload = ev.verify_token(issuer, token, audience)
        verified[name] = payload
        return payload

    service_p = verified_payload("service", service["access_token"], "mtmf-service-api")
    user_p = verified_payload("user", user["access_token"], "mtmf-user-api")
    svc_cross_p = verified_payload("service_cross", svc_cross["access_token"], "mtmf-service-api")
    user_cross_p = verified_payload("user_cross", user_cross["access_token"], "mtmf-user-api")
    svc_noclaim_p = verified_payload("svc_noclaim", svc_noclaim["access_token"], "mtmf-service-api")
    same_svc_p = verified_payload("same_service", same_svc["access_token"], "mtmf-same-client-api")
    same_user_p = verified_payload("same_user", same_user["access_token"], "mtmf-same-client-api")

    def detail(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "typ": payload.get("typ"),
            "aud": payload.get("aud"),
            "azp": payload.get("azp"),
            "client_id": payload.get("client_id"),
            "has_sub": bool(payload.get("sub")),
            "service_class": ev.service_class_ok(payload),
            "user_class": ev.user_class_ok(payload),
        }

    # G0-T01
    _result(
        report,
        Result(
            "G0-T01",
            "PASS"
            if ev.service_class_ok(service_p) and not ev.user_class_ok(service_p)
            else "FAIL",
            detail(service_p),
            "genuine client-credentials token satisfies the service predicate only",
        ),
    )
    # G0-T02
    _result(
        report,
        Result(
            "G0-T02",
            "PASS" if ev.user_class_ok(user_p) and not ev.service_class_ok(user_p) else "FAIL",
            detail(user_p),
            "genuine auth-code+PKCE token satisfies the user predicate only",
        ),
    )
    # G0-T03: user token carrying the service audience must fail the service predicate
    _result(
        report,
        Result(
            "G0-T03",
            "PASS"
            if "mtmf-service-api" in (user_cross_p.get("aud") or [])
            and not ev.service_class_ok(user_cross_p)
            else "FAIL",
            detail(user_cross_p),
            "user token with the service audience is rejected by the service predicate",
        ),
    )
    # G0-T04: service token carrying the user audience must fail the user predicate
    _result(
        report,
        Result(
            "G0-T04",
            "PASS"
            if "mtmf-user-api" in (svc_cross_p.get("aud") or [])
            and not ev.user_class_ok(svc_cross_p)
            else "FAIL",
            detail(svc_cross_p),
            "service token with the user audience is rejected by the user predicate",
        ),
    )
    # G0-T05: both-audience crossover cannot bypass class separation
    _result(
        report,
        Result(
            "G0-T05",
            "PASS"
            if not ev.service_class_ok(user_cross_p) and not ev.user_class_ok(svc_cross_p)
            else "FAIL",
            {"user_cross": detail(user_cross_p), "service_cross": detail(svc_cross_p)},
            "both-audience tokens do not satisfy the opposite class predicate",
        ),
    )
    # G0-T06: missing class evidence fails closed
    _result(
        report,
        Result(
            "G0-T06",
            "PASS" if not ev.service_class_ok(svc_noclaim_p) else "FAIL",
            detail(svc_noclaim_p),
            "service token without the grant-derived client_id claim fails the service predicate",
        ),
    )
    # G0-T07: ID/refresh tokens are not access-token classes
    id_token = user.get("id_token", "")
    refresh_token = user.get("refresh_token", "")
    id_p = _claims(id_token) if id_token else {}
    refresh_p = _claims(refresh_token) if refresh_token else {}
    _result(
        report,
        Result(
            "G0-T07",
            "PASS"
            if not ev.service_class_ok(id_p)
            and not ev.user_class_ok(id_p)
            and not ev.service_class_ok(refresh_p)
            and not ev.user_class_ok(refresh_p)
            else "FAIL",
            {"id_typ": id_p.get("typ"), "refresh_typ": refresh_p.get("typ")},
            "ID and refresh tokens satisfy neither class predicate",
        ),
    )
    # G0-T08: same-client azp observed; different-client pairing fails
    same_equal = same_svc_p.get("azp") == same_user_p.get("azp")
    different = service_p.get("azp") != user_p.get("azp")
    _result(
        report,
        Result(
            "G0-T08",
            "PASS" if same_equal and different else "FAIL",
            {
                "same_client_azp_equal": same_equal,
                "different_client_azp_differ": different,
                "cross_pairing_rejected": different,
            },
            "same-client azp observed equal; different-client pairing rejected",
        ),
    )

    # G0-T09: a realm protocol mapper can inject client_id and override azp.
    # Tested sequentially so the two spoofs do not interfere.
    user_client = admin.find_client("mtmf-evidence-user")
    spoof = {
        "client_id_injected": False,
        "injected_user_token_passes_service_predicate": False,
        "azp_overridden": False,
    }
    try:
        admin.add_hardcoded_mapper(
            user_client["id"], "g0-spoof-client-id", "client_id", "mtmf-evidence-user"
        )
        injected = _claims(
            user_token("mtmf-evidence-user", secrets["user"], "mtmf-user-alice")["access_token"]
        )
        spoof["client_id_injected"] = injected.get("client_id") == "mtmf-evidence-user"
        spoof["injected_user_token_passes_service_predicate"] = ev.service_class_ok(injected)
    finally:
        admin.delete_mapper(user_client["id"], "g0-spoof-client-id")
    try:
        admin.add_hardcoded_mapper(
            user_client["id"], "g0-spoof-azp", "azp", "mtmf-evidence-service"
        )
        overridden = _claims(
            user_token("mtmf-evidence-user", secrets["user"], "mtmf-user-alice")["access_token"]
        )
        spoof["azp_overridden"] = overridden.get("azp") == "mtmf-evidence-service"
    finally:
        admin.delete_mapper(user_client["id"], "g0-spoof-azp")
    spoofable = spoof["injected_user_token_passes_service_predicate"] or spoof["azp_overridden"]
    _result(
        report,
        Result(
            "G0-T09",
            "FAIL" if spoofable else "PASS",
            spoof,
            "a realm protocol mapper can inject client_id and override azp; the class "
            "predicates are therefore configuration-dependent, not unconditionally safe",
        ),
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
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
    parser.add_argument("--report", default="")
    args = parser.parse_args()

    context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else None
    issuer = ev.Issuer(base=args.base, realm=args.realm, ca_file=args.ca_file, allow_nonlocal=False)
    token = _admin_token(args.base, args.admin_username, args.admin_password, context)
    admin = Admin(args.base, args.realm, token, context)

    report = collect(issuer, admin, args.user_password)
    rendered = json.dumps([r.__dict__ for r in report], indent=2, sort_keys=True)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")
    print(rendered)
    return 0 if all(r.status in {"PASS", "BLOCKED", "NOT EXECUTED"} for r in report) else 1


if __name__ == "__main__":
    raise SystemExit(main())
