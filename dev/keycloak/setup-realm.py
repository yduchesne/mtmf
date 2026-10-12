#!/usr/bin/env python3
"""Idempotent Keycloak development realm setup for PR 14 Track 2 evidence.

Creates (or reconciles) a synthetic, development-only realm with separate
OAuth clients and audience mappers used only by the local evidence harness.
No real identity, secret, or production configuration is referenced.

Why a setup script instead of a tracked realm import
----------------------------------------------------
A Keycloak realm export embeds client secrets and is version-fragile. This
script uses the pinned issuer's own Admin REST API, is idempotent, and
never writes secrets into the repository. It is a documented deviation
from the plan's suggested ``realm/mtmf-dev-realm.json``.

All configuration comes from explicit ``MTMF_PR14_KC_*`` environment
variables. The script refuses to target a non-loopback/local host unless
``--allow-nonlocal`` is passed, so evidence credentials are never sent to
an arbitrary URL.

Usage::

    export MTMF_PR14_KC_ADMIN_USERNAME=mtmf-pr14-admin
    export MTMF_PR14_KC_ADMIN_PASSWORD='<generated>'
    uv run --no-sync python dev/keycloak/setup-realm.py
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

DEFAULT_BASE = "https://127.0.0.1:28443"
DEFAULT_REALM = "mtmf-pr14-dev"
DEFAULT_REDIRECT = "http://127.0.0.1:28400/callback"

#: Synthetic, clearly non-production fixture users. Passwords are generated
#: by the operator and supplied through the environment / runtime.
EVIDENCE_USERS = ("mtmf-user-alice", "mtmf-user-bob", "mtmf-root-admin", "mtmf-user-carol")


@dataclass(frozen=True, slots=True)
class ClientSpec:
    """A synthetic OAuth client needed by one evidence experiment."""

    client_id: str
    audiences: tuple[str, ...]
    service_account: bool
    standard_flow: bool
    redirect_uris: tuple[str, ...] = ()
    token_exchange: bool = False
    client_audiences: tuple[str, ...] = ()
    access_token_lifespan: int | None = None
    #: When True, remove the built-in ``service_account`` client scope so the
    #: client's tokens omit the grant-derived ``client_id``/``clientHost``/
    #: ``clientAddress`` claims (G0-T06 missing-class-evidence case).
    strip_service_account_scope: bool = False


CLIENTS = (
    ClientSpec(
        client_id="mtmf-evidence-service",
        audiences=("mtmf-service-api",),
        service_account=True,
        standard_flow=False,
    ),
    ClientSpec(
        client_id="mtmf-evidence-user",
        audiences=("mtmf-user-api",),
        service_account=False,
        standard_flow=True,
        redirect_uris=(DEFAULT_REDIRECT,),
        # Add the exchange target as a *client* audience so Standard Token
        # Exchange V2 can recognize the target client in the subject token.
        client_audiences=("mtmf-evidence-exchange",),
    ),
    ClientSpec(
        client_id="mtmf-evidence-same-client",
        audiences=("mtmf-same-client-api",),
        service_account=True,
        standard_flow=True,
        redirect_uris=(DEFAULT_REDIRECT,),
    ),
    # A second, independent same-client development credential for the V12
    # two-Application isolation acceptance (distinct client id and `azp`).
    ClientSpec(
        client_id="mtmf-evidence-same-client-b",
        audiences=("mtmf-same-client-api",),
        service_account=True,
        standard_flow=True,
        redirect_uris=(DEFAULT_REDIRECT,),
    ),
    ClientSpec(
        client_id="mtmf-evidence-root",
        audiences=("mtmf-root-api",),
        service_account=False,
        standard_flow=True,
        redirect_uris=(DEFAULT_REDIRECT,),
    ),
    ClientSpec(
        client_id="mtmf-evidence-exchange",
        audiences=("mtmf-exchange-api",),
        service_account=True,
        standard_flow=False,
        token_exchange=True,
    ),
    ClientSpec(
        client_id="mtmf-evidence-expiry",
        audiences=("mtmf-expiry-api",),
        service_account=True,
        standard_flow=False,
        access_token_lifespan=1,
    ),
    ClientSpec(
        client_id="mtmf-evidence-user-cross",
        audiences=("mtmf-user-api", "mtmf-service-api"),
        service_account=False,
        standard_flow=True,
        redirect_uris=(DEFAULT_REDIRECT,),
    ),
    ClientSpec(
        client_id="mtmf-evidence-service-cross",
        audiences=("mtmf-service-api", "mtmf-user-api"),
        service_account=True,
        standard_flow=False,
    ),
    ClientSpec(
        client_id="mtmf-evidence-svc-noclaim",
        audiences=("mtmf-service-api",),
        service_account=True,
        standard_flow=False,
        strip_service_account_scope=True,
    ),
)


class SetupError(RuntimeError):
    """Realm setup could not be completed."""


class AdminApi:
    """Minimal bearer-token Admin REST client (stdlib only)."""

    def __init__(self, base: str, token: str, context: ssl.SSLContext | None = None) -> None:
        self._base = base.rstrip("/")
        self._token = token
        self._context = context

    def request(
        self,
        method: str,
        path: str,
        body: Any | None = None,
        *,
        expected: tuple[int, ...] = (200, 201, 204),
    ) -> Any:
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
            with urllib.request.urlopen(request, timeout=30, context=self._context) as response:
                if response.status not in expected:
                    raise SetupError(f"{method} {path} returned HTTP {response.status}")
                payload = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            raise SetupError(f"{method} {path} failed: HTTP {exc.code}: {detail}") from exc
        if not payload:
            return None
        return json.loads(payload)

    def get(self, path: str, *, allow_404: bool = False) -> Any:
        try:
            return self.request("GET", path)
        except SetupError:
            if allow_404:
                return None
            raise


def admin_token(
    base: str, username: str, password: str, context: ssl.SSLContext | None = None
) -> str:
    """Return an administrator access token from the master realm."""
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
        with urllib.request.urlopen(request, timeout=30, context=context) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise SetupError(f"administrator authentication failed: HTTP {exc.code}: {detail}") from exc
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise SetupError("administrator authentication returned no access token")
    return token


def _is_local(base: str) -> bool:
    host = urllib.parse.urlparse(base).hostname or ""
    return host in {"127.0.0.1", "localhost", "::1"}


def ensure_realm(api: AdminApi, realm: str) -> None:
    """Create the realm when absent; leave an existing realm intact."""
    existing = api.get(f"/admin/realms/{realm}", allow_404=True)
    if existing is not None:
        return
    api.request(
        "POST",
        "/admin/realms",
        {
            "realm": realm,
            "enabled": True,
            "sslRequired": "none",
            "registrationAllowed": False,
            "loginWithEmailAllowed": False,
            "duplicateEmailsAllowed": False,
            "resetPasswordAllowed": False,
            "accessTokenLifespan": 300,
            "ssoSessionIdleTimeout": 1800,
            "ssoSessionMaxLifespan": 3600,
        },
    )


def ensure_client(api: AdminApi, realm: str, spec: ClientSpec) -> dict[str, Any]:
    """Create or reconcile one synthetic client, preserving any existing secret."""
    payload: dict[str, Any] = {
        "clientId": spec.client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "bearerOnly": False,
        "serviceAccountsEnabled": spec.service_account,
        "standardFlowEnabled": spec.standard_flow,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "redirectUris": list(spec.redirect_uris),
        "webOrigins": [],
        "attributes": {"pkce.code.challenge.method": "S256"},
    }
    if spec.service_account:
        payload["secret"] = f"{spec.client_id}-dev-secret"
    else:
        payload["secret"] = f"{spec.client_id}-dev-secret"
    if spec.token_exchange:
        payload["attributes"]["standard.token.exchange.enabled"] = "true"
    if spec.access_token_lifespan is not None:
        payload["attributes"]["access.token.lifespan"] = str(spec.access_token_lifespan)

    existing = api.get(f"/admin/realms/{realm}/clients?clientId={spec.client_id}")
    if existing:
        client = existing[0]
        client_id_uuid = client["id"]
        update = dict(payload)
        # Never rotate the secret implicitly.
        update.pop("secret", None)
        api.request("PUT", f"/admin/realms/{realm}/clients/{client_id_uuid}", update)
    else:
        api.request("POST", f"/admin/realms/{realm}/clients", payload)
        created = api.get(f"/admin/realms/{realm}/clients?clientId={spec.client_id}")
        if not created:
            raise SetupError(f"client {spec.client_id} was not created")
        client_id_uuid = created[0]["id"]

    ensure_audience_mapper(api, realm, client_id_uuid, spec)
    if spec.strip_service_account_scope:
        strip_client_scope(api, realm, client_id_uuid, "service_account")
    return api.get(f"/admin/realms/{realm}/clients/{client_id_uuid}")


def strip_client_scope(api: AdminApi, realm: str, client_uuid: str, scope_name: str) -> None:
    """Remove one client scope assignment (default or optional) from a client.

    Used only to reproduce the G0-T06 missing-class-evidence case.
    """
    for kind in ("default-client-scopes", "optional-client-scopes"):
        scopes = api.get(f"/admin/realms/{realm}/clients/{client_uuid}/{kind}") or []
        for scope in scopes:
            if scope.get("name") == scope_name:
                api.request(
                    "DELETE",
                    f"/admin/realms/{realm}/clients/{client_uuid}/{kind}/{scope['id']}",
                )


def ensure_audience_mapper(api: AdminApi, realm: str, client_uuid: str, spec: ClientSpec) -> None:
    """Ensure exactly one audience mapper per configured audience."""
    path = f"/admin/realms/{realm}/clients/{client_uuid}/protocol-mappers/models"
    existing = api.get(path) or []
    names = {mapper["name"] for mapper in existing}
    for audience in spec.audiences:
        name = f"aud-{audience}"
        if name in names:
            continue
        api.request(
            "POST",
            path,
            {
                "name": name,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": audience,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            },
        )
    for client_audience in spec.client_audiences:
        name = f"aud-client-{client_audience}"
        if name in names:
            continue
        api.request(
            "POST",
            path,
            {
                "name": name,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.client.audience": client_audience,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                    "introspection.token.claim": "true",
                },
            },
        )


def ensure_user(api: AdminApi, realm: str, username: str, password: str) -> dict[str, Any]:
    """Create or reconcile one synthetic user and reset its password."""
    existing = api.get(f"/admin/realms/{realm}/users?username={username}&exact=true")
    if existing:
        user = existing[0]
    else:
        api.request(
            "POST",
            f"/admin/realms/{realm}/users",
            {
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "email": f"{username}@example.invalid",
                "firstName": "Synthetic",
                "lastName": "User",
            },
        )
        created = api.get(f"/admin/realms/{realm}/users?username={username}&exact=true")
        if not created:
            raise SetupError(f"user {username} was not created")
        user = created[0]
    api.request(
        "PUT",
        f"/admin/realms/{realm}/users/{user['id']}/reset-password",
        {"type": "password", "value": password, "temporary": False},
    )
    return user


#: Dedicated, non-interactive least-privilege attestation reader (SEC-01).
#: It may perform only the read operations used by `canonical_manifest` and
#: `canonical_client_projection`; all realm/client/user/scope/mapper mutations
#: and role escalation are denied (proved by the Amendment #5 permission matrix).
ATTESTATION_READER_CLIENT_ID = "mtmf-attestation-reader"
ATTESTATION_READER_REALM_ROLES = ("view-realm", "view-clients", "query-clients")


def ensure_attestation_reader(api: AdminApi, realm: str) -> dict[str, Any]:
    """Provision the least-privilege reader client and its service-account roles."""
    spec = ClientSpec(
        client_id=ATTESTATION_READER_CLIENT_ID,
        audiences=(),
        service_account=True,
        standard_flow=False,
    )
    client = ensure_client(api, realm, spec)
    realm_management = api.get(f"/admin/realms/{realm}/clients?clientId=realm-management")
    if not realm_management:
        raise SetupError("realm-management client is missing")
    realm_management_uuid = realm_management[0]["id"]
    roles = api.get(f"/admin/realms/{realm}/clients/{realm_management_uuid}/roles") or []
    wanted = [role for role in roles if role["name"] in ATTESTATION_READER_REALM_ROLES]
    if len(wanted) != len(ATTESTATION_READER_REALM_ROLES):
        raise SetupError("required realm-management read roles are unavailable")
    service_account = api.get(f"/admin/realms/{realm}/clients/{client['id']}/service-account-user")
    api.request(
        "POST",
        f"/admin/realms/{realm}/users/{service_account['id']}/role-mappings/clients/"
        f"{realm_management_uuid}",
        wanted,
    )
    return client


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--realm", default=DEFAULT_REALM)
    parser.add_argument(
        "--admin-username", default=os.environ.get("MTMF_PR14_KC_ADMIN_USERNAME", "mtmf-pr14-admin")
    )
    parser.add_argument(
        "--admin-password", default=os.environ.get("MTMF_PR14_KC_ADMIN_PASSWORD", "")
    )
    parser.add_argument("--user-password", default=os.environ.get("MTMF_PR14_KC_USER_PASSWORD", ""))
    parser.add_argument("--ca-file", default=os.environ.get("MTMF_PR14_KC_CA_FILE", ""))
    parser.add_argument("--allow-nonlocal", action="store_true")
    args = parser.parse_args()

    if not _is_local(args.base) and not args.allow_nonlocal:
        print(
            "refusing to configure a non-loopback issuer without --allow-nonlocal", file=sys.stderr
        )
        return 2
    if not args.admin_password:
        print("MTMF_PR14_KC_ADMIN_PASSWORD is required (use --admin-password)", file=sys.stderr)
        return 2
    if not args.user_password:
        print("MTMF_PR14_KC_USER_PASSWORD is required (use --user-password)", file=sys.stderr)
        return 2

    context = ssl.create_default_context(cafile=args.ca_file) if args.ca_file else None
    token = admin_token(args.base, args.admin_username, args.admin_password, context)
    api = AdminApi(args.base, token, context)
    ensure_realm(api, args.realm)

    manifest: dict[str, Any] = {
        "issuer": f"{args.base.rstrip('/')}/realms/{args.realm}",
        "realm": args.realm,
        "clients": [],
        "users": [],
    }
    for spec in CLIENTS:
        client = ensure_client(api, args.realm, spec)
        manifest["clients"].append(
            {
                "client_id": spec.client_id,
                "service_account": spec.service_account,
                "standard_flow": spec.standard_flow,
                "audiences": list(spec.audiences),
                "token_exchange": spec.token_exchange,
                "uuid": client.get("id"),
            }
        )
    reader = ensure_attestation_reader(api, args.realm)
    manifest["attestation_reader"] = {
        "client_id": reader.get("clientId"),
        "roles": list(ATTESTATION_READER_REALM_ROLES),
        "uuid": reader.get("id"),
    }
    for username in EVIDENCE_USERS:
        ensure_user(api, args.realm, username, args.user_password)
        manifest["users"].append(username)

    # Sanitized manifest: no secrets, no passwords, no raw tokens.
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
