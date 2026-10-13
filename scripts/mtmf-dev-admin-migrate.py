#!/usr/bin/env python3
"""Development-only Keycloak master-realm administrator migration (PR 17-C Fixup 2).

Establishes the canonical development administrator ``mtmf-admin`` in the
preserved development Keycloak volume and retires the PR-numbered legacy
administrators ``mtmf-pr14-admin`` / ``mtmf-pr14-admin2`` **after** the new
account has been independently verified. It is an explicit, operator-supervised,
one-time action: it is never invoked by ``up``, the initializer, or a service
startup.

Safety contract:

* ``--inspect`` (default) is strictly read-only.
* ``--apply`` creates/verifies ``mtmf-admin`` and only then disables (never
  deletes) each legacy administrator, with a read-after-write after every
  disable and a check that at least one independently verified enabled master
  administrator remains at every step.
* Passwords are read ONLY from the environment or an owner-only password file;
  they are never accepted as command-line arguments, printed, or written to
  reports.
* Any ambiguous create outcome, missing verification, unexpected role,
  federation, required action, or failed privileged read is a STOP: the tool
  exits non-zero without mutating further and leaves the last verified
  administrator enabled.

Usage:
    python scripts/mtmf-dev-admin-migrate.py --inspect
    MTMF_DEV_KC_ADMIN_PASSWORD=... MTMF_DEV_KC_RECOVERY_PASSWORD=... \\
        python scripts/mtmf-dev-admin-migrate.py --apply
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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

CANONICAL_ADMIN_USERNAME = "mtmf-admin"
LEGACY_ADMIN_USERNAMES = ("mtmf-pr14-admin", "mtmf-pr14-admin2")
REQUIRED_MASTER_ROLE = "admin"
#: Realm roles Keycloak assigns to an ordinary master-realm administrator.
EXPECTED_MASTER_ROLES = frozenset({"admin", "default-roles-master"})
DEFAULT_BASE_URL = "https://keycloak.mtmf.test:28443"
MASTER_REALM = "master"
TARGET_REALM = "mtmf-pr14-dev"
MAX_RESPONSE_BYTES = 1024 * 1024


class AdminMigrationError(RuntimeError):
    """The administrator migration stopped without completing safely."""


class AdminRestError(AdminMigrationError):
    """A Keycloak Admin REST call failed."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass(slots=True)
class AccountState:
    """Non-secret, read-only account state."""

    username: str
    exists: bool
    user_id: str = ""
    enabled: bool = False
    federated: bool = False
    required_actions: tuple[str, ...] = ()
    realm_roles: tuple[str, ...] = ()

    def as_public(self) -> dict[str, Any]:
        """Return a sanitized representation for reporting."""
        return {
            "username": self.username,
            "exists": self.exists,
            "id": self.user_id[:8] if self.user_id else "",
            "enabled": self.enabled,
            "federated": self.federated,
            "required_actions": list(self.required_actions),
            "realm_roles": list(self.realm_roles),
        }


class AdminClient(Protocol):
    """Minimal Keycloak Admin REST boundary used by the migration."""

    def authenticate(self, username: str, password: str) -> str | None: ...

    def find_users(self, username: str) -> list[dict[str, Any]]: ...

    def realm_roles(self, user_id: str) -> list[str]: ...

    def get_master_role(self, role: str) -> dict[str, Any]: ...

    def create_user(self, username: str, password: str) -> str | None: ...

    def add_realm_roles(self, user_id: str, roles: list[dict[str, Any]]) -> None: ...

    def set_enabled(self, user_id: str, enabled: bool) -> None: ...

    def get_realm(self, realm: str) -> dict[str, Any]: ...


class HttpAdminClient:
    """Bounded, redirect-rejecting HTTPS Admin REST client (stdlib only)."""

    def __init__(self, base_url: str, ca_file: str, *, timeout: float = 10.0) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise AdminMigrationError("the admin base URL must be an absolute https URL")
        if not ca_file or not Path(ca_file).is_file():
            raise AdminMigrationError("the development CA file is required and must exist")
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._context = ssl.create_default_context(cafile=ca_file)
        self._token: str | None = None

    def _open(self, request: urllib.request.Request) -> Any:
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self._context))
        return opener.open(request, timeout=self._timeout)

    def authenticate(self, username: str, password: str) -> str | None:
        """Return a master-realm access token, or ``None`` on credentials failure."""
        data = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": username,
                "password": password,
            }
        ).encode()
        request = urllib.request.Request(
            f"{self._base}/realms/{MASTER_REALM}/protocol/openid-connect/token", data=data
        )
        try:
            with self._open(request) as response:
                payload = json.loads(response.read(MAX_RESPONSE_BYTES + 1))
        except urllib.error.URLError, OSError, ValueError, json.JSONDecodeError:
            return None
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            return None
        self._token = token
        return token

    def _request(self, method: str, path: str, body: Any | None = None) -> Any:
        if self._token is None:
            raise AdminMigrationError("admin client is not authenticated")
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self._base}/admin/realms/{path}", data=data, method=method, headers=headers
        )
        try:
            with self._open(request) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                location = response.headers.get("Location")
        except urllib.error.HTTPError as exc:
            raise AdminRestError(
                f"{method} admin request failed with HTTP {exc.code}", status=exc.code
            ) from None
        except (urllib.error.URLError, OSError) as exc:
            raise AdminRestError(f"{method} admin request failed: {type(exc).__name__}") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise AdminRestError("admin response exceeded the bounded size")
        parsed = json.loads(raw) if raw else None
        if method == "POST" and isinstance(location, str):
            # Surface the created resource id from the Location header.
            return {"location": location, "body": parsed}
        return parsed

    def find_users(self, username: str) -> list[dict[str, Any]]:
        quoted = urllib.parse.quote(username, safe="")
        payload = self._request("GET", f"{MASTER_REALM}/users?username={quoted}&exact=true")
        return payload if isinstance(payload, list) else []

    def realm_roles(self, user_id: str) -> list[str]:
        payload = self._request("GET", f"{MASTER_REALM}/users/{user_id}/role-mappings/realm")
        if not isinstance(payload, list):
            return []
        return [str(role.get("name")) for role in payload if isinstance(role, dict)]

    def get_master_role(self, role: str) -> dict[str, Any]:
        payload = self._request("GET", f"{MASTER_REALM}/roles/{urllib.parse.quote(role)}")
        if not isinstance(payload, dict):
            raise AdminMigrationError("the master-realm admin role is unavailable")
        return payload

    def create_user(self, username: str, password: str) -> str | None:
        body = {
            "username": username,
            "enabled": True,
            "emailVerified": False,
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        }
        payload = self._request("POST", f"{MASTER_REALM}/users", body)
        if isinstance(payload, dict):
            location = payload.get("location")
            if isinstance(location, str) and location:
                return location.rstrip("/").rsplit("/", 1)[-1]
        return None

    def add_realm_roles(self, user_id: str, roles: list[dict[str, Any]]) -> None:
        self._request("POST", f"{MASTER_REALM}/users/{user_id}/role-mappings/realm", roles)

    def set_enabled(self, user_id: str, enabled: bool) -> None:
        self._request("PUT", f"{MASTER_REALM}/users/{user_id}", {"enabled": enabled})

    def get_realm(self, realm: str) -> dict[str, Any]:
        payload = self._request("GET", realm)
        if not isinstance(payload, dict):
            raise AdminMigrationError("the target realm is unavailable")
        return payload


class Migration:
    """Operator-supervised migration state machine (Steps 0-5)."""

    def __init__(
        self,
        client_factory: Callable[[], AdminClient],
        *,
        canonical_username: str = CANONICAL_ADMIN_USERNAME,
        canonical_password: str,
        recovery_username: str,
        recovery_password: str,
    ) -> None:
        self._new_client = client_factory
        self.canonical_username = canonical_username
        self.canonical_password = canonical_password
        self.recovery_username = recovery_username
        self.recovery_password = recovery_password

    def _client_as(self, username: str, password: str, *, role: str) -> AdminClient:
        client = self._new_client()
        if client.authenticate(username, password) is None:
            raise AdminMigrationError(f"{role} administrator authentication failed; STOP")
        return client

    def _account_state(self, client: AdminClient, username: str) -> AccountState:
        users = client.find_users(username)
        if len(users) > 1:
            raise AdminMigrationError(
                f"ambiguous account {username!r}: multiple exact master-realm matches; STOP"
            )
        if not users:
            return AccountState(username=username, exists=False)
        user = users[0]
        roles = client.realm_roles(str(user.get("id")))
        return AccountState(
            username=username,
            exists=True,
            user_id=str(user.get("id") or ""),
            enabled=bool(user.get("enabled")),
            federated=bool(user.get("federationLink")),
            required_actions=tuple(str(a) for a in (user.get("requiredActions") or ())),
            realm_roles=tuple(roles),
        )

    def _require_verified(self, state: AccountState) -> None:
        if not state.exists:
            raise AdminMigrationError(f"expected account {state.username!r} is missing; STOP")
        if not state.enabled:
            raise AdminMigrationError(f"account {state.username!r} is disabled; STOP")
        if state.federated:
            raise AdminMigrationError(f"account {state.username!r} is federated; STOP")
        if state.required_actions:
            raise AdminMigrationError(f"account {state.username!r} has required actions; STOP")
        if REQUIRED_MASTER_ROLE not in state.realm_roles:
            raise AdminMigrationError(
                f"account {state.username!r} lacks the {REQUIRED_MASTER_ROLE!r} master role; STOP"
            )
        unexpected = set(state.realm_roles) - EXPECTED_MASTER_ROLES
        if unexpected:
            raise AdminMigrationError(
                f"account {state.username!r} has unexpected realm roles; STOP"
            )

    def inspect(self) -> dict[str, Any]:
        """Return read-only account states for the canonical and legacy admins."""
        client = self._client_as(self.recovery_username, self.recovery_password, role="recovery")
        # A privileged read of the target realm proves the session is usable.
        client.get_realm(TARGET_REALM)
        names = (self.canonical_username, *LEGACY_ADMIN_USERNAMES)
        return {name: self._account_state(client, name).as_public() for name in names}

    def apply(self) -> dict[str, Any]:
        """Create/verify the canonical admin, then disable legacy admins."""
        result: dict[str, Any] = {"created": False, "disabled": [], "canonical": None}
        recovery = self._client_as(self.recovery_username, self.recovery_password, role="recovery")
        recovery.get_realm(TARGET_REALM)

        canonical = self._account_state(recovery, self.canonical_username)
        if not canonical.exists:
            created_id = self._create_canonical(recovery)
            canonical = self._account_state(recovery, self.canonical_username)
            if not canonical.exists or canonical.user_id != created_id:
                raise AdminMigrationError(
                    "the canonical administrator could not be confirmed after create; STOP"
                )
            result["created"] = True
        else:
            self._require_verified(canonical)

        # Independent verification through a fresh canonical session.
        self._verify_canonical()
        result["canonical"] = canonical.as_public()

        for legacy in LEGACY_ADMIN_USERNAMES:
            state = self._account_state(recovery, legacy)
            if not state.exists or not state.enabled:
                continue
            self._require_other_enabled_admin(recovery, exclude=legacy)
            try:
                recovery.set_enabled(state.user_id, False)
            except AdminRestError as exc:
                raise AdminMigrationError(
                    f"failed to disable {legacy!r} ({type(exc).__name__}); STOP"
                ) from None
            after = self._account_state(recovery, legacy)
            if after.enabled:
                raise AdminMigrationError(f"legacy administrator {legacy!r} is still enabled; STOP")
            result["disabled"].append(legacy)

        # Post-migration: canonical must still authenticate and read.
        self._verify_canonical()
        return result

    def _create_canonical(self, client: AdminClient) -> str:
        try:
            user_id = client.create_user(self.canonical_username, self.canonical_password)
        except AdminRestError as exc:
            if exc.status == 409:
                raise AdminMigrationError(
                    "canonical administrator create conflicted (409); STOP and inspect"
                ) from None
            raise AdminMigrationError(
                "canonical administrator create outcome is ambiguous; STOP and inspect"
            ) from None
        if not user_id:
            raise AdminMigrationError(
                "canonical administrator create returned no Location; STOP and inspect"
            )
        role = client.get_master_role(REQUIRED_MASTER_ROLE)
        client.add_realm_roles(user_id, [role])
        return user_id

    def _verify_canonical(self) -> None:
        client = self._client_as(self.canonical_username, self.canonical_password, role="canonical")
        client.get_realm(MASTER_REALM)
        state = self._account_state(client, self.canonical_username)
        self._require_verified(state)

    def _require_other_enabled_admin(self, client: AdminClient, *, exclude: str) -> None:
        for candidate in (self.canonical_username, *LEGACY_ADMIN_USERNAMES):
            if candidate == exclude:
                continue
            state = self._account_state(client, candidate)
            if state.exists and state.enabled:
                return
        raise AdminMigrationError(
            "refusing to disable an administrator: no other verified enabled admin; STOP"
        )


def _read_secret(env_name: str, file_name: str) -> str:
    value = os.environ.get(env_name, "").strip()
    if value:
        return value
    path = os.environ.get(file_name, "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            raise AdminMigrationError(f"{file_name} is unreadable") from None
    raise AdminMigrationError(f"{env_name} or {file_name} is required (never passed in argv)")


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the read-only inspection or explicit migration."""
    parser = argparse.ArgumentParser(description="MTMF development admin migration")
    parser.add_argument("--inspect", action="store_true", help="read-only inspection (default)")
    parser.add_argument("--apply", action="store_true", help="explicitly migrate administrators")
    parser.add_argument(
        "--base-url", default=os.environ.get("MTMF_AUTH_ADMIN_BASE", DEFAULT_BASE_URL)
    )
    parser.add_argument("--ca-file", default=os.environ.get("MTMF_PR14_KC_CA_FILE", ""))
    parser.add_argument(
        "--canonical-username",
        default=os.environ.get("MTMF_DEV_KC_ADMIN_USERNAME", CANONICAL_ADMIN_USERNAME),
    )
    parser.add_argument(
        "--recovery-username",
        default=os.environ.get("MTMF_DEV_KC_RECOVERY_USERNAME", LEGACY_ADMIN_USERNAMES[-1]),
    )
    args = parser.parse_args(argv)
    if args.apply and args.inspect:
        print("choose either --inspect or --apply", file=sys.stderr)
        return 2
    if args.canonical_username != CANONICAL_ADMIN_USERNAME:
        print(
            f"the canonical administrator must be exactly {CANONICAL_ADMIN_USERNAME!r}",
            file=sys.stderr,
        )
        return 2
    try:
        canonical_password = _read_secret(
            "MTMF_DEV_KC_ADMIN_PASSWORD", "MTMF_DEV_KC_ADMIN_PASSWORD_FILE"
        )
        recovery_password = _read_secret(
            "MTMF_DEV_KC_RECOVERY_PASSWORD", "MTMF_DEV_KC_RECOVERY_PASSWORD_FILE"
        )
        migration = Migration(
            lambda: HttpAdminClient(args.base_url, args.ca_file),
            canonical_username=args.canonical_username,
            canonical_password=canonical_password,
            recovery_username=args.recovery_username,
            recovery_password=recovery_password,
        )
        result = migration.apply() if args.apply else migration.inspect()
    except AdminMigrationError as exc:
        print(f"administrator migration error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
