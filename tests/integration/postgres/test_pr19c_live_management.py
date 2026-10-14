"""PR 19C live acceptance: real Keycloak -> deployed MTMF service -> PostgreSQL.

Opt-in and authoritative only when ``MTMF_PR19C_LIVE=1`` and the isolated
acceptance topology is running. The authoritative path is **black-box HTTP**:
this module sends requests to the Compose-managed MTMF ``service`` on the fixed
loopback URL ``http://127.0.0.1:29001`` (``MTMF_PR19C_SERVICE_URL``). It never
constructs or starts an MTMF application/server. Real Keycloak issues both
tokens; the deployed service (restricted ``mtmf_runtime``) authorizes and
mutates; this process only seeds the fixture (privileged, committed) and reads
back committed membership/audit state.

Without the flag the module is skipped (ordinary ``--integration``). The
acceptance launcher sets the flag and requires four passes / zero skips.

Tokens, secrets and admin credentials are never printed or persisted.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

import httpx
import psycopg
import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("MTMF_PR19C_LIVE") != "1",
    reason="live PR 19C management acceptance is opt-in (set MTMF_PR19C_LIVE=1)",
)

REALM = os.environ.get("MTMF_AUTH_ADMIN_REALM", "mtmf-dev")
SAME_CLIENT = "mtmf-evidence-same-client"
SAME_SECRET = "mtmf-evidence-same-client-dev-secret"
SHARED_AUDIENCE = "mtmf-same-client-api"
STEWARD_USER = "mtmf-user-bob"
NON_STEWARD_USER = "mtmf-user-carol"
ROUTE = "/v1/management/identity-group-memberships"
TENANT_ADMIN_URN = "urn:mtmf:iam:roles:system:tenant-administrator"
ACTION_URN = "urn:mtmf:iam:actions:system:identity-group-membership:add-object"

#: The fixed acceptance service URL env var. The authoritative acceptance
#: topology publishes the deployed service on exactly this loopback address.
SERVICE_URL_ENV = "MTMF_PR19C_SERVICE_URL"
REQUIRED_SERVICE_URL = "http://127.0.0.1:29001"

_EVIDENCE = Path(__file__).resolve().parents[3] / "scripts" / "pr14-keycloak-evidence.py"
_spec = importlib.util.spec_from_file_location("pr14_keycloak_evidence", _EVIDENCE)
assert _spec is not None and _spec.loader is not None
ev = importlib.util.module_from_spec(_spec)
sys.modules["pr14_keycloak_evidence"] = ev
_spec.loader.exec_module(ev)


def _env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"live acceptance requires {name}")
    return value


def _service_base_url() -> str:
    """Return the fixed deployed-service base URL or fail closed.

    The authoritative acceptance service is exactly ``http://127.0.0.1:29001``.
    A missing or different value is a hard failure; this never starts a local
    server and never accepts an arbitrary remote address.
    """
    value = os.environ.get(SERVICE_URL_ENV, "").strip().rstrip("/")
    if not value:
        raise RuntimeError(f"live acceptance requires {SERVICE_URL_ENV}")
    if value != REQUIRED_SERVICE_URL:
        raise RuntimeError(
            f"{SERVICE_URL_ENV} must be exactly {REQUIRED_SERVICE_URL!r} for PR 19C acceptance"
        )
    return value


def _kc_base() -> str:
    return os.environ.get("MTMF_PR19C_KC_BASE", "").strip() or _env("MTMF_PR14_KC_BASE")


def _ca_file() -> str:
    return os.environ.get("MTMF_PR19C_CA_FILE", "").strip() or _env("MTMF_PR14_KC_CA_FILE")


def _user_password() -> str:
    return os.environ.get("MTMF_PR19C_USER_PASSWORD", "").strip() or _env(
        "MTMF_PR14_KC_USER_PASSWORD"
    )


def _uuid() -> str:
    import uuid

    return str(uuid.uuid4())


def _issuer_str() -> str:
    return f"{_kc_base()}/realms/{REALM}"


def _keycloak_issuer() -> Any:
    return ev.Issuer(base=_kc_base(), realm=REALM, ca_file=_ca_file())


def _service_token() -> str:
    return str(
        ev.client_credentials_token(_keycloak_issuer(), SAME_CLIENT, SAME_SECRET)["access_token"]
    )


def _user_token(user: str) -> str:
    token = ev.authorization_code_token(
        _keycloak_issuer(),
        SAME_CLIENT,
        SAME_SECRET,
        user,
        _user_password(),
        "http://127.0.0.1:28400/callback",
        28400,
    )
    return str(token["access_token"])


def _subject(token: str) -> str:
    return str(ev.decode_unverified(token)[1]["sub"])


def _seed(
    db: psycopg.Connection, *, steward_subject: str, non_steward_subject: str
) -> dict[str, str]:
    """Provision the PR 19C live fixture through the authorized primitives.

    The ``db`` fixture is autocommit, so every statement here is committed
    before the separate deployed service is called.
    """
    principal, steward, non_steward, target = (_uuid() for _ in range(4))
    tenant, other_tenant, group = (_uuid() for _ in range(3))
    application = _uuid()
    db.execute(
        "INSERT INTO mtmf.principal (id, name, deletion_status) VALUES (%s,'P',2)", (principal,)
    )
    for identity, name in ((steward, "Steward"), (non_steward, "Other"), (target, "Target")):
        db.execute(
            "INSERT INTO mtmf.identity (id, principal_id, name, origin, deletion_status) "
            "VALUES (%s,%s,%s,2,2)",
            (identity, principal, name),
        )
    db.execute(
        "INSERT INTO mtmf.tenant (id, name, scope, owner_identity_id, lifecycle, deletion_status) "
        "VALUES (%s,'T',2,%s,1,2), (%s,'O',2,%s,1,2)",
        (tenant, steward, other_tenant, steward),
    )
    db.execute("INSERT INTO mtmf.principal_tenant_membership VALUES (%s,%s)", (principal, tenant))
    for identity in (steward, non_steward, target):
        db.execute("INSERT INTO mtmf.identity_tenant_membership VALUES (%s,%s)", (identity, tenant))
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s,%s,'G',2)",
        (group, tenant),
    )
    db.execute("INSERT INTO mtmf.group_tenant_membership VALUES (%s,%s)", (group, tenant))
    db.execute(
        "INSERT INTO mtmf.identity_role_assignment (id, tenant_id, identity_id, role_urn) "
        "VALUES (%s,%s,%s,%s)",
        (_uuid(), tenant, steward, TENANT_ADMIN_URN),
    )
    db.execute(
        "INSERT INTO mtmf.stewardship_designation "
        "(tenant_id, steward_principal_id, designated_identity_id, version) VALUES (%s,%s,%s,1)",
        (tenant, principal, steward),
    )
    db.execute(
        "SELECT mtmf.application_add(%s,%s,'A',%s,1::smallint,'{}'::jsonb)",
        (application, f"app-{_uuid()[:8]}", steward),
    )
    db.execute(
        "SELECT mtmf.application_tenant_registration_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), application, tenant, steward),
    )
    from datetime import UTC, datetime, timedelta

    db.execute(
        "SELECT mtmf.tenant_application_subscription_add(%s,%s,%s,%s,1::smallint,%s,%s,now())",
        (_uuid(), application, tenant, steward, datetime.now(UTC) - timedelta(days=1), None),
    )
    db.execute(
        "SELECT mtmf.service_credential_application_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), SAME_CLIENT, application),
    )
    db.execute(
        "SELECT mtmf.external_subject_identity_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), steward_subject, steward),
    )
    db.execute(
        "SELECT mtmf.external_subject_identity_add(%s,%s,%s,%s,1::smallint,now())",
        (_uuid(), _issuer_str(), non_steward_subject, non_steward),
    )
    return {
        "tenant": tenant,
        "other_tenant": other_tenant,
        "steward": steward,
        "non_steward": non_steward,
        "target": target,
        "group": group,
        "application": application,
    }


@pytest.fixture(scope="module", autouse=True)
def deployed_service_ready() -> None:
    """Require the deployed acceptance service to be reachable and ready.

    A connection refusal, timeout, or non-200 is a hard failure. This never
    starts a replacement application.
    """
    base = _service_base_url()
    response = httpx.get(f"{base}/health/ready", timeout=10)
    if response.status_code != 200:
        raise RuntimeError(f"deployed acceptance service is not ready: HTTP {response.status_code}")


def _post(
    *, service: str, user: str, ids: dict[str, str], group: str | None = None
) -> httpx.Response:
    body = {
        "tenant_id": ids["tenant"],
        "identity_id": ids["target"],
        "group_id": group or ids["group"],
    }
    return httpx.post(
        f"{_service_base_url()}{ROUTE}",
        json=body,
        headers={
            "Authorization": f"Bearer {service}",
            "X-MTMF-User-Authorization": f"Bearer {user}",
        },
        timeout=30,
    )


def _membership_count(db: psycopg.Connection, ids: dict[str, str]) -> int:
    return int(
        db.execute(
            "SELECT count(*) FROM mtmf.identity_group_membership "
            "WHERE identity_id = %s AND group_id = %s",
            (ids["target"], ids["group"]),
        ).fetchone()[0]
    )


def _matching_audit_rows(
    db: psycopg.Connection, group_id: str, target_id: str
) -> list[tuple[object, ...]]:
    """Return committed audit rows for this test's exact target and Action."""
    return list(
        db.execute(
            "SELECT actor_identity_id, action_urn, target_kind, target_id, "
            "subject_identity_id, outcome FROM mtmf.security_mutation_audit "
            "WHERE target_kind = 'identity_group_membership' AND target_id = %s "
            "AND subject_identity_id = %s AND action_urn = %s",
            (group_id, target_id, ACTION_URN),
        ).fetchall()
    )


def test_h01_h02_live_created_then_authorized_no_op(db: psycopg.Connection) -> None:
    ids = _seed(
        db,
        steward_subject=_subject(_user_token(STEWARD_USER)),
        non_steward_subject=_subject(_user_token(NON_STEWARD_USER)),
    )
    created = _post(service=_service_token(), user=_user_token(STEWARD_USER), ids=ids)
    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store"
    assert created.json() == {
        "tenant_id": ids["tenant"],
        "identity_id": ids["target"],
        "group_id": ids["group"],
        "created": True,
    }
    assert _membership_count(db, ids) == 1
    rows = _matching_audit_rows(db, ids["group"], ids["target"])
    assert len(rows) == 1
    actor, action_urn, target_kind, target_id, subject_identity_id, outcome = rows[0]
    assert str(actor) == ids["steward"]
    assert action_urn == ACTION_URN
    assert target_kind == "identity_group_membership"
    assert str(target_id) == ids["group"]
    assert str(subject_identity_id) == ids["target"]
    assert outcome == "CREATED"

    repeated = _post(service=_service_token(), user=_user_token(STEWARD_USER), ids=ids)
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["created"] is False
    assert _membership_count(db, ids) == 1
    assert len(_matching_audit_rows(db, ids["group"], ids["target"])) == 1


def test_h03_non_steward_actor_is_opaque_forbidden(db: psycopg.Connection) -> None:
    ids = _seed(
        db,
        steward_subject=_subject(_user_token(STEWARD_USER)),
        non_steward_subject=_subject(_user_token(NON_STEWARD_USER)),
    )
    response = _post(service=_service_token(), user=_user_token(NON_STEWARD_USER), ids=ids)
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert _membership_count(db, ids) == 0
    assert _matching_audit_rows(db, ids["group"], ids["target"]) == []


def test_h04_cross_tenant_target_is_denied_without_disclosure(
    db: psycopg.Connection,
) -> None:
    ids = _seed(
        db,
        steward_subject=_subject(_user_token(STEWARD_USER)),
        non_steward_subject=_subject(_user_token(NON_STEWARD_USER)),
    )
    # A Group bound to a different Tenant: the lock helper rejects it opaquely.
    other_group = _uuid()
    db.execute(
        "INSERT INTO mtmf.group (id, tenant_id, name, deletion_status) VALUES (%s,%s,'O',2)",
        (other_group, ids["other_tenant"]),
    )
    db.execute(
        "INSERT INTO mtmf.group_tenant_membership VALUES (%s,%s)",
        (other_group, ids["other_tenant"]),
    )
    response = _post(
        service=_service_token(), user=_user_token(STEWARD_USER), ids=ids, group=other_group
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"]["code"] == "FORBIDDEN"
    assert _membership_count(db, ids) == 0
    assert _matching_audit_rows(db, ids["group"], ids["target"]) == []
    assert _matching_audit_rows(db, other_group, ids["target"]) == []


def test_h05_invalid_or_wrong_slot_tokens_never_succeed(db: psycopg.Connection) -> None:
    ids = _seed(
        db,
        steward_subject=_subject(_user_token(STEWARD_USER)),
        non_steward_subject=_subject(_user_token(NON_STEWARD_USER)),
    )
    body = {"tenant_id": ids["tenant"], "identity_id": ids["target"], "group_id": ids["group"]}
    base = _service_base_url()
    missing_user = httpx.post(
        f"{base}{ROUTE}",
        json=body,
        headers={"Authorization": f"Bearer {_service_token()}"},
        timeout=30,
    )
    assert missing_user.status_code in (401, 403), missing_user.text
    service_as_user = httpx.post(
        f"{base}{ROUTE}",
        json=body,
        headers={
            "Authorization": f"Bearer {_service_token()}",
            "X-MTMF-User-Authorization": f"Bearer {_service_token()}",
        },
        timeout=30,
    )
    assert service_as_user.status_code in (401, 403), service_as_user.text
    assert _membership_count(db, ids) == 0
    assert _matching_audit_rows(db, ids["group"], ids["target"]) == []
