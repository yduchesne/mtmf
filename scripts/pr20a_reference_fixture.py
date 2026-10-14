#!/usr/bin/env python3
"""PR 20A reference-consumer fixture definitions and privileged provisioning.

This module holds the *reviewed, fixture-only* policy values for the PR 20A
reference application and the narrow privileged operations that register and
grant them. It introduces no new generic management API: it calls only the
existing sanctioned ``action_add`` / ``role_add`` / ``identity_role_assignment_add``
primitives as the owner/migrator identity, exactly like the existing development
initializer.

The reference document-read Action and Permission are **not** part of the
protected built-in manifest. They are registered as independent shared
definitions and granted through a new TENANT-defined Role owned by the fixture
Tenant. No built-in Role is modified, no default grant is widened, and no new
runtime privilege is granted.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any
from uuid import UUID

#: Deterministic namespace reused from the development initializer so fixture
#: identifiers are stable and non-secret.
FIXTURE_NAMESPACE = uuid.UUID("6f2c1f0e-6f4f-4b64-9b5e-2f6d1f2a4c17")

#: The reviewed exact Action and matching Permission for the reference PEP.
DOCUMENT_READ_ACTION = "urn:mtmf:iam:actions:system:document:read-object"
DOCUMENT_READ_PERMISSION = "urn:mtmf:iam:permissions:system:document:read-object"

#: The default registered Application key. Its OAuth client has an approved
#: audience mapper and a Client Credentials service account, so the reference
#: app uses the same confidential client for its service token and the
#: fixture user's authorization-code token.
DEFAULT_APPLICATION_KEY = "evidence-same-client"

#: Human-readable fixture names.
REFERENCE_ROLE_NAME = "Reference Document Reader"
REFERENCE_ROLE_DESCRIPTION = "PR 20A fixture-only Tenant-scoped document read grant"


class ReferenceFixtureError(RuntimeError):
    """The reference fixture could not be provisioned without conflict."""


def deterministic(name: str) -> UUID:
    """Derive a stable fixture UUID from a non-secret manifest name."""
    return uuid.uuid5(FIXTURE_NAMESPACE, name)


def application_id(application_key: str) -> UUID:
    """Return the deterministic Application UUID for ``application_key``."""
    return deterministic(f"application:{application_key}")


def reference_role_urn(tenant_id: UUID) -> str:
    """Return the fixture TENANT-defined Role URN for ``tenant_id``."""
    return f"urn:mtmf:iam:roles:tenant:{tenant_id}:reference-document-reader"


def reference_role_payload(tenant_id: UUID) -> dict[str, Any]:
    """Return the complete Role aggregate payload for the fixture grant."""
    role_urn = reference_role_urn(tenant_id)
    set_id = deterministic(f"reference-document-permission-set:{tenant_id}")
    permission_id = deterministic(f"reference-document-permission:{tenant_id}")
    return {
        "urn": role_urn,
        "name": REFERENCE_ROLE_NAME,
        "description": REFERENCE_ROLE_DESCRIPTION,
        "defining_tenant_id": str(tenant_id),
        "extension": {},
        "permission_sets": [
            {
                "id": str(set_id),
                "role_urn": role_urn,
                "effect": "allow",
                "permissions": [
                    {
                        "id": str(permission_id),
                        "permission_set_id": str(set_id),
                        "urn": DOCUMENT_READ_PERMISSION,
                    }
                ],
            }
        ],
    }


def reference_assignment_id(tenant_id: UUID, identity_id: UUID) -> UUID:
    """Return the deterministic IdentityRoleAssignment UUID for the fixture."""
    return deterministic(f"reference-document-assignment:{tenant_id}:{identity_id}")


def ensure_document_read_action(provisioner: Any) -> None:
    """Register the exact reference Action (idempotent)."""
    provisioner._execute("SELECT mtmf.action_add(%s)", (DOCUMENT_READ_ACTION,))


def ensure_document_role(provisioner: Any, tenant_id: UUID) -> None:
    """Create or validate the fixture TENANT-defined Role aggregate.

    When the Role is absent, it is created with exactly
    :func:`reference_role_payload`. When it exists, its **security-relevant**
    aggregate (permission-set identity/ownership/effect and permission
    identity/parent/URN, including multiplicity) must match the canonical
    payload exactly. Any drift -- extra sets, extra/duplicate permissions,
    missing rows, changed ids, DENY effects, or foreign ownership -- fails
    closed and is never repaired or overwritten. Mutable display-only fields
    (``name``, ``description``) and the generic ``extension`` are not part of
    this security-relevant comparison.
    """
    role_urn = reference_role_urn(tenant_id)
    existing_tenant = provisioner._scalar(
        "SELECT defining_tenant_id FROM mtmf.role WHERE urn = %s", (role_urn,)
    )
    if existing_tenant is None:
        provisioner._execute(
            "SELECT mtmf.role_add(%s::jsonb)",
            (json.dumps(reference_role_payload(tenant_id)),),
        )
        return
    if str(existing_tenant) != str(tenant_id):
        raise ReferenceFixtureError("the reference Role exists in another definition namespace")
    if _read_role_aggregate(provisioner, role_urn) != _expected_role_aggregate(tenant_id):
        raise ReferenceFixtureError(
            "the reference Role aggregate differs from the approved fixture"
        )


def _expected_role_aggregate(tenant_id: UUID) -> list[tuple[Any, ...]]:
    """Return the exact ordered ``(set, role, effect, permission...)`` rows.

    The canonical payload has exactly one ALLOW permission set with exactly one
    Permission, so the expected aggregate is a single row. It is derived from
    the payload rather than restated so the two can never drift apart.
    """
    payload = reference_role_payload(tenant_id)
    rows: list[tuple[Any, ...]] = []
    for permission_set in payload["permission_sets"]:
        for permission in permission_set["permissions"]:
            rows.append(
                (
                    permission_set["id"],
                    permission_set["role_urn"],
                    permission_set["effect"],
                    permission["id"],
                    permission["permission_set_id"],
                    permission["urn"],
                )
            )
    return rows


def _read_role_aggregate(provisioner: Any, role_urn: str) -> list[tuple[Any, ...]]:
    """Read the persisted Role aggregate as deterministic, multiplicity-preserving rows.

    A ``LEFT JOIN`` from permission sets to permissions preserves an empty set as
    a row of ``NULL`` permission columns, so a missing Permission can never be
    mistaken for a matching aggregate. Rows are ordered by set and permission
    id; UUIDs are canonicalized to ``str`` for comparison with the payload.
    """
    result = provisioner._execute(
        "SELECT ps.id, ps.role_urn, ps.effect, p.id, p.permission_set_id, p.urn "
        "FROM mtmf.permission_set AS ps "
        "LEFT JOIN mtmf.permission AS p ON p.permission_set_id = ps.id "
        "WHERE ps.role_urn = %s "
        "ORDER BY ps.id, p.id",
        (role_urn,),
    ).fetchall()
    return [
        tuple(str(value) if isinstance(value, uuid.UUID) else value for value in row)
        for row in result
    ]


def ensure_document_role_assignment(provisioner: Any, tenant_id: UUID, identity_id: UUID) -> None:
    """Grant the fixture Role to exactly one Identity in the fixture Tenant."""
    assignment_id = reference_assignment_id(tenant_id, identity_id)
    provisioner._execute(
        "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, NULL)",
        (assignment_id, tenant_id, identity_id, reference_role_urn(tenant_id)),
    )


def write_fixture_mapping(
    path: Path,
    *,
    application_id_value: UUID,
    tenant_id: UUID,
    subjects: dict[str, UUID],
) -> None:
    """Write the non-secret subject/Application/Tenant fixture mapping."""
    payload = {
        "version": 1,
        "application_id": str(application_id_value),
        "tenant_id": str(tenant_id),
        "subjects": {subject: str(tenant_id) for subject in subjects},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
