#!/usr/bin/env python3
"""PR 20B follow-up 01: privileged metadata-read fixture provisioning.

This is a development/acceptance-only one-shot helper. It registers the
owner-approved genuine second Document operation:

- exact Action ``urn:mtmf:iam:actions:system:document:read-metadata``;
- matching Permission;
- one TENANT-defined Role ``...:reference-document-metadata-reader`` with a
  single ALLOW permission set and a single metadata Permission;
- deterministic metadata-reader assignments for **both** the fixture allowed
  and denied identities (Alice and Bob).

It introduces no new generic management API, no migration, no built-in policy
change, and no runtime grant. It calls only the existing sanctioned
``action_add`` / ``role_add`` / ``identity_role_assignment_add`` primitives as
the authenticated ``mtmf_migrator`` identity, exactly like the PR 20A
initializer. Drift in an existing aggregate fails closed and is never repaired.

The subject identities are discovered from the persisted fixture state: the
subject whose Identity already holds the PR 20A content-reader assignment is
the allowed user; the other fixture subject is the denied user. Identity IDs
are derived from the established deterministic initializer convention.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any
from uuid import UUID

REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPTS = REPO_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import pr20a_reference_fixture as content_fixture  # noqa: E402

_DEV_INITIALIZER = _SCRIPTS / "mtmf-dev-initialize.py"

#: Approved exact Action and matching Permission for the metadata read.
METADATA_ACTION = "urn:mtmf:iam:actions:system:document:read-metadata"
METADATA_PERMISSION = "urn:mtmf:iam:permissions:system:document:read-metadata"

METADATA_ROLE_NAME = "Reference Document Metadata Reader"
METADATA_ROLE_DESCRIPTION = "PR 20B fixture-only Tenant-scoped document metadata read grant"


class MetadataFixtureError(RuntimeError):
    """The metadata fixture could not be provisioned without conflict."""


def _load_dev_initializer() -> Any:
    spec = importlib.util.spec_from_file_location("pr20b_metadata_dev_initialize", _DEV_INITIALIZER)
    if spec is None or spec.loader is None:
        raise MetadataFixtureError("the development initializer could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules["pr20b_metadata_dev_initialize"] = module
    spec.loader.exec_module(module)
    return module


dev = _load_dev_initializer()


def metadata_role_urn(tenant_id: UUID) -> str:
    """Return the fixture TENANT-defined metadata Role URN."""
    return f"urn:mtmf:iam:roles:tenant:{tenant_id}:reference-document-metadata-reader"


def metadata_role_payload(tenant_id: UUID) -> dict[str, Any]:
    """Return the canonical metadata Role aggregate payload."""
    role_urn = metadata_role_urn(tenant_id)
    set_id = dev._deterministic(f"reference-document-metadata-permission-set:{tenant_id}")
    permission_id = dev._deterministic(f"reference-document-metadata-permission:{tenant_id}")
    return {
        "urn": role_urn,
        "name": METADATA_ROLE_NAME,
        "description": METADATA_ROLE_DESCRIPTION,
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
                        "urn": METADATA_PERMISSION,
                    }
                ],
            }
        ],
    }


def metadata_assignment_id(tenant_id: UUID, identity_id: UUID) -> UUID:
    """Return the deterministic metadata-reader assignment UUID."""
    return dev._deterministic(f"reference-document-metadata-assignment:{tenant_id}:{identity_id}")


def identity_id_for_subject(subject: str) -> UUID:
    """Return the established deterministic Identity UUID for ``subject``."""
    return dev._deterministic(f"user-identity:{subject}")


def ensure_metadata_action(provisioner: Any) -> None:
    """Register the exact metadata Action (idempotent)."""
    provisioner._execute("SELECT mtmf.action_add(%s)", (METADATA_ACTION,))


def _expected_aggregate(tenant_id: UUID) -> list[tuple[Any, ...]]:
    payload = metadata_role_payload(tenant_id)
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


def ensure_metadata_role(provisioner: Any, tenant_id: UUID) -> None:
    """Create or validate the metadata Role aggregate (drift fails closed)."""
    role_urn = metadata_role_urn(tenant_id)
    existing_tenant = provisioner._scalar(
        "SELECT defining_tenant_id FROM mtmf.role WHERE urn = %s", (role_urn,)
    )
    if existing_tenant is None:
        provisioner._execute(
            "SELECT mtmf.role_add(%s::jsonb)",
            (json.dumps(metadata_role_payload(tenant_id)),),
        )
        return
    if str(existing_tenant) != str(tenant_id):
        raise MetadataFixtureError("the metadata Role exists in another definition namespace")
    if content_fixture._read_role_aggregate(provisioner, role_urn) != _expected_aggregate(
        tenant_id
    ):
        raise MetadataFixtureError("the metadata Role aggregate differs from the approved fixture")


def ensure_metadata_assignment(provisioner: Any, tenant_id: UUID, identity_id: UUID) -> None:
    """Grant the metadata Role to exactly one Identity (idempotent)."""
    provisioner._execute(
        "SELECT mtmf.identity_role_assignment_add(%s, %s, %s, %s, NULL)",
        (
            metadata_assignment_id(tenant_id, identity_id),
            tenant_id,
            identity_id,
            metadata_role_urn(tenant_id),
        ),
    )


def _read_mapping(path: Path) -> tuple[UUID, list[str]]:
    if not path.is_file():
        raise MetadataFixtureError("the reference-app fixture mapping was not found")
    payload = json.loads(path.read_text(encoding="utf-8"))
    tenant_id = UUID(str(payload["tenant_id"]))
    subjects = list(payload["subjects"])
    if len(subjects) != 2:
        raise MetadataFixtureError("the fixture mapping must contain exactly two subjects")
    return tenant_id, subjects


def classify_subjects(provisioner: Any, tenant_id: UUID, subjects: list[str]) -> dict[str, str]:
    """Classify the two fixture subjects into allowed (content) and denied.

    The allowed subject is the one whose Identity already holds the PR 20A
    content-reader assignment; the other is the denied subject. This uses the
    persisted, authoritative binding rather than a caller-supplied label.
    """
    content_assignment_ids = {
        content_fixture.reference_assignment_id(
            tenant_id, identity_id_for_subject(subject)
        ): subject
        for subject in subjects
    }
    found = provisioner._execute(
        "SELECT id FROM mtmf.identity_role_assignment WHERE id = ANY(%s)",
        (list(content_assignment_ids),),
    ).fetchall()
    present = {row[0] for row in found}
    allowed = [
        subject for assignment, subject in content_assignment_ids.items() if assignment in present
    ]
    denied = [
        subject
        for assignment, subject in content_assignment_ids.items()
        if assignment not in present
    ]
    if len(allowed) != 1 or len(denied) != 1:
        raise MetadataFixtureError("could not classify exactly one allowed and one denied subject")
    return {"allowed": allowed[0], "denied": denied[0]}


def _require_development() -> None:
    from mtmf_service.settings import DeploymentMode, ServiceSettings

    if ServiceSettings.from_env().deployment_mode is not DeploymentMode.DEVELOPMENT:
        raise MetadataFixtureError("the PR 20B metadata fixture requires the development profile")


def _expected_database() -> str:
    value = os.environ.get("MTMF_PR20B_ACCEPTANCE_DB", "").strip()
    if not value:
        raise MetadataFixtureError(
            "MTMF_PR20B_ACCEPTANCE_DB must name the isolated acceptance database"
        )
    return value


def _open() -> Any:
    from mtmf_core.persistence.postgres import PostgresConfig, PostgresRole

    provisioner = dev.PostgresProvisioner(PostgresConfig.from_env(PostgresRole.MIGRATOR))
    provisioner.acquire()
    try:
        actual = provisioner._scalar("SELECT current_database()", ())
        if str(actual) != _expected_database():
            raise MetadataFixtureError(
                "the connected database is not the configured acceptance database"
            )
    except BaseException:
        provisioner.release()
        raise
    return provisioner


def provision(mapping_path: Path) -> dict[str, str]:
    """Provision the metadata Action, Role, and both deterministic assignments."""
    tenant_id, subjects = _read_mapping(mapping_path)
    provisioner = _open()
    try:
        classes = classify_subjects(provisioner, tenant_id, subjects)
        ensure_metadata_action(provisioner)
        ensure_metadata_role(provisioner, tenant_id)
        for subject in (classes["allowed"], classes["denied"]):
            ensure_metadata_assignment(provisioner, tenant_id, identity_id_for_subject(subject))
    finally:
        provisioner.release()
    return {
        "tenant_id": str(tenant_id),
        "metadata_role_urn": metadata_role_urn(tenant_id),
        "allowed_subject": classes["allowed"],
        "denied_subject": classes["denied"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PR 20B metadata fixture provisioner")
    parser.add_argument(
        "--mapping",
        default=os.environ.get("MTMF_PR20A_FIXTURE_DIR", "/tmp/mtmf-pr20a-acceptance-fixtures")
        + "/reference-app-fixture.json",
    )
    args = parser.parse_args(argv)
    try:
        _require_development()
        _expected_database()
        result = provision(Path(args.mapping))
    except MetadataFixtureError as exc:
        print(f"metadata fixture error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
