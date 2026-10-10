"""Revision 0007: explicit Identity origin and Tenant lifecycle.

Additive migration that installs the reviewed ``sql/v007`` resources: the
immutable ``identity.origin`` (LOCAL/FEDERATED) and ordinary-Tenant
``tenant.lifecycle`` (PROVISIONING/ACTIVE/SUSPENDED) columns with their
checks, the origin-immutability guard, the updated entity read/write
functions carrying the new fields, and the exact restricted-runtime
EXECUTE grants for the changed signatures.

The old v004 ``tenant_add``/``tenant_save``/``identity_add`` overloads are
dropped so only the new signatures remain. No shipped revision or packaged
SQL resource ``v001``-``v006`` is modified. Only upgrade-to-head is part of
the MTMF migration contract; there is no supported downgrade. The mandatory
post-upgrade runtime privilege verifier still runs after this revision.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0007"
down_revision = "0006"


def upgrade() -> None:
    """Install the v007 origin/lifecycle objects and grants in sorted order."""
    for path in sql_version_files("v007"):
        op.execute(path.read_text(encoding="utf-8"))
