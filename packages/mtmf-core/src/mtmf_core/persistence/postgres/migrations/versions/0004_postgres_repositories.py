"""Revision 0004: PostgreSQL repository stored functions and runtime grants.

Additive migration that installs the reviewed, versioned repository
functions from ``sql/v004`` for every existing typed repository:
Tenant/Organization/Principal/Identity/Group/ Action read/write
operations, the atomic ``Role -> PermissionSet -> Permission`` aggregate,
and the six typed membership add/get/find operations.

Every repository function is owner-owned ``SECURITY DEFINER`` with a
fixed empty ``search_path``; PUBLIC EXECUTE is revoked and the restricted
``mtmf_runtime`` login receives EXECUTE on exactly the reviewed
signatures. The runtime gains no table, view, or sequence privilege.

Revisions ``0001``-``0003`` and the packaged ``sql/v001``-``sql/v003``
resources are never modified. Only upgrade-to-head is part of the MTMF
migration contract; there is no supported downgrade. The mandatory
``PostgresMigrationManager`` post-upgrade runtime privilege verifier is
updated in lockstep with the new allowlist and still runs after this
revision.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0004"
down_revision = "0003"


def upgrade() -> None:
    """Install the v004 repository functions and grants in sorted order."""
    for path in sql_version_files("v004"):
        op.execute(path.read_text(encoding="utf-8"))
