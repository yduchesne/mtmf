"""Revision 0006: approved Gate M minimum built-in IAM seed.

Additive migration that installs the reviewed, versioned ``sql/v006``
resources: the protected ``builtin_role`` registry, the exact 11
SYSTEM-owned Role aggregates / 11 ALLOW PermissionSets / 11 exact
Permissions / 3 shared Action definitions from the approved PR #38 seed,
and the database-enforced protection that prevents ordinary ``role_save``
from rewriting a built-in definition.

The seed installer (``mtmf.install_builtin_policy``) is installation-only:
it is owner-owned, ``SECURITY DEFINER`` with a fixed empty ``search_path``,
PUBLIC ``EXECUTE`` is revoked, and it is deliberately **not** granted to
``mtmf_runtime``. The modification of the historically shipped
``role_save`` is an additive replacement of its body in this revision; its
signature and reviewed runtime grant are unchanged.

No shipped revision (``0001``-``0005``) or packaged SQL resource
(``v001``-``v005``) is modified. Only upgrade-to-head is part of the MTMF
migration contract; there is no supported downgrade. The mandatory
``PostgresMigrationManager`` post-upgrade runtime privilege verifier still
runs after this revision.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0006"
down_revision = "0005"


def upgrade() -> None:
    """Install the v006 built-in policy seed and protection in sorted order."""
    for path in sql_version_files("v006"):
        op.execute(path.read_text(encoding="utf-8"))
