"""Revision 0012: first verified, atomically audited management mutation.

Additive migration that installs the reviewed, versioned ``sql/v012``
resources for PR 19C: the append-only ``security_mutation_audit`` table,
the exact human-approved membership-add Action and its sole built-in
Tenant Administrator grant, the bounded row-lock/recheck helper, the
audited Identity-to-Group membership-add entry point, the revoked legacy
runtime grant, and the cumulative privilege assertions.

No shipped revision (``0001``-``0011``) or packaged SQL resource
(``v001``-``v011``) is modified. Only upgrade-to-head is part of the MTMF
migration contract; there is no supported downgrade. The mandatory
``PostgresMigrationManager`` post-upgrade runtime privilege verifier is
updated in lockstep with the new allowlist and still runs after this
revision.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0012"
down_revision = "0011"


def upgrade() -> None:
    """Install the v012 security-mutation resources in sorted order."""
    for path in sql_version_files("v012"):
        op.execute(path.read_text(encoding="utf-8"))
