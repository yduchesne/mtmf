"""Revision 0005: typed Role-assignment persistence.

Additive migration that installs the reviewed, versioned Role-assignment
resources from ``sql/v005``: the two typed assignment tables
(``identity_role_assignment`` and ``group_role_assignment``), their
structural constraints and composite foreign keys, the trusted stored
functions, and the exact restricted-runtime EXECUTE grants.

No shipped revision (``0001``-``0004``) or packaged SQL resource
(``v001``-``v004``) is modified. Only upgrade-to-head is part of the MTMF
migration contract; there is no supported downgrade. The mandatory
``PostgresMigrationManager`` post-upgrade runtime privilege verifier is
updated in lockstep with the new signature manifest and still runs after
this revision.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0005"
down_revision = "0004"


def upgrade() -> None:
    """Install the v005 Role-assignment objects and grants in sorted order."""
    for path in sql_version_files("v005"):
        op.execute(path.read_text(encoding="utf-8"))
