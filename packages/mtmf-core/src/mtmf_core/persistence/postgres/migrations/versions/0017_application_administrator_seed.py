"""Revision 0017: approved Application Administrator protected policy seed.

Installs exactly one protected SYSTEM Role, one ALLOW PermissionSet, eleven
approved exact Permissions and their Action definitions. This revision does
not assign the Role, create a database role/grant, or modify 0001-0016/v001-v016.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0017"
down_revision = "0016"


def upgrade() -> None:
    """Install the bounded approved seed and its independent assertions."""
    for path in sql_version_files("v017"):
        op.execute(path.read_text(encoding="utf-8"))
