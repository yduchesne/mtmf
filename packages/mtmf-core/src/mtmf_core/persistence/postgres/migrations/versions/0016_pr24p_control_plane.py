"""Revision 0016: PR 24P operator authority and private control functions.

Additive, role-independent migration. It installs the owner-only assignment,
immutable execution/audit ledger, and exactly five private functions for all
databases regardless of development opt-in. It never creates
``mtmf_control_exec`` or grants it EXECUTE; that is a separate approved
installation phase. The runtime allowlist remains exactly 78.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0016"
down_revision = "0015"


def upgrade() -> None:
    """Install v016 schema, private functions, ownership and assertions."""
    for path in sql_version_files("v016"):
        op.execute(path.read_text(encoding="utf-8"))
