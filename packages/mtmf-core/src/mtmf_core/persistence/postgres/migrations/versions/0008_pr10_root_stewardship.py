"""Revision 0008: canonical root registry, bootstrap, and stewardship.

Additive migration that installs the reviewed ``sql/v008`` resources: the
protected ``root_registry`` singleton, ``stewardship_designation`` and
append-only ``stewardship_audit`` tables, the installation-only
``bootstrap_root``/``designate_steward``/``activate_tenant``/
``suspend_tenant``/``recover_root_identity`` functions (owner-owned,
``SECURITY INVOKER``, never granted to ``mtmf_runtime``), and the database
guards that protect canonical root and current-steward state across the
existing mutation paths.

No shipped revision or packaged SQL resource ``v001``-``v007`` is modified.
Only upgrade-to-head is part of the MTMF migration contract; there is no
supported downgrade. The mandatory post-upgrade runtime privilege verifier
still runs after this revision.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0008"
down_revision = "0007"


def upgrade() -> None:
    """Install the v008 root/stewardship objects, guards, and grants."""
    for path in sql_version_files("v008"):
        op.execute(path.read_text(encoding="utf-8"))
