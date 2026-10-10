"""Revision 0009: TenantManagementGroup structural persistence (PR 11).

Additive migration that installs the reviewed ``sql/v009`` resources: the
``tenant_management_group`` / ``_membership`` / ``_actor_eligibility``
tables and database guards, the two approved SYSTEM management Roles and
their single exact ``tenant:get-object`` Permission, atomic ROOT management
group creation tied to the PR 10 canonical root registry, installation-only
privileged mutation functions (owner-owned, ``SECURITY INVOKER``, never
granted to ``mtmf_runtime``), and narrowly reviewed runtime read functions.

No shipped revision or packaged SQL resource ``v001``-``v008`` is modified.
Only upgrade-to-head is part of the MTMF migration contract; there is no
supported downgrade. The mandatory post-upgrade runtime privilege verifier
still runs after this revision.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0009"
down_revision = "0008"


def upgrade() -> None:
    """Install the v009 TenantManagementGroup objects, seed, and grants."""
    for path in sql_version_files("v009"):
        op.execute(path.read_text(encoding="utf-8"))
