"""Revision 0010: Application registry and Tenant subscriptions (PR 13).

Additive migration that installs the reviewed ``sql/v010`` resources: the
``application``, ``application_tenant_registration``, and
``tenant_application_subscription`` tables with partial-unique current
rows, database immutability/lifecycle guards, operator/installation-only
mutation functions (owner-owned, ``SECURITY INVOKER``, never granted to
``mtmf_runtime``), and eight narrowly reviewed runtime read functions.

No shipped revision or packaged SQL resource ``v001``-``v009`` is
modified. Only upgrade-to-head is part of the MTMF migration contract;
there is no supported downgrade. The mandatory post-upgrade runtime
privilege verifier still runs after this revision.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0010"
down_revision = "0009"


def upgrade() -> None:
    """Install the v010 Application-registry objects, guards, and grants."""
    for path in sql_version_files("v010"):
        op.execute(path.read_text(encoding="utf-8"))
