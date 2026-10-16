"""Revision 0014: Application onboarding entitlement foundation (PR 22).

Additive migration that installs the reviewed ``sql/v014`` resources: the
``application_onboarding_entitlement`` and
``application_onboarding_entitlement_event`` tables with immutable grant
provenance, terminal revocation, a single-ACTIVE-per-Application partial
unique index, and append-only history; operator/installation-only
``SECURITY INVOKER`` grant/revoke/read functions that are never granted to
``mtmf_runtime``.

This revision deliberately adds **no** Tenant-committing composite and **no**
runtime-granted function: the first-Tenant transaction seam is BLOCKED pending
an explicit privilege-separated architectural decision (see
``docs/pr-artifacts/pr-22/PR22_STOP_REPORT.md``). No shipped revision or
packaged SQL resource ``v001``-``v013`` is modified, and the protected
``0006``/``0012`` seeds are untouched. Only upgrade-to-head is part of the MTMF
migration contract; there is no supported downgrade.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0014"
down_revision = "0013"


def upgrade() -> None:
    """Install the v014 onboarding-entitlement objects, guards, and grants."""
    for path in sql_version_files("v014"):
        op.execute(path.read_text(encoding="utf-8"))
