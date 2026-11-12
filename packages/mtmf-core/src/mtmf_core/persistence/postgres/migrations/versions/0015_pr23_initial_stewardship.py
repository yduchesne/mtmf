"""Revision 0015: PR 23 initial stewardship transaction participants.

Additive migration that installs the reviewed ``sql/v015`` resources: the
stewardship-audit ``INITIAL_ONBOARDING`` operation and two owner-only,
``SECURITY INVOKER``, non-committing onboarding participants
(``onboarding_subject_prepare`` and ``onboarding_initial_steward_attach``).

Neither function is granted to ``mtmf_runtime`` and neither creates or
activates a Tenant, consumes quota, persists replay, or writes a
registration/subscription. The runtime EXECUTE manifest therefore remains
78 signatures. Shipped revisions and SQL resources ``v001``-``v014`` are not
modified, including the protected ``0006``/``0012`` seeds. Only
upgrade-to-head is part of the MTMF migration contract; there is no supported
downgrade.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0015"
down_revision = "0014"


def upgrade() -> None:
    """Install the v015 audit extension, participants, grants and assertions."""
    for path in sql_version_files("v015"):
        op.execute(path.read_text(encoding="utf-8"))
