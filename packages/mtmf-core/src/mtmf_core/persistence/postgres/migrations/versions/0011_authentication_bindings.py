"""Revision 0011: immutable authentication binding persistence (PR 14).

Additive migration installing the reviewed ``sql/v011`` resources: the
``service_credential_application`` and ``external_subject_identity`` tables
with partial-unique active rows, immutability/terminal guards,
operator/installation-only mutation functions (owner-owned, ``SECURITY
INVOKER``, never granted to ``mtmf_runtime``), and two narrowly reviewed
runtime read functions. No shipped revision or ``v001``-``v010`` resource is
modified. The mandatory post-upgrade runtime privilege verifier still runs.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0011"
down_revision = "0010"


def upgrade() -> None:
    """Install the v011 authentication-binding objects, guards, and grants."""
    for path in sql_version_files("v011"):
        op.execute(path.read_text(encoding="utf-8"))
