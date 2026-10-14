"""Revision 0013: monthly UTC partitioning of the security-mutation audit.

Additive migration installing the reviewed ``sql/v013`` resources: the
in-place conversion of ``mtmf.security_mutation_audit`` to PostgreSQL 18
native monthly ``RANGE (occurred_at)`` partitioning with a composite
``(occurred_at, id)`` primary key, an owner-only idempotent monthly
partition-provisioning helper, and post-conversion assertions.

No shipped revision (``0001``-``0012``) or packaged SQL resource
(``v001``-``v012``) is modified. Only upgrade-to-head is part of the MTMF
migration contract; there is no supported downgrade. The mandatory
``PostgresMigrationManager`` post-upgrade runtime privilege verifier is
unchanged because the runtime allowlist and privileges are preserved.
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0013"
down_revision = "0012"


def upgrade() -> None:
    """Convert the audit table to monthly partitions and install maintenance."""
    for path in sql_version_files("v013"):
        op.execute(path.read_text(encoding="utf-8"))
