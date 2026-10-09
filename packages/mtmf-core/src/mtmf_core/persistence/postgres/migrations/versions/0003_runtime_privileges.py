"""Revision 0003: restricted runtime privilege model.

Additive migration that establishes owner/migrator/runtime role separation
for the ``mtmf`` schema:

- normalizes schema/object ownership to ``mtmf_owner`` and fails loudly
  with the administrator handoff instruction if legacy ownership remains;
- revokes PUBLIC and runtime schema/table/sequence/function privileges
  (default-deny), granting the runtime role only schema USAGE;
- sets owner-scoped default privileges so future functions are not
  PUBLIC-executable;
- converts the six approved membership-removal functions to
  ``SECURITY DEFINER`` (owner-owned, fixed empty ``search_path``) and
  grants the runtime role EXECUTE on exactly those six signatures;
- asserts the resulting effective privilege posture inside the migration
  transaction.

Only upgrade-to-head is part of the MTMF migration contract; there is no
supported downgrade. Revisions ``0001``/``0002`` and the packaged
``sql/v001``/``sql/v002`` resources are never modified. Role creation is
an administrator operation outside Alembic (see
``mtmf_core.persistence.postgres.roles``).
"""

from __future__ import annotations

from alembic import op

from mtmf_core.persistence.postgres.resources import sql_version_files

revision = "0003"
down_revision = "0002"


def upgrade() -> None:
    """Install the v003 runtime privilege resources in sorted filename order."""
    for path in sql_version_files("v003"):
        op.execute(path.read_text(encoding="utf-8"))
