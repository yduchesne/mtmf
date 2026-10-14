"""Reference application's own Tenant-scoped Document store (SQLite).

This is deliberately the *consumer's* data store, not an MTMF store. Every
read applies both the trusted Tenant and the candidate document identifier as
an equality predicate; a missing or cross-Tenant row yields nothing and never
causes the app to switch Tenant context. All SQL is parameterized.

The store is initialized idempotently. Writes are possible only through the
explicit test-only fixture loader; there is no runtime create/update/delete
route.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path
from uuid import UUID

from mtmf_reference_app.models import Document

__all__ = ["DocumentStore", "DocumentStoreError", "canonical_uuid"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    document_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS documents_tenant_document
    ON documents (tenant_id, document_id);
"""


class DocumentStoreError(RuntimeError):
    """The Document store is unusable or a fixture write conflicted."""


def canonical_uuid(value: str) -> str:
    """Return the canonical lowercase hyphenated form of a UUID string.

    :raises ValueError: when ``value`` is not a valid UUID.
    """
    return str(UUID(value))


class DocumentStore:
    """Parameterized, Tenant-scoped access to the reference app's documents."""

    __slots__ = ("_path",)

    def __init__(self, path: Path) -> None:
        self._path = path

    @property
    def path(self) -> Path:
        """The configured SQLite database path."""
        return self._path

    def initialize(self) -> None:
        """Create the schema if absent. Idempotent and non-destructive."""
        try:
            with self._connect() as connection:
                connection.executescript(_SCHEMA)
        except sqlite3.Error as exc:
            raise DocumentStoreError("the Document store schema could not be initialized") from exc

    def ready(self) -> bool:
        """Return whether the store file and schema are usable."""
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'documents'"
                ).fetchone()
            return row is not None
        except sqlite3.Error:
            return False

    def load(self, tenant_id: str, document_id: str) -> Document | None:
        """Load exactly one row for ``tenant_id`` and ``document_id``.

        Both identifiers are equality predicates, so a document that belongs to
        another Tenant is simply not found. Returns ``None`` when absent.
        """
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT document_id, tenant_id, title, body FROM documents "
                    "WHERE tenant_id = ? AND document_id = ?",
                    (tenant_id, document_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise DocumentStoreError("the Document store could not be read") from exc
        if row is None:
            return None
        return Document(
            document_id=str(row[0]),
            tenant_id=str(row[1]),
            title=str(row[2]),
            body=str(row[3]),
        )

    def seed_documents(self, documents: Iterable[Document]) -> int:
        """Insert fixture rows idempotently; fail closed on any conflict.

        A row whose identifier already exists with identical content is left
        untouched. A row whose identifier exists with different content raises
        :class:`DocumentStoreError`; existing data is never silently overwritten.

        :returns: the number of newly inserted rows.
        """
        inserted = 0
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    for document in documents:
                        existing = connection.execute(
                            "SELECT tenant_id, title, body FROM documents WHERE document_id = ?",
                            (document.document_id,),
                        ).fetchone()
                        if existing is not None:
                            if tuple(existing) != (
                                document.tenant_id,
                                document.title,
                                document.body,
                            ):
                                raise DocumentStoreError(
                                    "a fixture document conflicts with an existing row"
                                )
                            continue
                        connection.execute(
                            "INSERT INTO documents (document_id, tenant_id, title, body) "
                            "VALUES (?, ?, ?, ?)",
                            (
                                document.document_id,
                                document.tenant_id,
                                document.title,
                                document.body,
                            ),
                        )
                        inserted += 1
                    connection.execute("COMMIT")
                except BaseException:
                    connection.execute("ROLLBACK")
                    raise
        except sqlite3.Error as exc:
            raise DocumentStoreError("the fixture documents could not be written") from exc
        return inserted

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
        return connection
