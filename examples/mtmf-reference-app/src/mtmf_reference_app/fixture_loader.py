"""Test-only fixture loader for the reference application's Document store.

There is no runtime route that creates, updates, or deletes documents. The
fixed acceptance rows are inserted here by an explicit, separate process
(``python -m mtmf_reference_app.fixture_loader``). The loader is idempotent for
identical rows and fails closed on any conflicting existing row; it never
overwrites silently.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from uuid import UUID

from mtmf_reference_app.models import Document
from mtmf_reference_app.store import DocumentStore, DocumentStoreError

__all__ = ["FixtureLoaderError", "load_manifest", "seed_from_manifest"]


class FixtureLoaderError(RuntimeError):
    """The fixture manifest is malformed or conflicted."""


def _uuid_text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise FixtureLoaderError(f"{field} must be a UUID string")
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise FixtureLoaderError(f"{field} is not a valid UUID") from exc


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise FixtureLoaderError(f"{field} must be a non-empty string")
    return value


def load_manifest(path: Path) -> list[Document]:
    """Parse and validate the document fixture manifest.

    :raises FixtureLoaderError: on unreadable/invalid JSON or any malformed row.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FixtureLoaderError("the fixture manifest could not be read") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("documents"), list):
        raise FixtureLoaderError("the fixture manifest must contain a documents array")
    documents: list[Document] = []
    seen: set[str] = set()
    for entry in raw["documents"]:
        if not isinstance(entry, dict):
            raise FixtureLoaderError("every fixture document must be an object")
        document_id = _uuid_text(entry.get("document_id"), "document_id")
        if document_id in seen:
            raise FixtureLoaderError("fixture document identifiers must be unique")
        seen.add(document_id)
        documents.append(
            Document(
                document_id=document_id,
                tenant_id=_uuid_text(entry.get("tenant_id"), "tenant_id"),
                title=_text(entry.get("title"), "title"),
                body=_text(entry.get("body"), "body"),
            )
        )
    return documents


def seed_from_manifest(manifest: Path, sqlite_path: Path) -> int:
    """Initialize the store and seed the manifest rows.

    :raises FixtureLoaderError: on a malformed manifest.
    :raises DocumentStoreError: on a conflicting existing row.
    """
    documents = load_manifest(manifest)
    store = DocumentStore(sqlite_path)
    store.initialize()
    return store.seed_documents(documents)


def main(argv: list[str] | None = None) -> int:
    """Run the explicit fixture loader."""
    parser = argparse.ArgumentParser(description="MTMF reference-app fixture loader")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--sqlite", required=True)
    args = parser.parse_args(argv)
    try:
        inserted = seed_from_manifest(Path(args.manifest), Path(args.sqlite))
    except (FixtureLoaderError, DocumentStoreError) as exc:
        print(f"fixture load failed: {exc}", file=sys.stderr)
        return 1
    print(f"fixture load complete ({inserted} inserted)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
