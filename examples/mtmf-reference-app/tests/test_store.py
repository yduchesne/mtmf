"""U02/U03/U06/U11 Tenant-scoped store and fixture-loader behavior."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers import DOCUMENT_ID, OTHER_TENANT_ID, TENANT_ID
from mtmf_reference_app.fixture_loader import FixtureLoaderError, main, seed_from_manifest
from mtmf_reference_app.models import Document
from mtmf_reference_app.store import DocumentStore, DocumentStoreError, canonical_uuid


def _document() -> Document:
    return Document(
        document_id=DOCUMENT_ID,
        tenant_id=str(TENANT_ID),
        title="Title",
        body="Body",
    )


def test_schema_initialization_is_idempotent(tmp_path: Path) -> None:
    store = DocumentStore(tmp_path / "documents.db")
    store.initialize()
    store.seed_documents([_document()])
    store.initialize()
    assert store.load(str(TENANT_ID), DOCUMENT_ID) == _document()


def test_cross_tenant_lookup_returns_none(tmp_path: Path) -> None:
    store = DocumentStore(tmp_path / "documents.db")
    store.initialize()
    store.seed_documents([_document()])
    assert store.load(str(OTHER_TENANT_ID), DOCUMENT_ID) is None


def test_canonical_uuid_rejects_malformed() -> None:
    with pytest.raises(ValueError):
        canonical_uuid("not-a-uuid")


def test_canonical_uuid_normalizes() -> None:
    assert canonical_uuid(DOCUMENT_ID.upper()) == DOCUMENT_ID


def test_ready_reflects_schema_presence(tmp_path: Path) -> None:
    store = DocumentStore(tmp_path / "documents.db")
    assert store.ready() is False
    store.initialize()
    assert store.ready() is True


def test_fixture_loader_idempotent(tmp_path: Path) -> None:
    manifest = tmp_path / "documents.json"
    manifest.write_text(
        json.dumps(
            {
                "documents": [
                    {
                        "document_id": DOCUMENT_ID,
                        "tenant_id": str(TENANT_ID),
                        "title": "Title",
                        "body": "Body",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    sqlite_path = tmp_path / "documents.db"
    assert seed_from_manifest(manifest, sqlite_path) == 1
    assert seed_from_manifest(manifest, sqlite_path) == 0


def test_fixture_loader_conflict_fails_closed(tmp_path: Path) -> None:
    manifest = tmp_path / "documents.json"
    manifest.write_text(
        json.dumps(
            {
                "documents": [
                    {
                        "document_id": DOCUMENT_ID,
                        "tenant_id": str(TENANT_ID),
                        "title": "Title",
                        "body": "Body",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    sqlite_path = tmp_path / "documents.db"
    store = DocumentStore(sqlite_path)
    store.initialize()
    store.seed_documents([_document()])
    conflicting = tmp_path / "conflict.json"
    conflicting.write_text(
        json.dumps(
            {
                "documents": [
                    {
                        "document_id": DOCUMENT_ID,
                        "tenant_id": str(TENANT_ID),
                        "title": "Different",
                        "body": "Body",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(DocumentStoreError):
        seed_from_manifest(conflicting, sqlite_path)


def test_fixture_loader_rejects_malformed_manifest(tmp_path: Path) -> None:
    manifest = tmp_path / "bad.json"
    manifest.write_text("{not json", encoding="utf-8")
    with pytest.raises(FixtureLoaderError):
        seed_from_manifest(manifest, tmp_path / "documents.db")


def test_fixture_loader_main_success(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    manifest = tmp_path / "documents.json"
    manifest.write_text(
        json.dumps(
            {
                "documents": [
                    {
                        "document_id": DOCUMENT_ID,
                        "tenant_id": str(TENANT_ID),
                        "title": "Title",
                        "body": "Body",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert main(["--manifest", str(manifest), "--sqlite", str(tmp_path / "d.db")]) == 0
    assert "fixture load complete" in capsys.readouterr().out


def test_fixture_loader_main_failure(tmp_path: Path) -> None:
    manifest = tmp_path / "bad.json"
    manifest.write_text("{not json", encoding="utf-8")
    assert main(["--manifest", str(manifest), "--sqlite", str(tmp_path / "d.db")]) == 1


@pytest.mark.parametrize(
    "documents",
    [
        ["not-an-object"],
        [
            {
                "document_id": DOCUMENT_ID,
                "tenant_id": "bad-uuid",
                "title": "T",
                "body": "B",
            }
        ],
        [
            {
                "document_id": DOCUMENT_ID,
                "tenant_id": str(TENANT_ID),
                "title": "T",
                "body": "",
            }
        ],
        [
            {"document_id": DOCUMENT_ID, "tenant_id": str(TENANT_ID), "title": "T", "body": "B"},
            {"document_id": DOCUMENT_ID, "tenant_id": str(TENANT_ID), "title": "T", "body": "B"},
        ],
    ],
)
def test_fixture_manifest_validation_rejects_bad_rows(
    tmp_path: Path, documents: list[object]
) -> None:
    manifest = tmp_path / "documents.json"
    manifest.write_text(json.dumps({"documents": documents}), encoding="utf-8")
    with pytest.raises(FixtureLoaderError):
        seed_from_manifest(manifest, tmp_path / "documents.db")


def test_store_error_wrapped_on_unwritable_path(tmp_path: Path) -> None:
    directory = tmp_path / "a-directory"
    directory.mkdir()
    store = DocumentStore(directory)
    with pytest.raises(DocumentStoreError):
        store.initialize()
