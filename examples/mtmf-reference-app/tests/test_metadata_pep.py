"""PR20B metadata-only Document operation: Action separation and no-body rule.

The metadata endpoint is a genuine second application operation with its own
exact Action. These tests prove that a content grant does not authorize
metadata, a metadata grant does not authorize content, and metadata never
serializes a ``body``.
"""

from __future__ import annotations

from pathlib import Path

from helpers import (
    ALLOWED_SUBJECT,
    ALLOWED_TOKEN,
    DENIED_SUBJECT,
    DENIED_TOKEN,
    DOCUMENT_ID,
    OTHER_DOCUMENT_ID,
    OTHER_TENANT_ID,
    TENANT_ID,
    FakeVerifier,
    PolicyClient,
    dependency_error,
    make_config,
    make_reader,
    make_test_client,
)
from mtmf_reference_app.app import (
    DOCUMENT_READ_ACTION,
    METADATA_ACTION,
    METADATA_REQUEST_ID,
)
from mtmf_reference_app.models import Document
from mtmf_reference_app.store import DocumentStore

from mtmf_api.authorization import ResourceKind

METADATA_ROUTE = f"/v1/documents/{DOCUMENT_ID}/metadata"


def _seed(config) -> None:  # type: ignore[no-untyped-def]
    store = DocumentStore(config.sqlite_path)
    store.initialize()
    store.seed_documents(
        [
            Document(
                document_id=DOCUMENT_ID,
                tenant_id=str(TENANT_ID),
                title="Seeded Title",
                body="Seeded Body",
            ),
            Document(
                document_id=OTHER_DOCUMENT_ID,
                tenant_id=str(OTHER_TENANT_ID),
                title="Other Title",
                body="Other Body",
            ),
        ]
    )


def _reader(tmp_path: Path, client: PolicyClient):  # type: ignore[no-untyped-def]
    config = make_config(tmp_path)
    _seed(config)
    verifier = FakeVerifier({ALLOWED_TOKEN: ALLOWED_SUBJECT, DENIED_TOKEN: DENIED_SUBJECT})
    return make_reader(config, verifier=verifier, client=client)


def _get(http, *, token: str | None) -> object:  # type: ignore[no-untyped-def]
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return http.get(METADATA_ROUTE, headers=headers)


def test_metadata_allowed_returns_id_and_title_without_body(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _get(http, token=DENIED_TOKEN)
    assert response.status_code == 200
    assert response.json() == {"id": DOCUMENT_ID, "title": "Seeded Title"}
    assert "body" not in response.json()
    assert response.headers["cache-control"] == "no-store"
    assert len(client.calls) == 1
    request, _token, _context = client.calls[0]
    occurrence = request.actions[0]
    assert occurrence.action == METADATA_ACTION
    assert occurrence.request_id == METADATA_REQUEST_ID
    assert occurrence.resource.kind is ResourceKind.APPLICATION_OWNED
    assert occurrence.resource.resource_id == DOCUMENT_ID


def test_metadata_requires_metadata_action_not_content_grant(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _get(http, token=ALLOWED_TOKEN)
    assert response.status_code == 403
    assert "Seeded" not in response.text
    assert "title" not in response.text


def test_content_requires_content_action_not_metadata_grant(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{DOCUMENT_ID}",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 403
    assert "Seeded" not in response.text


def test_metadata_policy_deny_returns_403_without_title(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions=frozenset())
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _get(http, token=ALLOWED_TOKEN)
    assert response.status_code == 403
    assert "Seeded" not in response.text


def test_metadata_remote_error_fails_closed(tmp_path: Path) -> None:
    client = PolicyClient(error=dependency_error())
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _get(http, token=ALLOWED_TOKEN)
    assert response.status_code == 503
    assert "Seeded" not in response.text


def test_metadata_missing_document_returns_404_without_pdp(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION})
    reader = _reader(tmp_path, client)
    missing = "66666666-6666-4666-8666-666666666666"
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{missing}/metadata",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 404
    assert client.calls == []


def test_metadata_cross_tenant_returns_404_without_pdp(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{OTHER_DOCUMENT_ID}/metadata",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 404
    assert "Other" not in response.text
    assert client.calls == []


def test_metadata_missing_authorization_returns_401_without_pdp(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _get(http, token=None)
    assert response.status_code == 401
    assert client.calls == []
