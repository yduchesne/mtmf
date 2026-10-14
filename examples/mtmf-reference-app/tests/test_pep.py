"""U04/U05/U06/U07/U08/U09 PEP route ordering and fail-closed behavior."""

from __future__ import annotations

import threading
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
    BlockingEvaluateClient,
    FakeClient,
    FakeVerifier,
    dependency_error,
    make_config,
    make_reader,
    make_test_client,
)
from mtmf_reference_app.app import (
    DOCUMENT_READ_ACTION,
    READ_REQUEST_ID,
    BoundedWorker,
)
from mtmf_reference_app.models import Document
from mtmf_reference_app.store import DocumentStore

from mtmf_api.authorization import ResourceKind


def _seed(config) -> None:
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


def _client_and_reader(tmp_path: Path, *, allowed: bool = True, error: Exception | None = None):
    config = make_config(tmp_path)
    _seed(config)
    verifier = FakeVerifier({ALLOWED_TOKEN: ALLOWED_SUBJECT, DENIED_TOKEN: DENIED_SUBJECT})
    client = FakeClient(allowed=allowed, error=error)
    reader = make_reader(config, verifier=verifier, client=client)
    return config, verifier, client, reader


def test_allowed_read_returns_exact_body_and_binds_loaded_row(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path, allowed=True)
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{DOCUMENT_ID}",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 200
    assert response.json() == {"id": DOCUMENT_ID, "title": "Seeded Title", "body": "Seeded Body"}
    assert response.headers["cache-control"] == "no-store"
    assert len(client.calls) == 1
    request, token, _context = client.calls[0]
    assert token == ALLOWED_TOKEN
    occurrence = request.actions[0]
    assert occurrence.action == DOCUMENT_READ_ACTION
    assert occurrence.request_id == READ_REQUEST_ID
    assert occurrence.resource.kind is ResourceKind.APPLICATION_OWNED
    assert occurrence.resource.resource_type == "document"
    assert occurrence.resource.resource_id == DOCUMENT_ID
    assert client.required == [
        (
            DOCUMENT_READ_ACTION,
            occurrence.resource,
            READ_REQUEST_ID,
        )
    ]


def test_policy_deny_returns_403_without_body(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path, allowed=False)
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{DOCUMENT_ID}",
            headers={"Authorization": f"Bearer {DENIED_TOKEN}"},
        )
    assert response.status_code == 403
    assert "Seeded" not in response.text
    assert len(client.calls) == 1


def test_missing_authorization_returns_401_without_pdp(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path)
    with make_test_client(reader, client) as http:
        response = http.get(f"/v1/documents/{DOCUMENT_ID}")
    assert response.status_code == 401
    assert client.calls == []


def test_unknown_subject_denies_without_pdp(tmp_path: Path) -> None:
    _, verifier, client, reader = _client_and_reader(tmp_path)
    verifier._subjects["unknown-token"] = "not-allowlisted"
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{DOCUMENT_ID}",
            headers={"Authorization": "Bearer unknown-token"},
        )
    assert response.status_code == 403
    assert client.calls == []


def test_unverifiable_token_returns_401_without_pdp(tmp_path: Path) -> None:
    _, verifier, client, reader = _client_and_reader(tmp_path)
    verifier.fail = True
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{DOCUMENT_ID}",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 401
    assert client.calls == []


def test_malformed_document_id_returns_404_without_pdp(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path)
    with make_test_client(reader, client) as http:
        response = http.get(
            "/v1/documents/not-a-uuid",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 404
    assert client.calls == []


def test_nonexistent_document_returns_404_without_pdp(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path)
    missing = "66666666-6666-4666-8666-666666666666"
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{missing}",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 404
    assert client.calls == []


def test_cross_tenant_document_returns_404(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path)
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{OTHER_DOCUMENT_ID}",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 404
    assert "Other" not in response.text
    assert client.calls == []


def test_remote_error_fails_closed(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path, error=dependency_error())
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{DOCUMENT_ID}",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 503
    assert "Seeded" not in response.text


def test_unexpected_error_fails_closed(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path, error=RuntimeError("boom"))
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{DOCUMENT_ID}",
            headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
        )
    assert response.status_code == 503
    assert "Seeded" not in response.text


def test_health_endpoints(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path)
    with make_test_client(reader, client) as http:
        assert http.get("/health/live").json() == {"status": "live"}
        ready = http.get("/health/ready")
        assert ready.status_code == 200
        assert ready.json() == {"status": "ready"}


def test_non_bearer_scheme_returns_401(tmp_path: Path) -> None:
    _, _, client, reader = _client_and_reader(tmp_path)
    with make_test_client(reader, client) as http:
        response = http.get(
            f"/v1/documents/{DOCUMENT_ID}",
            headers={"Authorization": "Basic abc"},
        )
    assert response.status_code == 401
    assert client.calls == []


def test_not_ready_when_schema_absent(tmp_path: Path) -> None:
    config = make_config(tmp_path)
    # A store whose schema was never initialized is not ready.
    verifier = FakeVerifier({ALLOWED_TOKEN: ALLOWED_SUBJECT})
    client = FakeClient()
    reader = make_reader(config, verifier=verifier, client=client)
    with make_test_client(reader, client) as http:
        assert http.get("/health/ready").status_code == 503


def test_evaluate_worker_timeout_maps_to_503_without_late_body(tmp_path: Path) -> None:
    """A timed-out MTMF evaluation fails closed and never discloses the body."""
    config = make_config(tmp_path)
    _seed(config)
    verifier = FakeVerifier({ALLOWED_TOKEN: ALLOWED_SUBJECT})
    release = threading.Event()
    client = BlockingEvaluateClient(release)
    reader = make_reader(
        config,
        verifier=verifier,
        client=client,
        evaluate_worker=BoundedWorker(limit=1, timeout=0.05),
    )
    try:
        with make_test_client(reader, client) as http:
            response = http.get(
                f"/v1/documents/{DOCUMENT_ID}",
                headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"},
            )
        assert response.status_code == 503
        assert "Seeded" not in response.text
    finally:
        # Let the abandoned blocking evaluation terminate before teardown.
        release.set()
