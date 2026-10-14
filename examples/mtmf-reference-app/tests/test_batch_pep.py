"""PR20B batch PEP route: input bounds, atomic disclosure, and fail-closed.

The batch route is a *single* MTMF evaluation with one ordered occurrence per
loaded row. These tests assert the documented security ordering for the
consumer side: authenticate, map the subject to a server-owned Tenant, validate
the bounded input, resolve every row before authorization, evaluate once, call
``require`` for every occurrence in input order, and only then serialize any
body. A single non-ALLOW occurrence denies the whole request with zero bodies.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from helpers import (
    ALLOWED_SUBJECT,
    ALLOWED_TOKEN,
    DENIED_TOKEN,
    DOCUMENT_ID,
    OTHER_DOCUMENT_ID,
    OTHER_TENANT_ID,
    TENANT_ID,
    FakeVerifier,
    dependency_error,
    make_config,
    make_reader,
    make_test_client,
)
from mtmf_reference_app.app import (
    BATCH_READ_MAX_IDS,
    DOCUMENT_READ_ACTION,
    READ_REQUEST_ID,
)
from mtmf_reference_app.models import Document
from mtmf_reference_app.store import DocumentStore

from mtmf_api.authorization import ResourceKind
from mtmf_client import AuthorizationDenied

BATCH_DOCUMENT_ID = "77777777-7777-4777-8777-777777777777"
BATCH_ROUTE = "/v1/documents/batch-read"


class MixedDecisionClient:
    """Deterministic client with per-``request_id`` decisions.

    ``evaluate`` returns the exact request as the snapshot; ``require`` denies
    only the request ids recorded as denied, so a genuinely mixed batch can be
    exercised without reimplementing the official client's wire semantics.
    """

    def __init__(
        self,
        *,
        deny_request_ids: frozenset[str] = frozenset(),
        error: Exception | None = None,
    ) -> None:
        self._denied = set(deny_request_ids)
        self._error = error
        self.calls: list[tuple[Any, str, Any]] = []
        self.required: list[tuple[str, ResourceKind, str, str | None]] = []

    def evaluate(self, request: Any, *, user_access_token: str, context: Any) -> Any:
        self.calls.append((request, user_access_token, context))
        if self._error is not None:
            raise self._error
        return request

    def require(
        self,
        snapshot: Any,
        *,
        context: Any,
        action: str,
        resource: Any,
        request_id: str | None = None,
    ) -> None:
        self.required.append((action, resource.kind, resource.resource_id, request_id))
        if request_id in self._denied:
            raise AuthorizationDenied("denied")

    def close(self) -> None:
        return None


def _seed(config: Any) -> None:
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
                document_id=BATCH_DOCUMENT_ID,
                tenant_id=str(TENANT_ID),
                title="Second Title",
                body="Second Body",
            ),
            Document(
                document_id=OTHER_DOCUMENT_ID,
                tenant_id=str(OTHER_TENANT_ID),
                title="Other Title",
                body="Other Body",
            ),
        ]
    )


def _reader(tmp_path: Path, client: Any) -> Any:
    config = make_config(tmp_path)
    _seed(config)
    verifier = FakeVerifier({ALLOWED_TOKEN: ALLOWED_SUBJECT, DENIED_TOKEN: "denied-subject"})
    return make_reader(config, verifier=verifier, client=client)


def _post(http: Any, body: Any, *, token: str | None = ALLOWED_TOKEN) -> Any:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return http.post(BATCH_ROUTE, json=body, headers=headers)


def test_batch_all_allow_returns_bodies_in_input_order(tmp_path: Path) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": [BATCH_DOCUMENT_ID, DOCUMENT_ID]})
    assert response.status_code == 200, response.text
    assert response.json() == {
        "documents": [
            {"id": BATCH_DOCUMENT_ID, "title": "Second Title", "body": "Second Body"},
            {"id": DOCUMENT_ID, "title": "Seeded Title", "body": "Seeded Body"},
        ]
    }
    assert response.headers["cache-control"] == "no-store"
    # Exactly one evaluation for the whole batch.
    assert len(client.calls) == 1
    request, token, _context = client.calls[0]
    assert token == ALLOWED_TOKEN
    assert [item.request_id for item in request.actions] == [
        f"{READ_REQUEST_ID}-0",
        f"{READ_REQUEST_ID}-1",
    ]
    assert [item.action for item in request.actions] == [DOCUMENT_READ_ACTION, DOCUMENT_READ_ACTION]
    assert [item.resource.resource_id for item in request.actions] == [
        BATCH_DOCUMENT_ID,
        DOCUMENT_ID,
    ]
    # require called once per occurrence, in input order.
    assert client.required == [
        (
            DOCUMENT_READ_ACTION,
            ResourceKind.APPLICATION_OWNED,
            BATCH_DOCUMENT_ID,
            "document-read-0",
        ),
        (DOCUMENT_READ_ACTION, ResourceKind.APPLICATION_OWNED, DOCUMENT_ID, "document-read-1"),
    ]


def test_batch_single_document_is_allowed(tmp_path: Path) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": [DOCUMENT_ID]})
    assert response.status_code == 200
    assert response.json()["documents"][0]["id"] == DOCUMENT_ID


def test_batch_deny_is_atomic_with_zero_bodies(tmp_path: Path) -> None:
    client = MixedDecisionClient(deny_request_ids=frozenset({"document-read-1"}))
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": [DOCUMENT_ID, BATCH_DOCUMENT_ID]})
    assert response.status_code == 403
    assert "Seeded" not in response.text
    assert "Second" not in response.text
    assert response.json() == {"error": "access denied"}
    assert len(client.calls) == 1


def test_batch_missing_document_returns_404_without_pdp(tmp_path: Path) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    missing = "66666666-6666-4666-8666-666666666666"
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": [DOCUMENT_ID, missing]})
    assert response.status_code == 404
    assert "Seeded" not in response.text
    assert client.calls == []


def test_batch_cross_tenant_document_returns_404_without_pdp(tmp_path: Path) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": [OTHER_DOCUMENT_ID]})
    assert response.status_code == 404
    assert "Other" not in response.text
    assert client.calls == []


@pytest.mark.parametrize(
    "body",
    [
        {"document_ids": []},
        {"document_ids": [DOCUMENT_ID, DOCUMENT_ID]},
        {"document_ids": ["not-a-uuid"]},
        {"document_ids": ["44444444-4444-4444-8444-44444444444"]},
        {"document_ids": ["44444444-4444-4444-8444-444444444444"[:0]]},
        {"document_ids": DOCUMENT_ID},
        {},
        {"document_ids": [DOCUMENT_ID], "tenant_id": str(TENANT_ID)},
        {"document_ids": [123]},
        {"document_ids": ["AA444444-4444-4444-8444-444444444444"]},
        [DOCUMENT_ID],
        "document_ids",
    ],
)
def test_batch_invalid_input_returns_400_without_pdp(tmp_path: Path, body: Any) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, body)
    assert response.status_code == 400
    assert client.calls == []


def test_batch_excess_ids_returns_400_without_pdp(tmp_path: Path) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    ids = [f"00000000-0000-4000-8000-{index:012d}" for index in range(BATCH_READ_MAX_IDS + 1)]
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": ids})
    assert response.status_code == 400
    assert client.calls == []


def test_batch_malformed_json_returns_400(tmp_path: Path) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = http.post(
            BATCH_ROUTE,
            content="{not-json",
            headers={
                "Authorization": f"Bearer {ALLOWED_TOKEN}",
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 400
    assert client.calls == []


def test_batch_missing_authorization_returns_401_without_pdp(tmp_path: Path) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": [DOCUMENT_ID]}, token=None)
    assert response.status_code == 401
    assert client.calls == []


def test_batch_unknown_subject_denies_without_pdp(tmp_path: Path) -> None:
    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": [DOCUMENT_ID]}, token="unmapped-token")
    assert response.status_code == 401
    assert client.calls == []


def test_batch_remote_error_fails_closed(tmp_path: Path) -> None:
    client = MixedDecisionClient(error=dependency_error())
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, {"document_ids": [DOCUMENT_ID]})
    assert response.status_code == 503
    assert "Seeded" not in response.text


def test_batch_read_rejects_unbounded_direct_call(tmp_path: Path) -> None:
    """The unit seam also refuses an out-of-bounds tuple (defense in depth)."""
    import asyncio

    client = MixedDecisionClient()
    reader = _reader(tmp_path, client)
    with pytest.raises(ValueError):
        asyncio.run(reader.read_batch(token=ALLOWED_TOKEN, document_ids=()))
