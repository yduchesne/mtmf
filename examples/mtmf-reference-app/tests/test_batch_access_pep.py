"""PR20B mixed-operation batch: genuine mixed Actions and atomic disclosure.

The batch-access route maps the caller's closed operation enum to server-defined
exact Actions. These tests exercise the PEP's own ordering with deterministic
per-Action decisions: one MTMF batch, one occurrence per input operation in
order, and zero results when any occurrence is denied.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
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
    ACCESS_REQUEST_ID,
    BATCH_ACCESS_MAX_OPERATIONS,
    DOCUMENT_READ_ACTION,
    METADATA_ACTION,
)
from mtmf_reference_app.models import Document
from mtmf_reference_app.store import DocumentStore

from mtmf_api.authorization import ResourceKind

ACCESS_ROUTE = "/v1/documents/batch-access"
BATCH_DOCUMENT_ID = "77777777-7777-4777-8777-777777777777"
ALL_DOCUMENT_IDS = [
    DOCUMENT_ID,
    BATCH_DOCUMENT_ID,
    "88888888-8888-4888-8888-888888888888",
    "99999999-9999-4999-8999-999999999999",
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
]


def _seed(config: Any, count: int = 2) -> None:
    store = DocumentStore(config.sqlite_path)
    store.initialize()
    documents = [
        Document(
            document_id=document_id,
            tenant_id=str(TENANT_ID),
            title=f"Title {index}",
            body=f"Body {index}",
        )
        for index, document_id in enumerate(ALL_DOCUMENT_IDS[:count])
    ]
    documents.append(
        Document(
            document_id=OTHER_DOCUMENT_ID,
            tenant_id=str(OTHER_TENANT_ID),
            title="Other Title",
            body="Other Body",
        )
    )
    store.seed_documents(documents)


def _reader(tmp_path: Path, client: PolicyClient, *, count: int = 2):  # type: ignore[no-untyped-def]
    config = make_config(tmp_path)
    _seed(config, count)
    verifier = FakeVerifier({ALLOWED_TOKEN: ALLOWED_SUBJECT, DENIED_TOKEN: DENIED_SUBJECT})
    return make_reader(config, verifier=verifier, client=client)


def _post(http: Any, operations: list[dict[str, str]], *, token: str | None = ALLOWED_TOKEN) -> Any:
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    return http.post(ACCESS_ROUTE, json={"operations": operations}, headers=headers)


def _pair(document_id: str, operation: str) -> dict[str, str]:
    return {"document_id": document_id, "operation": operation}


def test_mixed_allow_deny_is_atomic_with_zero_results(tmp_path: Path) -> None:
    # Bob: metadata ALLOW, content DENY.
    client = PolicyClient(allowed_actions={METADATA_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(
            http,
            [_pair(DOCUMENT_ID, "metadata"), _pair(DOCUMENT_ID, "content")],
            token=DENIED_TOKEN,
        )
    assert response.status_code == 403
    assert "results" not in response.text
    assert "Title 0" not in response.text
    assert "Body 0" not in response.text
    assert len(client.calls) == 1
    request, _token, _context = client.calls[0]
    assert [item.action for item in request.actions] == [METADATA_ACTION, DOCUMENT_READ_ACTION]
    assert [item.request_id for item in request.actions] == [
        f"{ACCESS_REQUEST_ID}-0",
        f"{ACCESS_REQUEST_ID}-1",
    ]
    assert {item.resource.resource_id for item in request.actions} == {DOCUMENT_ID}


def test_mixed_deny_allow_reversed_order_is_atomic(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(
            http,
            [_pair(DOCUMENT_ID, "content"), _pair(DOCUMENT_ID, "metadata")],
            token=DENIED_TOKEN,
        )
    assert response.status_code == 403
    assert "results" not in response.text
    assert len(client.calls) == 1


def test_both_allow_returns_ordered_results_without_metadata_body(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(
            http,
            [_pair(DOCUMENT_ID, "metadata"), _pair(DOCUMENT_ID, "content")],
            token=ALLOWED_TOKEN,
        )
    assert response.status_code == 200
    results = response.json()["results"]
    assert results[0] == {
        "operation": "metadata",
        "document": {"id": DOCUMENT_ID, "title": "Title 0"},
    }
    assert "body" not in results[0]["document"]
    assert results[1] == {
        "operation": "content",
        "document": {"id": DOCUMENT_ID, "title": "Title 0", "body": "Body 0"},
    }
    assert response.headers["cache-control"] == "no-store"
    # One batch, two occurrences, distinct Actions, same loaded resource.
    request, _token, _context = client.calls[0]
    assert [item.action for item in request.actions] == [METADATA_ACTION, DOCUMENT_READ_ACTION]
    assert len(client.required) == 2
    assert client.required[0][1] == client.required[1][1]
    assert client.required[0][1].kind is ResourceKind.APPLICATION_OWNED


def test_both_deny_returns_403_without_results(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions=frozenset())
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(
            http,
            [_pair(DOCUMENT_ID, "metadata"), _pair(DOCUMENT_ID, "content")],
            token=ALLOWED_TOKEN,
        )
    assert response.status_code == 403
    assert "results" not in response.text


def test_single_operation_is_accepted(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, [_pair(DOCUMENT_ID, "metadata")], token=DENIED_TOKEN)
    assert response.status_code == 200
    assert response.json()["results"][0]["operation"] == "metadata"
    assert "body" not in response.json()["results"][0]["document"]


def test_maximum_sixteen_operations_accepted(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client, count=8)
    operations = [
        _pair(document_id, operation)
        for document_id in ALL_DOCUMENT_IDS[:8]
        for operation in ("metadata", "content")
    ]
    assert len(operations) == BATCH_ACCESS_MAX_OPERATIONS
    with make_test_client(reader, client) as http:
        response = _post(http, operations)
    assert response.status_code == 200
    assert len(response.json()["results"]) == BATCH_ACCESS_MAX_OPERATIONS


@pytest.mark.parametrize("count", [0, 17, 18])
def test_out_of_range_operation_counts_return_400(tmp_path: Path, count: int) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client, count=8)
    operations = [
        _pair(ALL_DOCUMENT_IDS[index % 8], "metadata" if index < 8 else "content")
        for index in range(count)
    ]
    with make_test_client(reader, client) as http:
        response = _post(http, operations)
    assert response.status_code == 400
    assert client.calls == []


@pytest.mark.parametrize(
    "operations",
    [
        [_pair(DOCUMENT_ID, "metadata"), _pair(DOCUMENT_ID, "metadata")],
        [_pair(DOCUMENT_ID, "content"), _pair(DOCUMENT_ID, "content")],
    ],
)
def test_duplicate_pair_returns_400_without_pdp(
    tmp_path: Path, operations: list[dict[str, str]]
) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, operations)
    assert response.status_code == 400
    assert client.calls == []


@pytest.mark.parametrize(
    "body",
    [
        {"operations": [{"document_id": DOCUMENT_ID, "operation": "delete"}]},
        {"operations": [{"document_id": DOCUMENT_ID, "operation": "read"}]},
        {"operations": [{"document_id": DOCUMENT_ID, "operation": "metadata", "extra": "x"}]},
        {"operations": [{"document_id": DOCUMENT_ID, "operation": "metadata", "tenant_id": "x"}]},
        {
            "operations": [
                {"document_id": "AA444444-4444-4444-8444-444444444444", "operation": "metadata"}
            ]
        },
        {"operations": [{"document_id": 5, "operation": "metadata"}]},
        {"operations": "not-a-list"},
        {},
        {"operations": [{"document_id": DOCUMENT_ID, "operation": "metadata"}], "tenant_id": "x"},
        [{"document_id": DOCUMENT_ID, "operation": "metadata"}],
    ],
)
def test_invalid_shape_returns_400_without_pdp(tmp_path: Path, body: Any) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = http.post(
            ACCESS_ROUTE, json=body, headers={"Authorization": f"Bearer {ALLOWED_TOKEN}"}
        )
    assert response.status_code == 400
    assert client.calls == []


def test_malformed_json_returns_400_without_pdp(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = http.post(
            ACCESS_ROUTE,
            content="{not-json",
            headers={
                "Authorization": f"Bearer {ALLOWED_TOKEN}",
                "Content-Type": "application/json",
            },
        )
    assert response.status_code == 400
    assert client.calls == []


def test_missing_document_in_batch_returns_404_without_pdp(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client)
    missing = "66666666-6666-4666-8666-666666666666"
    with make_test_client(reader, client) as http:
        response = _post(http, [_pair(DOCUMENT_ID, "metadata"), _pair(missing, "content")])
    assert response.status_code == 404
    assert client.calls == []


def test_cross_tenant_document_in_batch_returns_404_without_pdp(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, [_pair(OTHER_DOCUMENT_ID, "metadata")])
    assert response.status_code == 404
    assert "Other" not in response.text
    assert client.calls == []


def test_missing_authorization_returns_401_without_pdp(tmp_path: Path) -> None:
    client = PolicyClient(allowed_actions={METADATA_ACTION, DOCUMENT_READ_ACTION})
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, [_pair(DOCUMENT_ID, "metadata")], token=None)
    assert response.status_code == 401
    assert client.calls == []


def test_remote_error_fails_closed_503(tmp_path: Path) -> None:
    client = PolicyClient(error=dependency_error())
    reader = _reader(tmp_path, client)
    with make_test_client(reader, client) as http:
        response = _post(http, [_pair(DOCUMENT_ID, "metadata")])
    assert response.status_code == 503
    assert "Title 0" not in response.text
