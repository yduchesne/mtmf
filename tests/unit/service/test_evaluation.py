"""Batch evaluation, decision mapping, context identity and TTL (H01-H10, H19, H21, H23, H24)."""

from __future__ import annotations

import pytest
from conftest import (
    ALLOW_ACTION,
    DENY_ACTION,
    NO_PERMISSION_ACTION,
    UNKNOWN_ACTION,
    action_body,
    auth_headers,
    seeded_harness,
)

from mtmf_api.authorization import AuthorizationEffect, DecisionReason
from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.domain.action import Action
from mtmf_core.domain.iam_urn import ActionUrn
from mtmf_service.evaluation import InternalEvaluationError, map_core_decision
from mtmf_service.sensitivity import AllowlistSensitiveActionClassifier
from mtmf_service.settings import ServiceSettings


def _post(harness, body, *, headers=None):
    return harness.client.post(
        "/v1/authorization/evaluate",
        json=body,
        headers=headers or auth_headers(),
    )


def test_h01_single_action_allow_and_deny():
    harness = seeded_harness()
    allowed = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert allowed.status_code == 200
    payload = allowed.json()
    assert payload["decisions"] == [{"request_id": "r1", "effect": "ALLOW", "reason": "PERMITTED"}]
    denied = _post(
        harness, action_body(("r1", DENY_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    assert denied.status_code == 200
    assert denied.json()["decisions"] == [
        {"request_id": "r1", "effect": "DENY", "reason": "EXPLICIT_DENY"}
    ]


def test_h02_hundred_actions_with_duplicates_preserve_order():
    harness = seeded_harness()
    actions = tuple((f"r{i}", ALLOW_ACTION if i % 2 == 0 else DENY_ACTION) for i in range(100))
    response = _post(harness, action_body(*actions, tenant_id=str(harness.world.tenant.id)))
    assert response.status_code == 200
    decisions = response.json()["decisions"]
    assert len(decisions) == 100
    assert [d["request_id"] for d in decisions] == [f"r{i}" for i in range(100)]
    assert decisions[0]["effect"] == "ALLOW"
    assert decisions[1]["effect"] == "DENY"


@pytest.mark.parametrize("count", [0, 101])
def test_h03_batch_size_bounds_rejected_without_processing(count):
    harness = seeded_harness()
    body = action_body(
        *[(f"r{i}", ALLOW_ACTION) for i in range(count)], tenant_id=str(harness.world.tenant.id)
    )
    response = _post(harness, body)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    # No token was ever verified (no policy/eligibility work happened).
    assert harness.service_verifier.calls == []
    assert harness.user_verifier.calls == []
    assert harness.attestor.calls == 0


def test_h03_duplicate_request_ids_rejected():
    harness = seeded_harness()
    body = action_body(
        ("dup", ALLOW_ACTION), ("dup", DENY_ACTION), tenant_id=str(harness.world.tenant.id)
    )
    response = _post(harness, body)
    assert response.status_code == 400
    assert harness.attestor.calls == 0


@pytest.mark.parametrize(
    "raw",
    [
        '{"tenant_id": "x", "tenant_id": "y", "actions": []}',
        '{"tenant_id": "x", "actions": [{"request_id": "r", "action": "a",'
        ' "resource": {"k": 1, "k": 2}}]}',
        "NaN",
        "{not json",
        "[1, 2, 3]",
        '"a string"',
    ],
)
def test_h04_strict_json_rejections(raw):
    harness = seeded_harness()
    response = harness.client.post(
        "/v1/authorization/evaluate",
        content=raw.encode(),
        headers={**auth_headers(), "Content-Type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert harness.attestor.calls == 0


@pytest.mark.parametrize(
    "body",
    [
        {"tenant_id": None, "actions": []},
        {
            "tenant_id": "not-a-uuid",
            "actions": [
                {"request_id": "r", "action": ALLOW_ACTION, "resource": {"kind": "capability"}}
            ],
        },
        {"tenant_id": "11111111-1111-1111-1111-111111111111", "actions": [], "principal_id": "x"},
        {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "actions": [
                {
                    "request_id": "r",
                    "action": "urn:mtmf:iam:actions:system:principal:*",
                    "resource": {"kind": "capability"},
                }
            ],
        },
        {
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            "actions": [
                {"request_id": "r", "action": ALLOW_ACTION, "resource": {"kind": "unknown"}}
            ],
        },
    ],
)
def test_h05_unknown_fields_wildcards_actor_ids_and_bad_resource_rejected(body):
    harness = seeded_harness()
    response = _post(harness, body)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert harness.attestor.calls == 0


def test_h06_unknown_action_denies_per_item():
    harness = seeded_harness()
    response = _post(
        harness,
        action_body(("r1", UNKNOWN_ACTION), tenant_id=str(harness.world.tenant.id)),
    )
    assert response.status_code == 200
    assert response.json()["decisions"] == [
        {"request_id": "r1", "effect": "DENY", "reason": "UNKNOWN_ACTION"}
    ]


def test_h07_mixed_known_and_unknown_actions_are_ordered():
    harness = seeded_harness()
    response = _post(
        harness,
        action_body(
            ("a", ALLOW_ACTION),
            ("b", UNKNOWN_ACTION),
            ("c", NO_PERMISSION_ACTION),
            tenant_id=str(harness.world.tenant.id),
        ),
    )
    assert response.status_code == 200
    assert [(d["request_id"], d["effect"], d["reason"]) for d in response.json()["decisions"]] == [
        ("a", "ALLOW", "PERMITTED"),
        ("b", "DENY", "UNKNOWN_ACTION"),
        ("c", "DENY", "NO_PERMISSION"),
    ]


def test_h08_capability_resource_is_action_level_only():
    harness = seeded_harness()
    body = action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    response = _post(harness, body)
    assert response.status_code == 200
    assert response.json()["decisions"][0]["effect"] == "ALLOW"


def test_h09_application_owned_resource_is_binding_metadata_only():
    harness = seeded_harness()
    body = {
        "tenant_id": str(harness.world.tenant.id),
        "organization_id": None,
        "actions": [
            {
                "request_id": "r1",
                "action": ALLOW_ACTION,
                "resource": {"kind": "application_owned", "type": "widget", "id": "w-1"},
            }
        ],
    }
    response = _post(harness, body)
    assert response.status_code == 200
    # The decision is action-level; no object-level authority is asserted.
    assert response.json()["decisions"][0]["effect"] == "ALLOW"


def test_h10_mtmf_owned_resource_never_allows():
    harness = seeded_harness()
    body = {
        "tenant_id": str(harness.world.tenant.id),
        "organization_id": None,
        "actions": [
            {
                "request_id": "r1",
                "action": ALLOW_ACTION,
                "resource": {"kind": "mtmf_owned", "type": "tenant", "id": "t-1"},
            }
        ],
    }
    response = _post(harness, body)
    assert response.status_code == 200
    assert response.json()["decisions"] == [
        {"request_id": "r1", "effect": "DENY", "reason": "UNSUPPORTED_RESOURCE"}
    ]


def test_h19_one_shared_context_and_one_policy_resolution():
    harness = seeded_harness(instrument=True)
    response = _post(
        harness,
        action_body(
            ("a", ALLOW_ACTION),
            ("b", DENY_ACTION),
            ("c", NO_PERMISSION_ACTION),
            tenant_id=str(harness.world.tenant.id),
        ),
    )
    assert response.status_code == 200
    assert len(harness.batch_authorizer.batches) == 1
    batch = harness.batch_authorizer.batches[0]
    first_context = batch.requests[0].context
    assert all(request.context is first_context for request in batch.requests)
    assert harness.resolver is not None
    assert harness.resolver.resolve_calls == 1


def test_h21_exhaustive_core_decision_mapping():
    assert map_core_decision(AuthorizationDecision.allow()) == (
        AuthorizationEffect.ALLOW,
        DecisionReason.PERMITTED,
    )
    assert map_core_decision(AuthorizationDecision.deny(DenyReason.NO_MATCH)) == (
        AuthorizationEffect.DENY,
        DecisionReason.NO_PERMISSION,
    )
    assert map_core_decision(AuthorizationDecision.deny(DenyReason.MATCHED_DENY)) == (
        AuthorizationEffect.DENY,
        DecisionReason.EXPLICIT_DENY,
    )
    assert map_core_decision(AuthorizationDecision.deny(DenyReason.INSUFFICIENT_DOMINANCE)) == (
        AuthorizationEffect.DENY,
        DecisionReason.INVALID_SCOPE,
    )
    assert map_core_decision(AuthorizationDecision.deny(DenyReason.UNSUPPORTED_CONSTRAINT)) == (
        AuthorizationEffect.DENY,
        DecisionReason.UNSUPPORTED_RESOURCE,
    )
    for internal in (
        DenyReason.INVALID_CONTEXT,
        DenyReason.TENANT_MISMATCH,
        DenyReason.NO_MANAGEMENT_SCOPE,
    ):
        with pytest.raises(InternalEvaluationError):
            map_core_decision(AuthorizationDecision.deny(internal))


def test_h21_no_policy_diagnostics_on_the_wire():
    harness = seeded_harness()
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    text = response.text
    for forbidden in ("matched", "specificity", "role", "policy", "principal_id", "identity_id"):
        assert forbidden not in text


def test_h23_conservative_default_ttl_is_sensitive():
    harness = seeded_harness()
    response = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    )
    payload = response.json()
    start = payload["issued_at"]
    end = payload["expires_at"]
    assert start == "2026-10-12T12:00:00Z"
    assert end == "2026-10-12T12:00:15Z"


def test_h23_allowlist_classifier_uses_default_for_non_sensitive():
    harness = seeded_harness(
        sensitivity=AllowlistSensitiveActionClassifier(frozenset({ALLOW_ACTION}))
    )
    non_sensitive = _post(
        harness,
        action_body(("r1", NO_PERMISSION_ACTION), tenant_id=str(harness.world.tenant.id)),
    )
    assert non_sensitive.json()["expires_at"] == "2026-10-12T12:01:00Z"


def test_h23_mixed_batch_is_bounded_by_sensitive_ttl():
    harness = seeded_harness(
        sensitivity=AllowlistSensitiveActionClassifier(frozenset({ALLOW_ACTION}))
    )
    response = _post(
        harness,
        action_body(
            ("r1", NO_PERMISSION_ACTION),
            ("r2", ALLOW_ACTION),
            tenant_id=str(harness.world.tenant.id),
        ),
    )
    assert response.json()["expires_at"] == "2026-10-12T12:00:15Z"


def test_h24_issued_precedes_expires_utc():
    harness = seeded_harness()
    payload = _post(
        harness, action_body(("r1", ALLOW_ACTION), tenant_id=str(harness.world.tenant.id))
    ).json()
    assert payload["issued_at"].endswith("Z")
    assert payload["expires_at"].endswith("Z")
    assert payload["issued_at"] < payload["expires_at"]


def test_h20_python_default_needs_no_native_module():
    import inspect

    from conftest import _issuer_config

    from mtmf_core.authorization.batch import BatchAuthorizer, RustBatchAuthorizer
    from mtmf_service.composition import build_authorization_service

    world = seeded_harness().world
    service = build_authorization_service(
        spi=world.spi, issuer_config=_issuer_config(), settings=ServiceSettings()
    )
    assert type(service._batch_authorizer) is BatchAuthorizer  # type: ignore[attr-defined]
    assert not isinstance(service._batch_authorizer, RustBatchAuthorizer)  # type: ignore[attr-defined]
    import mtmf_service.evaluation as evaluation_module

    assert "rust_engine" not in inspect.getsource(evaluation_module)


def test_action_object_is_exact_urn():
    assert Action(urn=ActionUrn(ALLOW_ACTION)).urn.value == ALLOW_ACTION
