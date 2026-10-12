"""Native batch adapter validation tests (PR 16, negative boundary only).

These tests exercise
:func:`mtmf_core.authorization.rust_engine.native_batch_evaluate` result
validation without requiring the native wheel: a fake module is injected
*only* to produce malformed/incapable native *responses*. Positive
native-feature evidence lives in ``test_rust_batch_authorizer.py`` and
uses the real installed module; no mock is ever substituted for a
positive native feature.

Covered fail-closed behavior: the adapter validates the complete batch
response (container type, exact length, per-element decision,
specificity, flags, deny reason, and coherence) before returning
anything, and maps malformed input/capability failures to the narrow
infrastructure exceptions that can never become a policy DENY or a
partial result.
"""

from __future__ import annotations

from typing import Any

import pytest

import mtmf_core.authorization.rust_engine as rust_engine
from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEvaluation,
    native_batch_evaluate,
)

_ACTIONS = [
    "urn:mtmf:iam:actions:system:principal:set-active",
    "urn:mtmf:iam:actions:system:principal:set-alias",
]
_PERMISSION_SETS = [("allow", ["urn:mtmf:iam:permissions:system:principal:set-*"])]


class _FakeModule:
    """A module-shaped object exposing only the batch capability."""

    def __init__(self, response: Any) -> None:
        self._response = response

    def batch_evaluate(self, permission_sets: Any, action_urns: Any) -> Any:
        return self._response


class _RaisingModule:
    """A module-shaped object whose batch capability raises TypeError."""

    def batch_evaluate(self, permission_sets: Any, action_urns: Any) -> Any:
        raise TypeError("wrong primitive type")


def _install(monkeypatch: pytest.MonkeyPatch, module: object) -> None:
    monkeypatch.setattr(rust_engine, "_load_native_module", lambda: module)


def test_valid_batch_response_is_validated_into_rust_evaluations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = [
        ("allow", "exact", True, False, None),
        ("deny", None, False, False, "no-match"),
    ]
    _install(monkeypatch, _FakeModule(response))
    evaluations = native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)
    assert all(isinstance(evaluation, RustEvaluation) for evaluation in evaluations)
    assert evaluations[0].allowed
    assert evaluations[0].matched_specificity == "exact"
    assert not evaluations[1].allowed
    assert evaluations[1].deny_reason == "no-match"


def test_missing_batch_capability_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    class _NoBatch:
        pass

    _install(monkeypatch, _NoBatch())
    with pytest.raises(RustEngineCapabilityError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_wrong_result_container_type_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeModule(42))
    with pytest.raises(RustEngineCapabilityError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_wrong_result_count_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeModule([("allow", "exact", True, False, None)]))
    with pytest.raises(RustEngineCapabilityError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_unknown_decision_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(
        monkeypatch,
        _FakeModule(
            [
                ("maybe", "exact", True, False, None),
                ("deny", None, False, False, "no-match"),
            ]
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_incoherent_state_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # An ALLOW with matched_deny true and no allow flag is incoherent.
    _install(
        monkeypatch,
        _FakeModule(
            [
                ("allow", "exact", False, True, None),
                ("deny", None, False, False, "no-match"),
            ]
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_no_match_with_specificity_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(
        monkeypatch,
        _FakeModule(
            [
                ("deny", "exact", False, False, "no-match"),
                ("deny", None, False, False, "no-match"),
            ]
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_non_boolean_flags_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(
        monkeypatch,
        _FakeModule(
            [
                ("allow", "exact", 1, 0, None),
                ("deny", None, False, False, "no-match"),
            ]
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_malformed_element_fails_whole_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    # The first element is valid; the second is malformed. Nothing is
    # returned because the adapter validates every element first.
    _install(
        monkeypatch,
        _FakeModule(
            [
                ("deny", None, False, False, "no-match"),
                "not-a-tuple",
            ]
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_native_type_error_is_normalized_to_value_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, _RaisingModule())
    with pytest.raises(ValueError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS)


def test_out_of_range_size_is_rejected_before_native_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _must_not_load() -> object:
        raise AssertionError("native module must not be loaded for an invalid batch size")

    monkeypatch.setattr(rust_engine, "_load_native_module", _must_not_load)
    with pytest.raises(ValueError):
        native_batch_evaluate(_PERMISSION_SETS, [])
    with pytest.raises(ValueError):
        native_batch_evaluate(_PERMISSION_SETS, _ACTIONS * 51)
