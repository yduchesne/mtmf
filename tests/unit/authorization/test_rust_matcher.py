"""PR 8B Python/Rust matcher parity tests.

The matrix mirrors the PR 8B plan (sections 12 and 21):

- VALID: for every documented case, the Python matcher
  (``PermissionUrn``/``ActionUrn`` + ``match_permission_urn``) and the
  Rust private matcher (through the ``rust_engine`` primitive adapter)
  agree under the normalization Python ``EXACT`` <-> ``"exact"``,
  Python ``QUALIFIER_WILDCARD`` <-> ``"qualifier-wildcard"``, and
  Python ``NO_MATCH`` <-> ``None``.
- INVALID: inputs the Python typed constructors reject with
  ``ValueError`` must also raise ``ValueError`` from the native parser;
  malformed input is never a valid ``NO_MATCH``.
- DETERMINISM: repeated native calls return identical facts.
- BOUNDARY: the adapter stays private (never exported by
  :mod:`mtmf_core.authorization`), module absence fails closed with
  :class:`RustEngineUnavailableError`, and unknown native responses
  fail with :class:`RustEngineCapabilityError`.

Tests that genuinely require the built native module skip when it is
not installed (for example in plain ``./build.sh --qa`` on a machine
that has not run ``./build.sh --rust``). Hermetic adapter-behavior tests
always run. No test here starts PostgreSQL, Podman, or any external
service.
"""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

import pytest

from mtmf_core import (
    ActionUrn,
    MatchSpecificity,
    PermissionUrn,
    match_permission_urn,
)
from mtmf_core.authorization.rust_engine import (
    RustEngineCapabilityError,
    RustEngineUnavailableError,
    native_match_permission_urn,
)

NATIVE_MODULE = "_mtmf_permission_engine"

# --- helpers ---------------------------------------------------------------


def _native() -> ModuleType:
    return pytest.importorskip(NATIVE_MODULE)


def _python_fact(permission: PermissionUrn, action: ActionUrn) -> str | None:
    """Normalize the Python matcher fact to the primitive fact format."""
    result = match_permission_urn(permission, action)
    if result.specificity is MatchSpecificity.EXACT:
        return "exact"
    if result.specificity is MatchSpecificity.QUALIFIER_WILDCARD:
        return "qualifier-wildcard"
    assert result.specificity is None
    return None


def _fact(via: str, *, action: str, permission: str) -> str | None:
    """Compute the match fact through either the Python or native path."""
    if via == "python":
        return _python_fact(PermissionUrn(permission), ActionUrn(action))
    if via == "native":
        return native_match_permission_urn(action, permission)
    raise AssertionError(f"unknown path {via!r}")


# --- VALID: Python/Rust parity on every documented case --------------------

_VALID_CASES = [
    # (permission resource, permission verb, permission qualifier,
    #  action resource, action verb, action qualifier, expected fact)
    # exact
    ("principal", "set", "active", "principal", "set", "active", "exact"),
    # exact mismatch
    ("principal", "set", "active", "principal", "set", "inactive", None),
    # wildcard
    ("principal", "set", "*", "principal", "set", "active", "qualifier-wildcard"),
    # wildcard other qualifier
    ("principal", "set", "*", "principal", "set", "alias", "qualifier-wildcard"),
    # verb mismatch
    ("principal", "set", "*", "principal", "get", "object", None),
    # resource mismatch
    ("principal", "set", "*", "tenant", "set", "active", None),
    # later hyphens: same hyphenated qualifier
    ("principal", "set", "self-hosted", "principal", "set", "self-hosted", "exact"),
    # later-hyphen mismatch: different hyphenated qualifier
    ("principal", "set", "self-hosted", "principal", "set", "self-hosted-v2", None),
]


@pytest.mark.parametrize(
    (
        "permission_resource",
        "permission_verb",
        "permission_qualifier",
        "action_resource",
        "action_verb",
        "action_qualifier",
        "expected",
    ),
    _VALID_CASES,
)
def test_valid_case_python_and_native_agree(
    permission_resource: str,
    permission_verb: str,
    permission_qualifier: str,
    action_resource: str,
    action_verb: str,
    action_qualifier: str,
    expected: str | None,
) -> None:
    _native()
    action = f"urn:mtmf:iam:actions:system:{action_resource}:{action_verb}-{action_qualifier}"
    permission = (
        f"urn:mtmf:iam:permissions:system:{permission_resource}:"
        f"{permission_verb}-{permission_qualifier}"
    )
    python_fact = _fact("python", action=action, permission=permission)
    native_fact = _fact("native", action=action, permission=permission)
    assert python_fact == expected
    assert native_fact == python_fact


def test_repeated_native_calls_are_deterministic() -> None:
    _native()
    action = "urn:mtmf:iam:actions:system:principal:set-active"
    permission = "urn:mtmf:iam:permissions:system:principal:set-*"
    assert native_match_permission_urn(action, permission) == "qualifier-wildcard"
    for _ in range(5):
        assert native_match_permission_urn(action, permission) == "qualifier-wildcard"
    non_match = "urn:mtmf:iam:permissions:system:principal:set-inactive"
    assert native_match_permission_urn(action, non_match) is None
    for _ in range(5):
        assert native_match_permission_urn(action, non_match) is None


# --- INVALID grammar parity ------------------------------------------------

_VALID_ACTION = "urn:mtmf:iam:actions:system:principal:set-active"
_VALID_PERMISSION = "urn:mtmf:iam:permissions:system:principal:set-*"

_INVALID_ACTIONS = [
    "urn:wrong:iam:actions:system:principal:set-active",  # wrong prefix
    "urn:mtmf:iam:permissions:system:principal:set-active",  # Permission kind as Action
    "urn:mtmf:iam:actions::principal:set-active",  # missing namespace
    "urn:mtmf:iam:actions:tenant:principal:set-active",  # tenant namespace
    "urn:mtmf:iam:actions:vendor:principal:set-active",  # unknown namespace
    "urn:mtmf:iam:actions:system::set-active",  # empty resource
    "urn:mtmf:iam:actions:system:principal:setactive",  # missing operation hyphen
    "urn:mtmf:iam:actions:system:principal:-active",  # empty verb
    "urn:mtmf:iam:actions:system:principal:set-",  # empty qualifier
    "urn:mtmf:iam:actions:system:prin*cipal:set-active",  # wildcard resource
    "urn:mtmf:iam:actions:system:principal:s*t-active",  # wildcard verb
    "urn:mtmf:iam:actions:system:principal:set-*",  # wildcard qualifier
    "urn:mtmf:iam:actions:system:principal:set-act*ve",  # partial wildcard
    "urn:mtmf:iam:actions:system:principal:set -active",  # whitespace
    " urn:mtmf:iam:actions:system:principal:set-active",  # leading whitespace
    "urn:mtmf:iam:actions:system:principal:set-active:extra",  # extra component
]

_INVALID_PERMISSIONS = [
    "urn:wrong:iam:permissions:system:principal:set-*",  # wrong prefix
    "urn:mtmf:iam:actions:system:principal:set-*",  # Action kind as Permission
    "urn:mtmf:iam:permissions::principal:set-*",  # missing namespace
    "urn:mtmf:iam:permissions:tenant:principal:set-*",  # tenant namespace
    "urn:mtmf:iam:permissions:vendor:principal:set-*",  # unknown namespace
    "urn:mtmf:iam:permissions:system::set-*",  # empty resource
    "urn:mtmf:iam:permissions:system:principal:set*",  # missing operation hyphen
    "urn:mtmf:iam:permissions:system:principal:-*",  # empty verb
    "urn:mtmf:iam:permissions:system:principal:set-",  # empty qualifier
    "urn:mtmf:iam:permissions:system:prin*cipal:set-*",  # wildcard resource
    "urn:mtmf:iam:permissions:system:principal:s*t-*",  # wildcard verb
    "urn:mtmf:iam:permissions:system:principal:set-act*ve",  # partial/embedded wildcard
    "urn:mtmf:iam:permissions:system:principal:set-al*",  # partial wildcard
    "urn:mtmf:iam:permissions:system:principal:set -*",  # whitespace
    "urn:mtmf:iam:permissions:system:principal:set-*:extra",  # extra component
]


@pytest.mark.parametrize("action_text", _INVALID_ACTIONS)
def test_invalid_action_grammar_rejected_by_python_and_native(action_text: str) -> None:
    _native()
    with pytest.raises(ValueError):
        ActionUrn(action_text)
    with pytest.raises(ValueError):
        native_match_permission_urn(action_text, _VALID_PERMISSION)


@pytest.mark.parametrize("permission_text", _INVALID_PERMISSIONS)
def test_invalid_permission_grammar_rejected_by_python_and_native(
    permission_text: str,
) -> None:
    _native()
    with pytest.raises(ValueError):
        PermissionUrn(permission_text)
    with pytest.raises(ValueError):
        native_match_permission_urn(_VALID_ACTION, permission_text)


def test_malformed_input_is_never_a_valid_non_match() -> None:
    _native()
    # A malformed URN must raise, never silently return None like a
    # valid non-match would.
    for action_text in (
        "urn:mtmf:iam:actions:system:principal:set-",
        "not-a-urn",
        "",
    ):
        with pytest.raises(ValueError):
            native_match_permission_urn(action_text, _VALID_PERMISSION)
    for permission_text in (
        "urn:mtmf:iam:permissions:system:principal:set-",
        "not-a-urn",
        "",
    ):
        with pytest.raises(ValueError):
            native_match_permission_urn(_VALID_ACTION, permission_text)


# --- BOUNDARY: adapter privacy and fail-closed behavior ---------------------


def test_native_adapter_is_private_to_the_authorization_package() -> None:
    import mtmf_core.authorization as authorization

    assert "native_match_permission_urn" not in authorization.__all__
    assert not hasattr(authorization, "native_match_permission_urn")


def test_adapter_fails_closed_when_native_module_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, NATIVE_MODULE, None)
    with pytest.raises(RustEngineUnavailableError):
        native_match_permission_urn(_VALID_ACTION, _VALID_PERMISSION)


def test_adapter_rejects_unknown_native_match_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(
            engine_version=lambda: "0.1.0",
            match_permission=lambda action_urn, permission_urn: "ALLOW",  # type: ignore[return-value]
        ),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_match_permission_urn(_VALID_ACTION, _VALID_PERMISSION)


def test_adapter_rejects_missing_native_matcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(engine_version=lambda: "0.1.0"),
    )
    with pytest.raises(RustEngineCapabilityError):
        native_match_permission_urn(_VALID_ACTION, _VALID_PERMISSION)


def test_adapter_accepts_documented_native_match_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(
        sys.modules,
        NATIVE_MODULE,
        SimpleNamespace(
            engine_version=lambda: "0.1.0",
            match_permission=lambda action_urn, permission_urn: None,  # type: ignore[arg-type]
        ),
    )
    assert native_match_permission_urn(_VALID_ACTION, _VALID_PERMISSION) is None
