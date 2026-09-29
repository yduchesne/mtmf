"""Private capability adapter for the Rust permission engine.

This module is the internal Python-owned seam to the private
``_mtmf_permission_engine`` PyO3 native module.

PR 8A exposed only a deterministic smoke/capability surface. PR 8B adds
the smallest primitive matcher bridge: ``native_match_permission_urn``
computes a single-Permission match fact (``"exact"``,
``"qualifier-wildcard"``, or ``None`` for a valid non-match) for one
detached Permission matcher URN against one detached exact Action URN.

Boundary invariants:

- primitive strings in; a primitive match fact out;
- no domain-object parameters and no domain conversion;
- no live MTMF domain objects (``Action``, ``Role``, ``PermissionSet``,
  ``Permission``) cross the FFI boundary and no JSON serialization is
  introduced to carry policy;
- malformed input raises ``ValueError`` from the native parser;
  malformed input is never a valid ``NO_MATCH``;
- this adapter is deliberately not exported by
  :mod:`mtmf_core.authorization` and is never imported by the
  :class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
  or the :class:`~mtmf_core.authorization.authorizer.Authorizer`: no
  active authorization path depends on Rust.
"""

from __future__ import annotations

import importlib
from typing import Any

_NATIVE_MODULE_NAME = "_mtmf_permission_engine"

# The primitive match facts the native matcher can return, using the
# existing Python specificity values.
_NATIVE_EXACT = "exact"
_NATIVE_QUALIFIER_WILDCARD = "qualifier-wildcard"
_NATIVE_MATCH_FACTS = frozenset({_NATIVE_EXACT, _NATIVE_QUALIFIER_WILDCARD})


class RustEngineUnavailableError(RuntimeError):
    """Raised when the private native module cannot be imported.

    A native infrastructure failure is not a policy DENY. Because Rust is
    not on any active authorization path, this error never changes
    current Python authorization behavior.
    """


class RustEngineCapabilityError(RuntimeError):
    """Raised when the native module rejects a capability call.

    Covers a missing/invalid ``engine_version`` response or a matcher
    response that is not one of the documented primitive match facts.
    This is an infrastructure-capability failure, never a policy
    decision.
    """


def _load_native_module() -> Any:
    """Import the private native module or fail with a clear error."""
    try:
        return importlib.import_module(_NATIVE_MODULE_NAME)
    except ImportError as exc:
        raise RustEngineUnavailableError(
            f"private native module {_NATIVE_MODULE_NAME!r} is not importable; "
            "run `./build.sh --rust` to build and install it"
        ) from exc


def engine_version() -> str:
    """Return the deterministic native engine capability version.

    Smoke/capability only: accepts no domain objects, parses no URNs,
    and evaluates no Actions. It proves that the canonical native build
    is importable by the current interpreter.
    """
    module = _load_native_module()
    version = module.engine_version()
    if not isinstance(version, str) or version == "":
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned an invalid engine version"
        )
    return version


def native_match_permission_urn(action_urn: str, permission_urn: str) -> str | None:
    """Match one exact Action URN against one Permission matcher URN in Rust.

    Primitive strings in; a primitive match fact out:

    - ``"exact"`` - exact qualifier match;
    - ``"qualifier-wildcard"`` - complete-qualifier ``*`` match;
    - ``None`` - valid input, no match.

    Malformed input raises :class:`ValueError` from the native parser: a
    parsing failure is deliberately distinct from a valid ``NO_MATCH``.
    No effect and no authorization decision are computed here: the call
    produces a match fact only.

    :raises ValueError: for malformed Action/Permission URN text.
    :raises RustEngineUnavailableError: when the native module is absent.
    :raises RustEngineCapabilityError: when the native response is not a
        documented primitive match fact.
    """
    module = _load_native_module()
    matcher = getattr(module, "match_permission", None)
    if not callable(matcher):
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} does not expose the primitive "
            "matcher 'match_permission'"
        )
    result = matcher(action_urn, permission_urn)
    if result is None:
        return None
    if not isinstance(result, str) or result not in _NATIVE_MATCH_FACTS:
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned an unknown match fact {result!r}"
        )
    return result
