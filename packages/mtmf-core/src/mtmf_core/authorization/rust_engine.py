"""Private capability adapter for the Rust permission engine (PR 8A).

This module is the internal Python-owned seam to the private
``_mtmf_permission_engine`` PyO3 native module. PR 8A exposes only a
deterministic smoke/capability surface: no permission semantics are
implemented in Rust, and no active authorization path imports this
module.

The future native evaluation boundary (PR 8B+) is:

.. code-block:: text

    exact Action + already-applicable PermissionSets -> evaluation result

Python keeps ownership of policy applicability and authorization
context; the native kernel is a pure, deterministic, in-memory
computation that performs no retrieval and no I/O. Detached primitive
input is the rule: no live MTMF domain objects (``Action``, ``Role``,
``PermissionSet``, ``Permission``) cross the FFI boundary and no JSON
serialization is introduced to carry policy.

This adapter is deliberately not exported by
:mod:`mtmf_core.authorization` and is never imported by the
:class:`~mtmf_core.authorization.authorizer.Authorizer` in 8A.
"""

from __future__ import annotations

import importlib
from typing import Any

_NATIVE_MODULE_NAME = "_mtmf_permission_engine"


class RustEngineUnavailableError(RuntimeError):
    """Raised when the private native module cannot be imported.

    A native infrastructure failure is not a policy DENY. Because Rust is
    not on any active authorization path in 8A, this error never changes
    current Python authorization behavior.
    """


class RustEngineCapabilityError(RuntimeError):
    """Raised when the native module rejects the capability call.

    Covers a missing or invalid ``engine_version`` response. This is an
    infrastructure-capability failure, never a policy decision.
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
