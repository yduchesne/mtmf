"""EXPERIMENTAL PR 8F msgspec semantic-buffer evaluator adapter.

This module is the benchmark-side adapter for the experimental
msgspec/MessagePack semantic boundary. It satisfies the same narrow
internal evaluator protocol as :class:`PermissionEvaluator` and
:class:`RustPermissionEvaluator` and is used only by the PR 8F
benchmark: it is NOT used by the :class:`Authorizer`, and the production
``RustPermissionEvaluator`` (URN-text boundary) is unchanged.

Path measured (end-to-end):

.. code-block:: text

    domain (Action, Roles)
        -> semantic wire DTOs         (msgspec_wire.build_payload)
        -> MessagePack encode          (M1: Encoder.encode /
                                        M2: Encoder.encode_into reusable buffer)
        -> one PyO3 call               (bytes-like payload)
        -> Rust MessagePack decode     (no MTMF URN reparsing)
        -> canonical Rust evaluator
        -> primitive 5-tuple result
        -> validated + mapped back to AuthorizationDecision

Every per-call evaluation transfers the full policy in the payload:
nothing is retained between calls (no compiled-policy handle, no cache).

Failure semantics mirror the production seam: malformed wire data
raises :class:`PermissionEvaluationInfrastructureError` (never ALLOW or
a semantic DENY); the existing native-result validation and decision
mapping helpers from the production adapters are reused rather than
duplicated.
"""

from __future__ import annotations

import importlib
from collections.abc import Iterable
from typing import Literal

import msgspec.msgpack as msgpack
from msgspec_wire import build_payload

from mtmf_core.authorization.decision import AuthorizationDecision
from mtmf_core.authorization.evaluator import PermissionEvaluatorProtocol
from mtmf_core.authorization.rust_engine import _validate_native_evaluation
from mtmf_core.authorization.rust_permission_evaluator import (
    PermissionEvaluationInfrastructureError,
    _map_native_evaluation,
)
from mtmf_core.domain.action import Action
from mtmf_core.domain.role import Role

_NATIVE_MODULE_NAME = "_mtmf_permission_engine"

EncodeMode = Literal["encode", "encode_into"]


def _load_semantic_native() -> object:
    """Import the private native module and locate the experimental entry point.

    :raises PermissionEvaluationInfrastructureError: when the module or
        the experimental entry point is unavailable (fail closed).
    """
    try:
        module = importlib.import_module(_NATIVE_MODULE_NAME)
    except ImportError as exc:
        raise PermissionEvaluationInfrastructureError(
            f"private native module {_NATIVE_MODULE_NAME!r} is not importable; "
            "run `./build.sh --rust` first"
        ) from exc
    evaluator = getattr(module, "evaluate_semantic_msgpack", None)
    profile = getattr(module, "build_profile", None)
    if not callable(evaluator):
        raise PermissionEvaluationInfrastructureError(
            f"native module {_NATIVE_MODULE_NAME!r} does not expose the experimental "
            "evaluator 'evaluate_semantic_msgpack'; rebuild with `./build.sh --rust`"
        )
    if not callable(profile):
        raise PermissionEvaluationInfrastructureError(
            f"native module {_NATIVE_MODULE_NAME!r} does not expose 'build_profile'; "
            "rebuild with `./build.sh --rust`"
        )
    return module


def native_build_profile() -> str:
    """Return the installed native build profile (``"debug"``/``"release"``).

    Lets benchmark output record which native build was measured, so
    debug and release characterization are never conflated.
    """
    module = _load_semantic_native()
    return str(module.build_profile())  # type: ignore[attr-defined]


class MsgspecEvaluator(PermissionEvaluatorProtocol):
    """Experimental msgspec semantic-buffer evaluator (benchmark-only).

    ``encode_mode`` selects the encode variant: ``"encode"`` (M1) or
    ``"encode_into"`` (M2, reusable buffer). Every evaluation transfers
    the complete policy payload; nothing is compiled or retained.
    """

    def __init__(
        self,
        encode_mode: EncodeMode = "encode",
        buffer_size: int = 1 << 20,
    ) -> None:
        self._encode_mode = encode_mode
        self._encoder = msgpack.Encoder()
        self._buffer = bytearray(buffer_size)
        self._native = _load_semantic_native()

    @property
    def encoder(self) -> msgpack.Encoder:
        """The msgspec encoder (component benchmarks reuse it)."""
        return self._encoder

    @property
    def buffer(self) -> bytearray:
        """The reusable ``encode_into`` buffer (M2 component reuse)."""
        return self._buffer

    def evaluate(self, action: Action, roles: Iterable[Role]) -> AuthorizationDecision:
        """Decide one exact Action via the experimental semantic boundary.

        :raises PermissionEvaluationInfrastructureError: for native
            unavailability, capability, wire, parsing, or
            malformed/incoherent response failures; never a policy
            decision.
        """
        payload = build_payload(action, roles)
        if self._encode_mode == "encode":
            encoded = self._encoder.encode(payload)
        elif self._encode_mode == "encode_into":
            self._encoder.encode_into(payload, self._buffer)
            encoded = self._buffer
        else:
            raise PermissionEvaluationInfrastructureError(
                f"unsupported encode mode {self._encode_mode!r}"
            )
        try:
            native_response = self._native.evaluate_semantic_msgpack(encoded)  # type: ignore[attr-defined]
        except (ValueError, TypeError) as exc:
            raise PermissionEvaluationInfrastructureError(
                "experimental msgspec semantic evaluation failed; the protected operation "
                "must fail closed because no ALLOW decision can be produced"
            ) from exc
        evaluation = _validate_native_evaluation(native_response)
        return _map_native_evaluation(evaluation)


__all__ = [
    "EncodeMode",
    "MsgspecEvaluator",
    "native_build_profile",
]
