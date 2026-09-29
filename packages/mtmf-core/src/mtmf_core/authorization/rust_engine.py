"""Private capability adapter for the Rust permission engine.

This module is the internal Python-owned seam to the private
``_mtmf_permission_engine`` PyO3 native module. It exposes the
primitive capability surface (``engine_version``), the smallest
primitive matcher bridge (``native_match_permission_urn``, which
computes a single-Permission match fact (``"exact"``,
``"qualifier-wildcard"``, or ``None`` for a valid non-match) for one
detached Permission matcher URN against one detached exact Action URN),
the primitive native evaluator bridge:
``native_evaluate`` evaluates one exact Action against zero or more
already-applicable detached PermissionSets entirely in Rust and returns
a validated :class:`RustEvaluation` aggregate result (decision, highest
specificity, ALLOW/DENY presence at that specificity, coarse deny
reason), and - PR 8G experiment only - the ``native_compile_policy``
compiled-policy bridge: compile already-applicable detached
PermissionSets once into an opaque immutable native object whose
``evaluate`` method handles repeated Actions without resending,
reparsing, sorting, or scanning policy.

Boundary invariants:

- primitive strings/lists of primitive pairs in; a validated primitive
  result out;
- no domain-object parameters and no domain conversion;
- no live MTMF domain objects (``Action``, ``Role``, ``PermissionSet``,
  ``Permission``) cross the FFI boundary and no JSON serialization is
  introduced to carry policy;
- malformed input raises ``ValueError`` from the native parser;
  malformed input is never a valid ``NO_MATCH`` or a policy DENY;
- unknown PermissionSet effects raise ``ValueError`` and are never
  silently mapped to ALLOW or DENY;
- the native response is strictly validated: unknown decisions,
  specificities, deny reasons, malformed tuples, and incoherent result
  states fail with :class:`RustEngineCapabilityError`;
- this adapter is deliberately not exported by
  :mod:`mtmf_core.authorization` and is never imported by the
  :class:`~mtmf_core.authorization.permission_evaluator.PermissionEvaluator`
  or the :class:`~mtmf_core.authorization.authorizer.Authorizer`: no
  active authorization path depends on Rust, and Rust never determines
  which policy is applicable.

``native_evaluate`` and ``native_match_permission_urn`` are the only
bridges on the active authorization path (through
:class:`~mtmf_core.authorization.rust_permission_evaluator.RustPermissionEvaluator`).
``native_compile_policy`` is experimental (PR 8G) and is reached only by
benchmark/experimental code, never by a production evaluator or the
Authorizer. Wrong primitive types or container shapes at the native
boundary are normalized into the malformed-input ``ValueError`` contract
instead of leaking an unclassified ``TypeError``.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any

_NATIVE_MODULE_NAME = "_mtmf_permission_engine"

# The primitive match facts the native matcher can return, using the
# existing Python specificity values.
_NATIVE_EXACT = "exact"
_NATIVE_QUALIFIER_WILDCARD = "qualifier-wildcard"
_NATIVE_MATCH_FACTS = frozenset({_NATIVE_EXACT, _NATIVE_QUALIFIER_WILDCARD})

# The primitive evaluation outcomes the native evaluator can return.
_NATIVE_ALLOW = "allow"
_NATIVE_DENY = "deny"
_NATIVE_DECISIONS = frozenset({_NATIVE_ALLOW, _NATIVE_DENY})
_NATIVE_NO_MATCH = "no-match"
_NATIVE_MATCHED_DENY = "matched-deny"
_NATIVE_DENY_REASONS = frozenset({_NATIVE_NO_MATCH, _NATIVE_MATCHED_DENY})


class RustEngineUnavailableError(RuntimeError):
    """Raised when the private native module cannot be imported.

    A native infrastructure failure is not a policy DENY. Because Rust is
    not on any active authorization path, this error never changes
    current Python authorization behavior.
    """


class RustEngineCapabilityError(RuntimeError):
    """Raised when the native module rejects a capability call.

    Covers a missing/invalid ``engine_version`` response, a matcher
    response that is not one of the documented primitive match facts, a
    missing/invalid native evaluator, or an evaluator response that is
    not a documented coherent primitive result. This is an
    infrastructure-capability failure, never a policy decision.
    """


@dataclass(frozen=True, slots=True)
class RustEvaluation:
    """Validated primitive aggregate result of one native evaluation.

    Mirrors the evidence the Python reference decision carries:

    - :attr:`decision` is exactly ``"allow"`` or ``"deny"``;
    - :attr:`matched_specificity` is the highest matching specificity
      (``"exact"``, ``"qualifier-wildcard"``) or ``None``;
    - :attr:`matched_allow`/:attr:`matched_deny` report whether an
      ALLOW/DENY existed at that maximum specificity;
    - :attr:`deny_reason` is ``"no-match"``, ``"matched-deny"``, or
      ``None`` for an ALLOW.

    Only the native module constructs this class; the adapter validates
    every response against the documented coherent state matrix first.
    """

    decision: str
    matched_specificity: str | None
    matched_allow: bool
    matched_deny: bool
    deny_reason: str | None

    @property
    def allowed(self) -> bool:
        """True only for an explicit native ALLOW decision."""
        return self.decision == _NATIVE_ALLOW


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

    Malformed input raises :class:`ValueError` from the native parser or
    from the adapter's type/shape normalization: a parsing failure is
    deliberately distinct from a valid ``NO_MATCH``. No effect and no
    authorization decision are computed here: the call produces a match
    fact only.

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
    try:
        result = matcher(action_urn, permission_urn)
    except TypeError as exc:
        # PyO3 rejects wrong primitive types (e.g. an int or None where
        # an exact Action/Permission URN 'str' is required) with
        # TypeError. Normalize that into the documented ValueError
        # contract so every malformed-input class classifies identically
        # and none can be misread as a valid non-match.
        raise ValueError(
            f"malformed primitive input to the native {_NATIVE_MODULE_NAME!r} boundary; "
            "expected exact Action and Permission URN 'str' values"
        ) from exc
    if result is None:
        return None
    if not isinstance(result, str) or result not in _NATIVE_MATCH_FACTS:
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned an unknown match fact {result!r}"
        )
    return result


def _validate_native_evaluation(native_response: Any) -> RustEvaluation:
    """Validate the raw native evaluator response into a coherent result.

    The native contract is a 5-tuple ``(decision, specificity,
    matched_allow, matched_deny, deny_reason)``. Any other shape, unknown
    primitive value, or incoherent state matrix entry fails with
    :class:`RustEngineCapabilityError`.

    Documented coherent states:

    - ALLOW: specificity set, ``matched_allow`` true, ``matched_deny``
      false, no deny reason;
    - DENY/NO_MATCH: specificity ``None``, both flags false;
    - DENY/MATCHED_DENY: specificity set, ``matched_deny`` true, with
      ``matched_allow`` reporting an equal-specificity ALLOW if one
      matched.
    """
    if not isinstance(native_response, tuple) or len(native_response) != 5:
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned a malformed evaluation "
            f"response {native_response!r}; expected a 5-tuple"
        )
    decision, specificity, matched_allow, matched_deny, deny_reason = native_response
    if not isinstance(decision, str) or decision not in _NATIVE_DECISIONS:
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned unknown evaluation "
            f"decision {decision!r}; expected exactly 'allow' or 'deny'"
        )
    if specificity is not None and (
        not isinstance(specificity, str) or specificity not in _NATIVE_MATCH_FACTS
    ):
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned unknown matched "
            f"specificity {specificity!r}"
        )
    if not isinstance(matched_allow, bool) or not isinstance(matched_deny, bool):
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned non-boolean match flags "
            f"({matched_allow!r}, {matched_deny!r})"
        )
    if deny_reason is not None and (
        not isinstance(deny_reason, str) or deny_reason not in _NATIVE_DENY_REASONS
    ):
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned unknown deny reason {deny_reason!r}"
        )
    evaluation = RustEvaluation(decision, specificity, matched_allow, matched_deny, deny_reason)
    if evaluation.decision == _NATIVE_ALLOW:
        coherent = (
            evaluation.matched_specificity is not None
            and evaluation.matched_allow
            and not evaluation.matched_deny
            and evaluation.deny_reason is None
        )
    elif evaluation.deny_reason == _NATIVE_NO_MATCH:
        coherent = (
            evaluation.matched_specificity is None
            and not evaluation.matched_allow
            and not evaluation.matched_deny
        )
    else:
        coherent = evaluation.matched_specificity is not None and evaluation.matched_deny
    if not coherent:
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned an incoherent evaluation "
            f"state {native_response!r}"
        )
    return evaluation


def native_evaluate(
    action_urn: str,
    permission_sets: list[tuple[str, list[str]]],
) -> RustEvaluation:
    """Evaluate one exact Action against detached PermissionSets in Rust.

    Primitive data in; a validated :class:`RustEvaluation` out.
    ``permission_sets`` is a list of ``(effect, permissions)`` pairs
    where ``effect`` is exactly ``"allow"`` or ``"deny"`` and
    ``permissions`` is a list of Permission matcher URN texts. No domain
    conversion is performed: this adapter accepts no ``Action``,
    ``Role``, ``PermissionSet``, or ``Permission`` objects, and Rust
    never determines which policy is applicable.

    The computed semantics match the Python reference: match all
    Permissions, retain maximum specificity, discard lower specificities
    before effect resolution, let an equal-specificity DENY win, default
    to DENY on no match, and stay independent of set order, Permission
    order, and duplicates.

    :raises ValueError: for malformed Action/Permission URNs, unknown
        PermissionSet effects, or wrong primitive types/container
        shapes; malformed input is never a policy DENY.
    :raises RustEngineUnavailableError: when the native module is absent.
    :raises RustEngineCapabilityError: when the native evaluator is
        missing or its response is malformed/unknown/incoherent.
    """
    module = _load_native_module()
    evaluator = getattr(module, "evaluate", None)
    if not callable(evaluator):
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} does not expose the primitive "
            "evaluator 'evaluate'"
        )
    try:
        primitive_sets = [(effect, list(permissions)) for effect, permissions in permission_sets]
        native_response = evaluator(action_urn, primitive_sets)
    except TypeError as exc:
        # PyO3 rejects wrong primitive types/container shapes (an int
        # Action URN, a non-iterable Permission collection, an int
        # Permission text, ...) with TypeError. Normalize that into the
        # documented ValueError contract so malformed input is always a
        # parsing/boundary failure, never a policy decision.
        raise ValueError(
            f"malformed primitive input to the native {_NATIVE_MODULE_NAME!r} boundary; "
            "expected an exact Action URN 'str' and a list of "
            "(effect: 'str', permissions: list['str']) pairs"
        ) from exc
    return _validate_native_evaluation(native_response)


def native_compile_policy(permission_sets: list[tuple[str, list[str]]]) -> Any:
    """Compile already-applicable detached PermissionSets once (PR 8G).

    Experimental compiled-policy bridge: primitive data in, an opaque
    immutable native :class:`_mtmf_permission_engine.NativeCompiledPolicy`
    object out. The object exposes exactly one capability, ``evaluate``
    (one exact Action URN -> the same validated
    :class:`RustEvaluation`-compatible native 5-tuple as
    :func:`native_evaluate`), and repeated evaluation NEVER resends,
    reparses, sorts, or scans policy.

    ``permission_sets`` has the same shape as :func:`native_evaluate`:
    a list of ``(effect, permissions)`` pairs where ``effect`` is
    exactly ``"allow"`` or ``"deny"`` and ``permissions`` is a list of
    Permission matcher URN texts. Empty policy is valid and compiles to
    an object that returns ``DENY / NO_MATCH`` for every Action.

    Malformed Permission URNs, unknown effects, and wrong primitive
    types/container shapes raise :class:`ValueError` (never a policy
    decision, and never a usable policy object). The returned object is
    opaque and read-only: private Rust fields, no setters, no mutable
    map exposure, deterministic evaluation that never mutates the
    policy. There is no registry, global cache, serialization, pickling,
    or invalidation mechanism; the accepted lifetime is only construct
    -> evaluate zero or more times -> drop.

    :raises ValueError: for malformed Permission URNs, unknown
        PermissionSet effects, or wrong primitive types/container
        shapes; malformed input is never a policy DENY.
    :raises RustEngineUnavailableError: when the native module is absent.
    :raises RustEngineCapabilityError: when the native module does not
        expose the ``compile_policy`` capability or its response is not
        the documented opaque compiled object.
    """
    module = _load_native_module()
    compiler = getattr(module, "compile_policy", None)
    if not callable(compiler):
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} does not expose the primitive "
            "compiled-policy compiler 'compile_policy'"
        )
    try:
        primitive_sets = [(effect, list(permissions)) for effect, permissions in permission_sets]
        compiled = compiler(primitive_sets)
    except TypeError as exc:
        raise ValueError(
            f"malformed primitive input to the native {_NATIVE_MODULE_NAME!r} boundary; "
            "expected a list of (effect: 'str', permissions: list['str']) pairs"
        ) from exc
    if not callable(getattr(compiled, "evaluate", None)):
        raise RustEngineCapabilityError(
            f"native module {_NATIVE_MODULE_NAME!r} returned a compiled-policy "
            "object without the documented 'evaluate' capability"
        )
    return compiled
