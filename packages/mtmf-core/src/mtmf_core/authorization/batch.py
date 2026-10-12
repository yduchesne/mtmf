"""Ordered internal batch authorization seam (PR 16).

PR 16 adds an internal, private batch authorization surface that shares
one validated structural authorization context and (at most) one policy
resolution across an ordered batch of exact Action requests, while
preserving the authoritative single-Action
:class:`~mtmf_core.authorization.authorizer.Authorizer` semantics for
every ordered occurrence.

**Invariant:** for every index ``i``::

    BatchAuthorizer().authorize(batch).decisions[i]
        == Authorizer().authorize(batch.requests[i])

as a *complete* :class:`~mtmf_core.authorization.decision.AuthorizationDecision`
(effect, reason, matched specificity, matched-allow, matched-deny). Any
resolver, compilation, or native infrastructure failure fails the
**entire** batch: there is no partial result, no per-item DEFAULT, and no
automatic fallback.

Frozen internal contract:

.. code-block:: python

    AuthorizationBatch(requests: tuple[AuthorizationRequest, ...])       # 1..100
    AuthorizationBatchResult(decisions: tuple[AuthorizationDecision, ...])
    BatchAuthorizer().authorize(batch) -> AuthorizationBatchResult

Every request must share the *exact same* ``AuthorizationContext``
object (identity, not structural equality): a batch represents one
acting ``(Tenant, Principal, Identity)`` session and one resolved
applicable policy. The contract deliberately carries no request id,
caller identity UUID, Application, subscription, or public wire DTO;
PR 17 owns authentication, subscription eligibility, and mapping to the
PR 15 DTOs.

:class:`BatchAuthorizer` is pure Python and is the default batch path
(no backend/environment selector). :class:`RustBatchAuthorizer` is an
explicitly selected, experimental/non-default batch path that crosses
the private native boundary exactly once per eligible batch (policy
conversion + compile + ordered Action batch + result mapping); the Rust
evaluator never determines applicable policy and no part of the default
Python path depends on it.
"""

from __future__ import annotations

from dataclasses import dataclass

from mtmf_core.authorization.context import AuthorizationContext, AuthorizationRequest
from mtmf_core.authorization.decision import AuthorizationDecision, DenyReason
from mtmf_core.authorization.guards import (
    apply_post_policy_guards,
    target_is_permitted,
    validate_request_session,
)
from mtmf_core.authorization.policy_resolver import (
    AuthorizationPolicyResolver,
    DefaultAuthorizationPolicyResolver,
)
from mtmf_core.domain.action import Action

# Frozen PR 16 batch bound. Mirrors the native direct-batch bound.
MIN_BATCH_SIZE = 1
MAX_BATCH_SIZE = 100

__all__ = [
    "MAX_BATCH_SIZE",
    "MIN_BATCH_SIZE",
    "AuthorizationBatch",
    "AuthorizationBatchResult",
    "BatchAuthorizer",
    "InvalidAuthorizationBatchError",
    "RustBatchAuthorizer",
]


class InvalidAuthorizationBatchError(ValueError):
    """Raised when an :class:`AuthorizationBatch` violates the frozen contract.

    This is a caller/programming error detected *before* any policy
    resolution or native call: an empty or oversized batch, a mutable or
    wrong-typed element, or requests that do not share the exact same
    ``AuthorizationContext`` object.
    """


@dataclass(frozen=True, slots=True)
class AuthorizationBatch:
    """An immutable ordered batch of 1-100 requests sharing one context.

    Construction validates the frozen contract immediately, so an
    invalid batch can never reach policy resolution or a native call.
    All requests must share the exact same ``AuthorizationContext``
    object; structural equality is insufficient for mutable aggregates.
    """

    requests: tuple[AuthorizationRequest, ...]

    def __post_init__(self) -> None:
        _validate_batch(self)


@dataclass(frozen=True, slots=True)
class AuthorizationBatchResult:
    """The ordered complete decisions, one per request, positionally correlated."""

    decisions: tuple[AuthorizationDecision, ...]


def _validate_batch(batch: AuthorizationBatch) -> None:
    """Validate the frozen batch contract before any evaluation."""
    requests = batch.requests
    if type(requests) is not tuple:
        raise InvalidAuthorizationBatchError(
            "AuthorizationBatch.requests must be an immutable tuple"
        )
    size = len(requests)
    if size < MIN_BATCH_SIZE or size > MAX_BATCH_SIZE:
        raise InvalidAuthorizationBatchError(
            f"batch size {size} is outside the supported range [{MIN_BATCH_SIZE}, {MAX_BATCH_SIZE}]"
        )
    first = requests[0]
    if not isinstance(first, AuthorizationRequest):
        raise InvalidAuthorizationBatchError(
            "every batch element must be a genuine AuthorizationRequest"
        )
    for index, request in enumerate(requests):
        if not isinstance(request, AuthorizationRequest):
            raise InvalidAuthorizationBatchError(
                f"batch element {index} must be a genuine AuthorizationRequest"
            )
        if request.context is not first.context:
            raise InvalidAuthorizationBatchError(
                "every batch request must share the exact same AuthorizationContext "
                "object (identity, not structural equality)"
            )


class BatchAuthorizer:
    """The internal ordered batch authorization component (pure Python, default).

    Performs no persistence, no authentication, and no subscription
    check. It depends only on the narrow
    :class:`~mtmf_core.authorization.policy_resolver.AuthorizationPolicyResolver`
    seam and applies the exact same extracted guards as the single-Action
    :class:`~mtmf_core.authorization.authorizer.Authorizer`.

    Batch algorithm (order is security-significant):

    1. validate the batch shape and shared context (construction-time);
    2. validate the shared session **once**; an invalid session produces
       an ordered ``DENY/INVALID_CONTEXT`` for every item with zero
       resolver/native calls;
    3. per-item target-Tenant/management precheck in original position;
       an invalid target produces ``DENY/NO_MANAGEMENT_SCOPE``;
    4. if at least one item survives, resolve the applicable policy
       **once**; if *all* items were pre-denied, return without resolving;
    5. evaluate the surviving ordered Actions through the resolved policy
       (or one native batch call for :class:`RustBatchAuthorizer`);
    6. apply the per-item post-policy guards (unsupported constraint,
       then strict dominance) to each policy ALLOW; a policy DENY is
       final;
    7. assemble the ordered complete tuple only after every evaluation
       succeeds.

    Any resolver/compilation/native exception propagates and fails the
    whole batch, even if some items were already deterministically
    DENY; there is no partial result and no fallback.
    """

    def __init__(
        self,
        policy_resolver: AuthorizationPolicyResolver | None = None,
    ) -> None:
        """Create a batch authorizer using ``policy_resolver`` (default:
        :class:`DefaultAuthorizationPolicyResolver`)."""
        self._policy_resolver = (
            policy_resolver if policy_resolver is not None else DefaultAuthorizationPolicyResolver()
        )

    def authorize(self, batch: AuthorizationBatch) -> AuthorizationBatchResult:
        """Return the ordered complete decisions for ``batch``.

        :raises InvalidAuthorizationBatchError: for an invalid batch
            (raised at construction).
        :raises Exception: resolver/compilation/evaluation failures
            propagate and fail the entire batch; they are never converted
            into a semantic DENY, a partial result, or an ALLOW.
        """
        requests = batch.requests

        invalid_session = validate_request_session(requests[0])
        if invalid_session is not None:
            # One shared session check; every item fails closed and no
            # resolver/native call happens.
            return AuthorizationBatchResult(tuple(invalid_session for _ in requests))

        pre_denied: dict[int, AuthorizationDecision] = {}
        surviving_positions: list[int] = []
        surviving_actions: list[Action] = []
        for index, request in enumerate(requests):
            if target_is_permitted(request):
                surviving_positions.append(index)
                surviving_actions.append(request.action)
            else:
                pre_denied[index] = AuthorizationDecision.deny(DenyReason.NO_MANAGEMENT_SCOPE)

        evaluated: dict[int, AuthorizationDecision] = {}
        if surviving_actions:
            # Resolve applicable policy once (Python) or cross the native
            # boundary once (Rust); any exception here fails the whole
            # batch before a single decision is assembled.
            decisions = self._evaluate_surviving(requests[0].context, tuple(surviving_actions))
            for index, decision in zip(surviving_positions, decisions, strict=True):
                evaluated[index] = apply_post_policy_guards(requests[index], decision)

        ordered = tuple(
            pre_denied[index] if index in pre_denied else evaluated[index]
            for index in range(len(requests))
        )
        return AuthorizationBatchResult(ordered)

    def _evaluate_surviving(
        self,
        context: AuthorizationContext,
        actions: tuple[Action, ...],
    ) -> tuple[AuthorizationDecision, ...]:
        """Evaluate the surviving ordered Actions against one resolved policy.

        The default pure-Python implementation resolves (compiles)
        ``context.applicable_roles`` exactly once and evaluates each
        Action against that single policy. Subclasses may replace the
        evaluation mechanism (for example a single native batch crossing)
        without changing the guard ordering, session/target handling, or
        fail-closed semantics.
        """
        policy = self._policy_resolver.resolve(context)
        return tuple(policy.evaluate(action) for action in actions)


class RustBatchAuthorizer(BatchAuthorizer):
    """Explicit, non-default batch path crossing the native boundary once.

    Evaluates the shared, already-resolved applicable policy through the
    private native indexed compiled-policy kernel: the already-applicable
    ``context.applicable_roles`` are ownership-validated and flattened to
    detached primitives, then the whole surviving ordered Action batch is
    evaluated in exactly one PyO3 call
    (:func:`mtmf_core.authorization.rust_engine.native_batch_evaluate`).

    This class is **never** selected implicitly and is **not** the
    default; :class:`BatchAuthorizer` remains the pure-Python default and
    the single-Action default :class:`Authorizer` is unchanged. The
    native path never determines applicable policy, never receives
    session/Tenant/membership/assignment state, and has no Python
    fallback: any native unavailability, capability, parsing, or
    malformed/incoherent response is an infrastructure failure that fails
    the whole batch.
    """

    def __init__(self) -> None:
        """Create the explicit native batch authorizer (no resolver injection).

        The native path does not use an ``AuthorizationPolicyResolver``:
        it flattens ``context.applicable_roles`` to detached primitives
        and compiles them natively. Accepting an unused resolver here
        would be misleading, so this constructor takes no arguments.
        """
        super().__init__()

    def _evaluate_surviving(
        self,
        context: AuthorizationContext,
        actions: tuple[Action, ...],
    ) -> tuple[AuthorizationDecision, ...]:
        from mtmf_core.authorization.rust_engine import (
            RustEngineCapabilityError,
            RustEngineUnavailableError,
            native_batch_evaluate,
        )
        from mtmf_core.authorization.rust_permission_evaluator import (
            PermissionEvaluationInfrastructureError,
            _map_native_evaluation,
            flatten_roles_to_primitive_sets,
        )

        # Structural ownership validation happens before any native call
        # and raises PermissionEvaluationError (corrupt domain policy),
        # never an infrastructure error and never a decision.
        primitive_sets = flatten_roles_to_primitive_sets(context.applicable_roles)
        action_urns = [action.urn.value for action in actions]
        try:
            evaluations = native_batch_evaluate(primitive_sets, action_urns)
        except (
            RustEngineUnavailableError,
            RustEngineCapabilityError,
            ValueError,
            TypeError,
        ) as exc:
            raise PermissionEvaluationInfrastructureError(
                "Rust batch permission evaluation failed; the protected batch must fail "
                "closed because no ALLOW decision can be produced"
            ) from exc
        return tuple(_map_native_evaluation(evaluation) for evaluation in evaluations)
