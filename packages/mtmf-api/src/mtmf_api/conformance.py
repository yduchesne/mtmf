"""Pure request/response correlation checks for the v1 batch contract.

This module proves that a response *structurally corresponds* to the
request that produced it: exact length, unique and input-ordered
``request_id`` correlation, and Tenant/Organization equality. It performs
no policy evaluation, resolves no policy, and has no side effects, so it
can never mint an ``ALLOW``. PR 18 reuses it when binding a snapshot to
the original immutable request and trusted context.
"""

from __future__ import annotations

from mtmf_api.authorization import AuthorizationBatchRequest, AuthorizationBatchResponse
from mtmf_api.errors import ApiContractValidationError


class ResponseConformanceError(ApiContractValidationError):
    """The response does not conform to its originating request."""


def validate_response_for_request(
    request: AuthorizationBatchRequest,
    response: AuthorizationBatchResponse,
) -> None:
    """Validate exact structural conformance of ``response`` to ``request``.

    Rejects a response that is missing, reordering, duplicating, or adding
    a decision occurrence, or whose Tenant/Organization selector differs
    from the request. Note that ``request_id`` correlation alone is *not*
    authority: PR 18 must still bind the snapshot to the original
    immutable request and the verified authenticated context.

    :raises ResponseConformanceError: when the response does not conform.
    """
    if response.tenant_id != request.tenant_id:
        raise ResponseConformanceError("response tenant_id does not match the request")
    if response.organization_id != request.organization_id:
        raise ResponseConformanceError("response organization_id does not match the request")
    if len(response.decisions) != len(request.actions):
        raise ResponseConformanceError(
            "response decision count does not match the request action count"
        )
    response_ids = [decision.request_id for decision in response.decisions]
    if len(set(response_ids)) != len(response_ids):
        raise ResponseConformanceError("response decision request_id values must be unique")
    request_ids = [action.request_id for action in request.actions]
    if response_ids != request_ids:
        raise ResponseConformanceError(
            "response decisions must correlate one-to-one with request order"
        )
