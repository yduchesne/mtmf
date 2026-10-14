"""The synchronous, HTTP-only official MTMF client (``HttpMtmfClient``).

The client acquires an OAuth 2.0 Client Credentials *service* token,
propagates an independently obtained *end-user* access token supplied by
the consumer in a separate header, calls the frozen v1
``POST /v1/authorization/evaluate`` endpoint, strictly validates the
response against the original request, and issues one immutable,
context-bound, monotonic authorization snapshot.

It does not embed a policy evaluator, does not decode JWTs for trust, does
not follow redirects, and never retries an ambiguous authorization POST.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx

from mtmf_api.authorization import (
    SNAPSHOT_MAX_TTL,
    SNAPSHOT_SENSITIVE_MAX_TTL,
    AuthorizationBatchRequest,
    AuthorizationBatchResponse,
    ResourceTarget,
)
from mtmf_api.conformance import validate_response_for_request
from mtmf_api.errors import ApiContractValidationError, ApiErrorCode, ApiErrorResponse
from mtmf_api.json_codec import parse_error_json, parse_response_json, serialize_request
from mtmf_client.config import USER_AUTHORIZATION_HEADER, ClientConfig
from mtmf_client.credentials import ServiceTokenManager
from mtmf_client.errors import (
    ActorContextError,
    AuthorizationDenied,
    ClientClosedError,
    DependencyUnavailableError,
    RemoteAuthenticationError,
    RemoteEligibilityError,
    RemoteProtocolError,
)
from mtmf_client.observability import (
    ClientInstrumentation,
    NoopClientInstrumentation,
    SnapshotRejectionReason,
)
from mtmf_client.snapshot import (
    AuthorizationSnapshot,
    TrustedActorContext,
    _context_matches,
    _issue_snapshot,
    _owned_by,
    _Provenance,
    _snapshot_is_live,
)
from mtmf_client.snapshot import (
    is_allowed as _is_allowed,
)
from mtmf_client.snapshot import (
    require as _require,
)
from mtmf_client.transport import HttpTransport, RawResponse

__all__ = ["HttpMtmfClient"]

_EVALUATE_PATH = "/v1/authorization/evaluate"


def _utc_now() -> datetime:
    """Return the current UTC wall-clock time."""
    return datetime.now(UTC)


class HttpMtmfClient:
    """Synchronous official MTMF v1 batch-authorization HTTP client."""

    __slots__ = (
        "_closed",
        "_config",
        "_instrumentation",
        "_monotonic_clock",
        "_provenance",
        "_tokens",
        "_transport",
        "_utc_clock",
    )

    def __init__(
        self,
        config: ClientConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        monotonic_clock: Callable[[], float] = time.monotonic,
        utc_clock: Callable[[], datetime] = _utc_now,
        instrumentation: ClientInstrumentation | None = None,
    ) -> None:
        if not isinstance(config, ClientConfig):
            raise ActorContextError("HttpMtmfClient requires a ClientConfig")
        self._config = config
        self._instrumentation = instrumentation or NoopClientInstrumentation()
        self._transport = HttpTransport(
            config, transport=transport, instrumentation=self._instrumentation
        )
        self._tokens = ServiceTokenManager(
            config,
            self._transport,
            monotonic_clock=monotonic_clock,
            instrumentation=self._instrumentation,
        )
        self._monotonic_clock = monotonic_clock
        self._utc_clock = utc_clock
        self._provenance = _Provenance()
        self._closed = False

    @property
    def config(self) -> ClientConfig:
        """The immutable client configuration."""
        return self._config

    @property
    def closed(self) -> bool:
        """Whether the client has been closed."""
        return self._closed

    def __enter__(self) -> HttpMtmfClient:
        self._ensure_open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP connection pool. Idempotent."""
        if not self._closed:
            self._closed = True
            self._transport.close()

    def evaluate(
        self,
        request: AuthorizationBatchRequest,
        *,
        user_access_token: str,
        context: TrustedActorContext,
    ) -> AuthorizationSnapshot:
        """Evaluate one ordered batch and return a bound, expiring snapshot.

        :param request: The exact frozen v1 batch request.
        :param user_access_token: The consumer's already-authenticated
            end-user access token. Never decoded or refreshed here.
        :param context: The trusted local actor/session binding.
        :raises ActorContextError: when the token or context is missing or
            the request Tenant/Organization does not match the context.
        :raises ClientClosedError: when the client is closed.
        :raises ClientAuthenticationError: when no service token can be obtained.
        :raises RemoteAuthenticationError / RemoteEligibilityError:
            when the service rejects the service or actor context.
        :raises RemoteProtocolError: when the response is malformed or non-conformant.
        :raises DependencyUnavailableError: on transient remote/transport failure.
        """
        self._ensure_open()
        self._validate_context(context, request)
        if not isinstance(user_access_token, str) or not user_access_token.strip():
            raise ActorContextError("a verified end-user access token is required")
        with self._instrumentation.span_evaluate():
            service_token = self._tokens.get_token()
            body = serialize_request(request)
            response = self._post(service_token, user_access_token, body)
            if response.status_code != 200:
                raise self._map_error(response)
            parsed = self._parse_success(response, request)
            return self._build_snapshot(request, parsed, context)

    def is_allowed(
        self,
        snapshot: AuthorizationSnapshot | None,
        *,
        context: TrustedActorContext,
        action: str,
        resource: ResourceTarget,
        request_id: str | None = None,
    ) -> bool:
        """Strictly client-bound variant of the module-level :func:`is_allowed`.

        ``action`` and ``resource`` are mandatory (see the module-level
        helper). Additionally requires that ``snapshot`` was issued by *this*
        client instance. Never performs network I/O.
        """
        self._ensure_open()
        reason = self._snapshot_rejection_reason(snapshot, context)
        if reason is not None:
            self._record_snapshot_rejection(reason)
            return False
        allowed = _is_allowed(
            snapshot,
            context=context,
            action=action,
            resource=resource,
            request_id=request_id,
        )
        if not allowed:
            self._record_snapshot_rejection(SnapshotRejectionReason.DENIED)
        return allowed

    def require(
        self,
        snapshot: AuthorizationSnapshot | None,
        *,
        context: TrustedActorContext,
        action: str,
        resource: ResourceTarget,
        request_id: str | None = None,
    ) -> None:
        """Strictly client-bound variant of the module-level :func:`require`."""
        self._ensure_open()
        reason = self._snapshot_rejection_reason(snapshot, context)
        if reason is not None:
            self._record_snapshot_rejection(reason)
            raise AuthorizationDenied("the requested Action occurrence is not allowed")
        try:
            _require(
                snapshot,
                context=context,
                action=action,
                resource=resource,
                request_id=request_id,
            )
        except AuthorizationDenied:
            self._record_snapshot_rejection(SnapshotRejectionReason.DENIED)
            raise

    # -- internals ---------------------------------------------------------

    def _snapshot_rejection_reason(
        self,
        snapshot: AuthorizationSnapshot | None,
        context: TrustedActorContext,
    ) -> SnapshotRejectionReason | None:
        """Return the local rejection reason, or ``None`` when locally usable."""
        if not _owned_by(snapshot, self._provenance):
            return SnapshotRejectionReason.NOT_OWNED
        if not isinstance(snapshot, AuthorizationSnapshot):
            return SnapshotRejectionReason.NOT_OWNED
        if not _context_matches(snapshot, context):
            return SnapshotRejectionReason.CONTEXT_MISMATCH
        if not _snapshot_is_live(snapshot):
            return SnapshotRejectionReason.EXPIRED
        return None

    def _record_snapshot_rejection(self, reason: SnapshotRejectionReason) -> None:
        """Record a local PEP rejection; never let telemetry raise."""
        try:
            self._instrumentation.record_snapshot_rejection(reason=reason)
        except Exception:
            return

    def _ensure_open(self) -> None:
        if self._closed:
            raise ClientClosedError("the client is closed")

    def _validate_context(
        self,
        context: TrustedActorContext,
        request: AuthorizationBatchRequest,
    ) -> None:
        if not isinstance(context, TrustedActorContext):
            raise ActorContextError("a TrustedActorContext is required")
        if context.application_id != self._config.application_id:
            raise ActorContextError("the trusted context Application does not match the client")
        if not isinstance(request, AuthorizationBatchRequest):
            raise ActorContextError("an AuthorizationBatchRequest is required")
        if request.tenant_id != context.tenant_id:
            raise ActorContextError("the request Tenant does not match the trusted context")
        if request.organization_id != context.organization_id:
            raise ActorContextError("the request Organization does not match the trusted context")

    def _post(self, service_token: str, user_token: str, body: str) -> RawResponse:
        url = f"{self._config.base_url}{_EVALUATE_PATH}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {service_token}",
            USER_AUTHORIZATION_HEADER: f"Bearer {user_token}",
        }
        return self._transport.post_json(url, body=body, headers=headers)

    def _parse_success(
        self,
        response: RawResponse,
        request: AuthorizationBatchRequest,
    ) -> AuthorizationBatchResponse:
        if response.content_type != "application/json":
            raise RemoteProtocolError("the MTMF success response was not JSON")
        try:
            parsed = parse_response_json(response.body)
        except ApiContractValidationError as exc:
            raise RemoteProtocolError("the MTMF success response violated the v1 contract") from exc
        try:
            validate_response_for_request(request, parsed)
        except ApiContractValidationError as exc:
            raise RemoteProtocolError("the MTMF response did not conform to the request") from exc
        return parsed

    def _build_snapshot(
        self,
        request: AuthorizationBatchRequest,
        parsed: AuthorizationBatchResponse,
        context: TrustedActorContext,
    ) -> AuthorizationSnapshot:
        receipt_utc = self._utc_clock()
        receipt_monotonic = float(self._monotonic_clock())
        uncertainty = timedelta(seconds=float(self._config.clock_uncertainty_seconds))
        if parsed.issued_at > receipt_utc + uncertainty:
            raise RemoteProtocolError("the MTMF response issued_at is unreasonably in the future")
        if parsed.expires_at <= receipt_utc:
            raise RemoteProtocolError("the MTMF response is already expired")
        wall_remaining = (parsed.expires_at - receipt_utc).total_seconds()
        server_lifetime = (parsed.expires_at - parsed.issued_at).total_seconds()
        candidates = (
            max(0.0, wall_remaining - uncertainty.total_seconds()),
            max(0.0, server_lifetime - uncertainty.total_seconds()),
            float(self._config.max_snapshot_ttl_seconds),
            float(SNAPSHOT_MAX_TTL.total_seconds()),
            float(SNAPSHOT_SENSITIVE_MAX_TTL.total_seconds()),
        )
        deadline_monotonic = receipt_monotonic + min(candidates)
        return _issue_snapshot(
            request=request,
            response=parsed,
            context=context,
            issued_monotonic=receipt_monotonic,
            deadline_monotonic=deadline_monotonic,
            monotonic_clock=self._monotonic_clock,
            provenance=self._provenance,
        )

    def _map_error(self, response: RawResponse) -> Exception:
        if response.is_redirect:
            return RemoteProtocolError("the MTMF endpoint attempted a redirect")
        if response.content_type != "application/json":
            return RemoteProtocolError("the MTMF error response was not JSON")
        try:
            envelope = parse_error_json(response.body)
        except ApiContractValidationError:
            return RemoteProtocolError("the MTMF error response was malformed")
        return _exception_for_error(envelope)


def _exception_for_error(envelope: ApiErrorResponse) -> Exception:
    """Map a validated error envelope to a typed, redacted exception."""
    code = envelope.code
    if code is ApiErrorCode.UNAUTHENTICATED:
        return RemoteAuthenticationError("the MTMF service rejected the service credential")
    if code in (ApiErrorCode.UNTRUSTED_ACTOR, ApiErrorCode.INELIGIBLE_APPLICATION):
        return RemoteEligibilityError("the MTMF service rejected the actor or subscription")
    if code in (ApiErrorCode.RATE_LIMITED, ApiErrorCode.DEPENDENCY_UNAVAILABLE):
        return DependencyUnavailableError("the MTMF service is temporarily unavailable")
    if code is ApiErrorCode.INTERNAL_ERROR:
        return DependencyUnavailableError("the MTMF service reported an internal error")
    return RemoteProtocolError("the MTMF service rejected the request as invalid")
