"""Reference application HTTP boundary and Policy Enforcement Point.

Security ordering for ``GET /v1/documents/{document_id}`` (never reordered to
broaden access):

1. cryptographically verify the inbound end-user access token;
2. resolve the server-owned subject-to-Tenant fixture binding and build the
   request-local trusted actor context (no caller-supplied Tenant/actor);
3. parse the candidate document id, then load it with a Tenant-scoped SQL
   predicate from the app's own store (generic 404 when absent);
4. derive the ``ResourceTarget`` from the actually loaded row;
5. evaluate exactly one exact Action/resource occurrence through the official
   ``mtmf-client`` in a bounded worker;
6. call ``require`` with the exact loaded-row target, and only then serialize
   the body.

No document body is written before ``require`` succeeds. Authentication is not
policy, and a missing resource is never evidence of a policy DENY.
"""

from __future__ import annotations

import asyncio
import functools
import logging
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mtmf_api.authorization import (
    ActionRequest,
    AuthorizationBatchRequest,
    ResourceKind,
    ResourceTarget,
)
from mtmf_client import (
    ActorContextError,
    AuthorizationDenied,
    AuthorizationSnapshot,
    ClientAuthenticationError,
    ClientClosedError,
    ClientConfig,
    DependencyUnavailableError,
    HttpMtmfClient,
    RemoteAuthenticationError,
    RemoteEligibilityError,
    RemoteProtocolError,
    TrustedActorContext,
)
from mtmf_reference_app.auth import (
    AuthenticationError,
    SessionKeyDeriver,
    UserTokenVerifier,
)
from mtmf_reference_app.config import ReferenceAppConfig
from mtmf_reference_app.models import Document
from mtmf_reference_app.store import DocumentStore, DocumentStoreError

__all__ = [
    "BATCH_ACCESS_MAX_OPERATIONS",
    "BATCH_ACCESS_MIN_OPERATIONS",
    "BATCH_READ_MAX_IDS",
    "BATCH_READ_MIN_IDS",
    "DOCUMENT_READ_ACTION",
    "METADATA_ACTION",
    "METADATA_REQUEST_ID",
    "READ_REQUEST_ID",
    "AccessResult",
    "AuthorizationClient",
    "CreateDependencies",
    "DocumentReader",
    "MetadataResponse",
    "build_client_config",
    "create_app",
    "main",
]

#: The single exact Action this reference PEP evaluates. It is registered and
#: granted to the fixture user's ordinary Tenant-scoped Role by the privileged
#: one-shot initializer; it is never a wildcard or an unrelated management Action.
DOCUMENT_READ_ACTION = "urn:mtmf:iam:actions:system:document:read-object"

#: The owner-approved genuine second operation: an exact metadata-only read.
#: It is registered and granted to the fixture users' Tenant-scoped metadata
#: Role by the PR 20B privileged fixture; it is never a wildcard.
METADATA_ACTION = "urn:mtmf:iam:actions:system:document:read-metadata"

#: Stable correlation discriminator for the one occurrence in every batch. The
#: batch route appends the zero-based occurrence index (``document-read-0``).
READ_REQUEST_ID = "document-read"

#: Bounded multi-document batch. The fixed route is deliberately small so a
#: single verified actor cannot amplify one request into an unbounded number of
#: MTMF evaluations.
BATCH_READ_MIN_IDS = 1
BATCH_READ_MAX_IDS = 16

#: Bounded mixed-operation batch (metadata and/or content).
BATCH_ACCESS_MIN_OPERATIONS = 1
BATCH_ACCESS_MAX_OPERATIONS = 16

#: Stable correlation discriminator for the metadata-only occurrence.
METADATA_REQUEST_ID = "document-metadata"

#: Stable correlation discriminator prefix for the mixed-operation batch.
ACCESS_REQUEST_ID = "document-access"

#: The closed operation enum accepted by the mixed-operation batch route. The
#: caller's string never selects policy directly: it maps to a server-defined
#: exact Action and a fixed serializer.
_OPERATION_ACTIONS: dict[str, str] = {
    "metadata": METADATA_ACTION,
    "content": DOCUMENT_READ_ACTION,
}

#: Bounded concurrent MTMF evaluations. The worker never unboundedly multiplies
#: threads under load.
_MAX_IN_FLIGHT = 32

#: Bounded wall-clock budget for one outbound MTMF evaluation.
_EVALUATE_TIMEOUT_SECONDS = 15.0

#: Bounded wall-clock budget for one end-user token verification (includes a
#: possible JWKS fetch).
_VERIFY_TIMEOUT_SECONDS = 10.0

#: Non-secret structured event log. It records only the decision outcome and
#: the application document identifier; it never records tokens, claims,
#: headers, or document content.
logger = logging.getLogger("mtmf_reference_app")


class AuthorizationClient(Protocol):
    """The narrow official-client seam the PEP depends on."""

    def evaluate(
        self,
        request: AuthorizationBatchRequest,
        *,
        user_access_token: str,
        context: TrustedActorContext,
    ) -> AuthorizationSnapshot:
        """Evaluate one ordered batch through MTMF."""
        ...

    def require(
        self,
        snapshot: AuthorizationSnapshot | None,
        *,
        context: TrustedActorContext,
        action: str,
        resource: ResourceTarget,
        request_id: str | None = None,
    ) -> None:
        """Enforce an exact bound occurrence, raising on any non-ALLOW."""
        ...


class _ReadError(Exception):
    """Base for a safe, already-classified document read failure."""

    status_code: int
    message: str


class _UnauthenticatedError(_ReadError):
    status_code = 401
    message = "authentication required"


class _AccessDeniedError(_ReadError):
    status_code = 403
    message = "access denied"


class _NotFoundError(_ReadError):
    status_code = 404
    message = "document not found"


class _DependencyFailureError(_ReadError):
    status_code = 503
    message = "authorization dependency unavailable"


class BoundedWorker:
    """Run blocking work off the event loop under a concurrency/time bound."""

    __slots__ = ("_semaphore", "_timeout")

    def __init__(self, *, limit: int = _MAX_IN_FLIGHT, timeout: float) -> None:
        if limit < 1:
            raise ValueError("limit must be positive")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self._semaphore = asyncio.Semaphore(limit)
        self._timeout = timeout

    async def run(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run ``func`` in a thread, bounded by the semaphore and a deadline.

        A worker slot represents one submitted blocking operation **until its
        thread actually terminates**, not until the awaiting request stops
        waiting. A timeout or cancellation releases the caller, but the slot
        stays occupied until the underlying executor future completes, so
        repeated slow operations cannot exceed the configured outstanding-work
        bound. Neither a timeout nor a cancellation ever produces a response
        body.
        """
        # The acquire is cancellable: a cancellation before acquisition must
        # not release a slot that was never taken.
        await self._semaphore.acquire()
        loop = asyncio.get_running_loop()
        try:
            future = loop.run_in_executor(None, functools.partial(self._invoke, func, args, kwargs))
        except BaseException:
            self._semaphore.release()
            raise

        def on_done(done: asyncio.Future[Any]) -> None:
            # Retrieve a late exception so a timed-out caller cannot leave an
            # unhandled-future-exception warning behind. The text is never
            # logged and calling ``exception()`` does not consume it for a
            # caller still awaiting the future.
            try:
                if not done.cancelled():
                    done.exception()
            finally:
                self._semaphore.release()

        future.add_done_callback(on_done)
        # Shield the executor future: wait_for cancels only the shield on
        # timeout/cancellation, never the submitted operation, so the callback
        # above remains the single release owner when the thread finishes.
        outcome = await asyncio.wait_for(asyncio.shield(future), timeout=self._timeout)
        succeeded, payload = outcome
        if succeeded:
            return payload
        raise payload

    @staticmethod
    def _invoke(
        func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
    ) -> tuple[bool, Any]:
        """Run ``func`` and capture an ordinary failure as a value.

        An abandoned (timed-out/cancelled) operation must not leave an
        unretrieved executor-future exception: Python 3.14's ``asyncio.shield``
        logs such a late exception as ``... exception in shielded future`` even
        after a completion callback retrieves it. Returning ``(False, exc)``
        keeps the caller-visible behavior (the same exception is re-raised while
        the caller still awaits) without a late-exception log. Only ordinary
        ``Exception`` failures are captured; system-exiting ``BaseException``
        values still propagate through the executor future unchanged.
        """
        try:
            return True, func(*args, **kwargs)
        except Exception as exc:
            return False, exc


@dataclass(frozen=True, slots=True)
class DocumentResponse:
    """The content disclosure payload returned only after a verified ALLOW."""

    document_id: str
    title: str
    body: str


@dataclass(frozen=True, slots=True)
class MetadataResponse:
    """The metadata-only disclosure payload: ``id`` and ``title``, never body."""

    document_id: str
    title: str


@dataclass(frozen=True, slots=True)
class AccessResult:
    """One ordered mixed-operation result before route serialization.

    ``body`` is populated only for the closed ``content`` operation and is
    ``None`` for ``metadata``; the route never serializes a ``body`` key for a
    metadata result.
    """

    operation: str
    document_id: str
    title: str
    body: str | None


class DocumentReader:
    """The ordered, fail-closed document read vertical slice."""

    __slots__ = (
        "_client",
        "_config",
        "_evaluate_worker",
        "_session_keys",
        "_store",
        "_token_verifier",
        "_verify_worker",
    )

    def __init__(
        self,
        *,
        config: ReferenceAppConfig,
        store: DocumentStore,
        token_verifier: UserTokenVerifier,
        session_keys: SessionKeyDeriver,
        client: AuthorizationClient,
        evaluate_worker: BoundedWorker | None = None,
        verify_worker: BoundedWorker | None = None,
    ) -> None:
        self._config = config
        self._store = store
        self._token_verifier = token_verifier
        self._session_keys = session_keys
        self._client = client
        self._evaluate_worker = evaluate_worker or BoundedWorker(
            limit=_MAX_IN_FLIGHT, timeout=_EVALUATE_TIMEOUT_SECONDS
        )
        self._verify_worker = verify_worker or BoundedWorker(
            limit=_MAX_IN_FLIGHT, timeout=_VERIFY_TIMEOUT_SECONDS
        )

    async def read(self, *, token: str, document_id: str) -> DocumentResponse:
        """Return the document only after all four disclosure conditions hold.

        :raises _UnauthenticatedError: on any inbound authentication failure.
        :raises _AccessDeniedError: on an unknown subject or an MTMF policy DENY.
        :raises _NotFoundError: for a malformed/absent/cross-Tenant document.
        :raises _DependencyFailureError: on a local or remote dependency failure.
        """
        verified = await self._verify(token)
        binding = self._config.fixture_mapping.binding_for(verified.subject)
        if binding is None:
            logger.info("event=subject_not_allowlisted")
            raise _AccessDeniedError()
        tenant_id = binding.tenant_id
        canonical_document_id = _canonical_document_id(document_id)
        if canonical_document_id is None:
            logger.info("event=document_id_malformed")
            raise _NotFoundError()
        document = await self._evaluate_worker.run(
            self._store.load, str(tenant_id), canonical_document_id
        )
        if document is None:
            logger.info("event=document_not_found")
            raise _NotFoundError()
        resource = ResourceTarget(
            kind=ResourceKind.APPLICATION_OWNED,
            resource_type="document",
            resource_id=document.document_id,
        )
        context = self._trusted_context(verified, token, tenant_id)
        batch = AuthorizationBatchRequest(
            tenant_id=tenant_id,
            organization_id=None,
            actions=(
                ActionRequest(
                    request_id=READ_REQUEST_ID,
                    action=DOCUMENT_READ_ACTION,
                    resource=resource,
                ),
            ),
        )
        try:
            logger.info("event=mtmf_evaluate document=%s", document.document_id)
            snapshot = await self._evaluate_worker.run(
                self._client.evaluate,
                batch,
                user_access_token=token,
                context=context,
            )
            self._client.require(
                snapshot,
                context=context,
                action=DOCUMENT_READ_ACTION,
                resource=resource,
                request_id=READ_REQUEST_ID,
            )
        except AuthorizationDenied as exc:
            logger.info("event=access_denied document=%s", document.document_id)
            raise _AccessDeniedError() from exc
        except ActorContextError as exc:
            raise _UnauthenticatedError() from exc
        except RemoteAuthenticationError as exc:
            raise _UnauthenticatedError() from exc
        except RemoteEligibilityError as exc:
            logger.info("event=access_denied document=%s", document.document_id)
            raise _AccessDeniedError() from exc
        except (
            ClientAuthenticationError,
            DependencyUnavailableError,
            RemoteProtocolError,
            ClientClosedError,
        ) as exc:
            raise _DependencyFailureError() from exc
        except DocumentStoreError as exc:
            raise _DependencyFailureError() from exc
        logger.info("event=document_allowed document=%s", document.document_id)
        return DocumentResponse(
            document_id=document.document_id,
            title=document.title,
            body=document.body,
        )

    async def read_batch(
        self, *, token: str, document_ids: tuple[str, ...]
    ) -> list[DocumentResponse]:
        """Return an ordered document batch with all-or-nothing disclosure.

        The trusted context is built exactly once from the independently
        verified end-user token and the server-owned subject mapping. Every
        requested document is resolved against the app's own Tenant-scoped
        store **before** any authorization is requested; if any row is absent
        or belongs to another Tenant the whole request is a generic 404 with no
        MTMF evaluation. Exactly one ordered batch with one occurrence per
        loaded row is evaluated through the official client, then ``require`` is
        called for every occurrence in input order before any body is
        serialized. A single non-ALLOW occurrence denies the whole request and
        discloses zero bodies.

        :raises _UnauthenticatedError: on any inbound authentication failure.
        :raises _AccessDeniedError: on an unknown subject or an MTMF policy DENY.
        :raises _NotFoundError: for any malformed/absent/cross-Tenant document.
        :raises _DependencyFailureError: on a local or remote dependency failure.
        """
        if not BATCH_READ_MIN_IDS <= len(document_ids) <= BATCH_READ_MAX_IDS:
            raise ValueError("document_ids is outside the bounded batch size")
        verified = await self._verify(token)
        binding = self._config.fixture_mapping.binding_for(verified.subject)
        if binding is None:
            logger.info("event=subject_not_allowlisted")
            raise _AccessDeniedError()
        tenant_id = binding.tenant_id
        documents: list[Document] = []
        for document_id in document_ids:
            document = await self._evaluate_worker.run(
                self._store.load, str(tenant_id), document_id
            )
            if document is None:
                logger.info("event=document_not_found")
                raise _NotFoundError()
            documents.append(document)
        occurrences = tuple(
            ActionRequest(
                request_id=f"{READ_REQUEST_ID}-{index}",
                action=DOCUMENT_READ_ACTION,
                resource=ResourceTarget(
                    kind=ResourceKind.APPLICATION_OWNED,
                    resource_type="document",
                    resource_id=document.document_id,
                ),
            )
            for index, document in enumerate(documents)
        )
        context = self._trusted_context(verified, token, tenant_id)
        batch = AuthorizationBatchRequest(
            tenant_id=tenant_id,
            organization_id=None,
            actions=occurrences,
        )
        try:
            logger.info("event=mtmf_evaluate documents=%d", len(batch.actions))
            snapshot = await self._evaluate_worker.run(
                self._client.evaluate,
                batch,
                user_access_token=token,
                context=context,
            )
            for occurrence in occurrences:
                self._client.require(
                    snapshot,
                    context=context,
                    action=occurrence.action,
                    resource=occurrence.resource,
                    request_id=occurrence.request_id,
                )
        except AuthorizationDenied as exc:
            logger.info("event=access_denied documents=%d", len(documents))
            raise _AccessDeniedError() from exc
        except ActorContextError as exc:
            raise _UnauthenticatedError() from exc
        except RemoteAuthenticationError as exc:
            raise _UnauthenticatedError() from exc
        except RemoteEligibilityError as exc:
            logger.info("event=access_denied documents=%d", len(documents))
            raise _AccessDeniedError() from exc
        except (
            ClientAuthenticationError,
            DependencyUnavailableError,
            RemoteProtocolError,
            ClientClosedError,
        ) as exc:
            raise _DependencyFailureError() from exc
        except DocumentStoreError as exc:
            raise _DependencyFailureError() from exc
        logger.info("event=documents_allowed documents=%d", len(documents))
        return [
            DocumentResponse(
                document_id=document.document_id,
                title=document.title,
                body=document.body,
            )
            for document in documents
        ]

    async def read_metadata(self, *, token: str, document_id: str) -> MetadataResponse:
        """Return ``id`` and ``title`` only, after a verified metadata ALLOW.

        Follows the existing read ordering with the exact metadata Action. The
        response never carries a ``body``. A content-read grant alone does not
        authorize this operation.

        :raises _UnauthenticatedError: on any inbound authentication failure.
        :raises _AccessDeniedError: on an unknown subject or an MTMF policy DENY.
        :raises _NotFoundError: for a malformed/absent/cross-Tenant document.
        :raises _DependencyFailureError: on a local or remote dependency failure.
        """
        verified = await self._verify(token)
        binding = self._config.fixture_mapping.binding_for(verified.subject)
        if binding is None:
            logger.info("event=subject_not_allowlisted")
            raise _AccessDeniedError()
        tenant_id = binding.tenant_id
        canonical_document_id = _canonical_document_id(document_id)
        if canonical_document_id is None:
            logger.info("event=document_id_malformed")
            raise _NotFoundError()
        document = await self._evaluate_worker.run(
            self._store.load, str(tenant_id), canonical_document_id
        )
        if document is None:
            logger.info("event=document_not_found")
            raise _NotFoundError()
        resource = ResourceTarget(
            kind=ResourceKind.APPLICATION_OWNED,
            resource_type="document",
            resource_id=document.document_id,
        )
        context = self._trusted_context(verified, token, tenant_id)
        batch = AuthorizationBatchRequest(
            tenant_id=tenant_id,
            organization_id=None,
            actions=(
                ActionRequest(
                    request_id=METADATA_REQUEST_ID,
                    action=METADATA_ACTION,
                    resource=resource,
                ),
            ),
        )
        await self._evaluate_and_require(batch, token=token, context=context)
        logger.info("event=document_metadata_allowed document=%s", document.document_id)
        return MetadataResponse(document_id=document.document_id, title=document.title)

    async def read_access_batch(
        self, *, token: str, operations: tuple[tuple[str, str], ...]
    ) -> list[AccessResult]:
        """Return ordered mixed-operation results with all-or-nothing disclosure.

        Each input operation is a ``(canonical_document_id, operation)`` pair
        whose operation is the closed server enum ``metadata``/``content``. Every
        distinct document is resolved against the app's Tenant-scoped store
        before any authorization is requested; any absent/cross-Tenant row is a
        generic 404 with no MTMF call. Exactly one ordered MTMF batch is
        evaluated, ``require`` is called for every occurrence in input order,
        and only then are results assembled. A single non-ALLOW occurrence
        denies the whole request with zero results.

        :raises _UnauthenticatedError: on any inbound authentication failure.
        :raises _AccessDeniedError: on an unknown subject or an MTMF policy DENY.
        :raises _NotFoundError: for any malformed/absent/cross-Tenant document.
        :raises _DependencyFailureError: on a local or remote dependency failure.
        """
        if not BATCH_ACCESS_MIN_OPERATIONS <= len(operations) <= BATCH_ACCESS_MAX_OPERATIONS:
            raise ValueError("operations is outside the bounded access batch size")
        if any(operation not in _OPERATION_ACTIONS for _document, operation in operations):
            raise ValueError("operation is outside the closed server enum")
        verified = await self._verify(token)
        binding = self._config.fixture_mapping.binding_for(verified.subject)
        if binding is None:
            logger.info("event=subject_not_allowlisted")
            raise _AccessDeniedError()
        tenant_id = binding.tenant_id
        documents: dict[str, Document] = {}
        for document_id, _operation in operations:
            if document_id in documents:
                continue
            document = await self._evaluate_worker.run(
                self._store.load, str(tenant_id), document_id
            )
            if document is None:
                logger.info("event=document_not_found")
                raise _NotFoundError()
            documents[document_id] = document
        occurrences = tuple(
            ActionRequest(
                request_id=f"{ACCESS_REQUEST_ID}-{index}",
                action=_OPERATION_ACTIONS[operation],
                resource=ResourceTarget(
                    kind=ResourceKind.APPLICATION_OWNED,
                    resource_type="document",
                    resource_id=documents[document_id].document_id,
                ),
            )
            for index, (document_id, operation) in enumerate(operations)
        )
        context = self._trusted_context(verified, token, tenant_id)
        batch = AuthorizationBatchRequest(
            tenant_id=tenant_id,
            organization_id=None,
            actions=occurrences,
        )
        await self._evaluate_and_require(batch, token=token, context=context)
        logger.info("event=document_access_allowed operations=%d", len(occurrences))
        return [
            AccessResult(
                operation=operation,
                document_id=documents[document_id].document_id,
                title=documents[document_id].title,
                body=documents[document_id].body if operation == "content" else None,
            )
            for document_id, operation in operations
        ]

    async def _evaluate_and_require(
        self,
        batch: AuthorizationBatchRequest,
        *,
        token: str,
        context: TrustedActorContext,
    ) -> None:
        """Evaluate one batch and enforce every ordered occurrence, or raise.

        No content/metadata is serialized by the caller until this returns.
        The exception mapping is the same fail-closed classification used by
        the content vertical slice.
        """
        try:
            logger.info("event=mtmf_evaluate occurrences=%d", len(batch.actions))
            snapshot = await self._evaluate_worker.run(
                self._client.evaluate,
                batch,
                user_access_token=token,
                context=context,
            )
            for occurrence in batch.actions:
                self._client.require(
                    snapshot,
                    context=context,
                    action=occurrence.action,
                    resource=occurrence.resource,
                    request_id=occurrence.request_id,
                )
        except AuthorizationDenied as exc:
            logger.info("event=access_denied occurrences=%d", len(batch.actions))
            raise _AccessDeniedError() from exc
        except (ActorContextError, RemoteAuthenticationError) as exc:
            raise _UnauthenticatedError() from exc
        except RemoteEligibilityError as exc:
            logger.info("event=access_denied occurrences=%d", len(batch.actions))
            raise _AccessDeniedError() from exc
        except (
            ClientAuthenticationError,
            DependencyUnavailableError,
            RemoteProtocolError,
            ClientClosedError,
        ) as exc:
            raise _DependencyFailureError() from exc
        except DocumentStoreError as exc:
            raise _DependencyFailureError() from exc

    def _trusted_context(self, verified: Any, token: str, tenant_id: UUID) -> TrustedActorContext:
        """Build the request-local trusted actor context for a verified user."""
        return TrustedActorContext(
            actor_key=f"{verified.issuer}|{verified.subject}",
            session_key=self._session_keys.derive(token),
            tenant_id=tenant_id,
            application_id=self._config.application_id,
        )

    async def _verify(self, token: str) -> Any:
        try:
            return await self._verify_worker.run(self._token_verifier.verify, token)
        except AuthenticationError as exc:
            logger.info("event=auth_rejected")
            raise _UnauthenticatedError() from exc
        except Exception as exc:  # JWKS/transport or unexpected verifier fault: fail closed
            logger.info("event=verifier_unavailable")
            raise _DependencyFailureError() from exc

    def ready(self) -> bool:
        """Return whether local configuration and store are usable."""
        return self._store.ready()


def _canonical_document_id(value: str) -> str | None:
    """Return the canonical UUID text for ``value`` or ``None`` when invalid."""
    try:
        return str(UUID(value))
    except ValueError, AttributeError, TypeError:
        return None


async def _parse_batch_body(request: Request) -> tuple[str, ...] | None:
    """Parse and strictly validate a batch-read body or return ``None``.

    The accepted shape is exactly ``{"document_ids": [<canonical UUID>, ...]}``:
    a JSON object with no additional keys, a list of 1..``BATCH_READ_MAX_IDS``
    unique canonical UUID strings in canonical lowercase-hyphenated form. Any
    duplicate, malformed, out-of-range, or unknown-field input returns ``None``
    and must be rejected with 400 *before* any MTMF evaluation. The route, the
    Tenant, and the Application are never accepted from caller input.
    """
    try:
        payload = await request.json()
    except Exception:
        return None
    if not isinstance(payload, dict) or set(payload) != {"document_ids"}:
        return None
    raw_ids = payload["document_ids"]
    if not isinstance(raw_ids, list) or not (
        BATCH_READ_MIN_IDS <= len(raw_ids) <= BATCH_READ_MAX_IDS
    ):
        return None
    canonical_ids: list[str] = []
    seen: set[str] = set()
    for value in raw_ids:
        if not isinstance(value, str):
            return None
        canonical = _canonical_document_id(value)
        if canonical is None or canonical != value:
            return None
        if canonical in seen:
            return None
        seen.add(canonical)
        canonical_ids.append(canonical)
    return tuple(canonical_ids)


async def _parse_batch_access_body(
    request: Request,
) -> tuple[tuple[str, str], ...] | None:
    """Parse and strictly validate a mixed-operation access body or return ``None``.

    Accepted shape is exactly
    ``{"operations": [{"document_id": <canonical UUID>,
    "operation": "metadata"|"content"}, ...]}`` with 1..16 entries, no unknown
    keys, and no duplicate ``(document_id, operation)`` pair. The same document
    id with different operations is legal. Any malformed, duplicated,
    out-of-range, or unknown-field input returns ``None`` and must be rejected
    with 400 *before* any MTMF evaluation. The operation string is a closed enum
    mapped server-side to an exact Action; it never selects policy by itself.
    """
    try:
        payload = await request.json()
    except Exception:
        return None
    if not isinstance(payload, dict) or set(payload) != {"operations"}:
        return None
    raw_operations = payload["operations"]
    if not isinstance(raw_operations, list) or not (
        BATCH_ACCESS_MIN_OPERATIONS <= len(raw_operations) <= BATCH_ACCESS_MAX_OPERATIONS
    ):
        return None
    operations: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw_operations:
        if not isinstance(item, dict) or set(item) != {"document_id", "operation"}:
            return None
        document_value = item["document_id"]
        operation = item["operation"]
        if not isinstance(document_value, str) or not isinstance(operation, str):
            return None
        canonical = _canonical_document_id(document_value)
        if canonical is None or canonical != document_value:
            return None
        if operation not in _OPERATION_ACTIONS:
            return None
        pair = (canonical, operation)
        if pair in seen:
            return None
        seen.add(pair)
        operations.append(pair)
    return tuple(operations)


def _extract_bearer(header: str | None) -> str | None:
    """Return the bearer token from an ``Authorization`` header or ``None``."""
    if not header:
        return None
    scheme, separator, credentials = header.partition(" ")
    if not separator or scheme.lower() != "bearer":
        return None
    token = credentials.strip()
    return token or None


def _error_response(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": message},
        headers={"Cache-Control": "no-store"},
    )


def build_client_config(config: ReferenceAppConfig) -> ClientConfig:
    """Construct the official client configuration from validated app config."""
    return ClientConfig(
        base_url=config.mtmf_base_url,
        token_endpoint=config.token_endpoint,
        application_id=config.application_id,
        client_id=config.client_id,
        client_secret_file=config.client_secret_file,
        expected_issuer=config.issuer,
        ca_bundle=str(config.ca_bundle),
        read_timeout=config.mtmf_timeout_seconds,
        renewal_leeway_seconds=config.renewal_leeway_seconds,
    )


@dataclass(frozen=True, slots=True)
class CreateDependencies:
    """The concrete runtime dependencies bundled for one app instance."""

    reader: DocumentReader
    client: HttpMtmfClient


def create_app(dependencies: CreateDependencies) -> FastAPI:
    """Build the FastAPI application around already-constructed dependencies."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> Any:
        try:
            yield
        finally:
            dependencies.client.close()

    app = FastAPI(
        title="MTMF Reference App",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    reader = dependencies.reader

    @app.get("/health/live")
    async def health_live() -> dict[str, str]:
        return {"status": "live"}

    @app.get("/health/ready")
    async def health_ready() -> JSONResponse:
        if not reader.ready():
            return JSONResponse(
                status_code=503,
                content={"status": "not-ready"},
                headers={"Cache-Control": "no-store"},
            )
        return JSONResponse(content={"status": "ready"}, headers={"Cache-Control": "no-store"})

    @app.get("/v1/documents/{document_id}")
    async def get_document(document_id: str, request: Request) -> JSONResponse:
        token = _extract_bearer(request.headers.get("authorization"))
        if token is None:
            return _error_response(401, _UnauthenticatedError.message)
        try:
            document = await reader.read(token=token, document_id=document_id)
        except _ReadError as exc:
            return _error_response(exc.status_code, exc.message)
        except Exception:
            # Any unexpected fault is a fail-closed dependency failure; it never
            # becomes an ALLOW and never discloses document content.
            return _error_response(503, _DependencyFailureError.message)
        return JSONResponse(
            content={"id": document.document_id, "title": document.title, "body": document.body},
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/v1/documents/{document_id}/metadata")
    async def get_document_metadata(document_id: str, request: Request) -> JSONResponse:
        token = _extract_bearer(request.headers.get("authorization"))
        if token is None:
            return _error_response(401, _UnauthenticatedError.message)
        try:
            metadata = await reader.read_metadata(token=token, document_id=document_id)
        except _ReadError as exc:
            return _error_response(exc.status_code, exc.message)
        except Exception:
            # Any unexpected fault is a fail-closed dependency failure; it never
            # becomes an ALLOW and never discloses metadata or content.
            return _error_response(503, _DependencyFailureError.message)
        return JSONResponse(
            content={"id": metadata.document_id, "title": metadata.title},
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/v1/documents/batch-access")
    async def batch_access_documents(request: Request) -> JSONResponse:
        token = _extract_bearer(request.headers.get("authorization"))
        if token is None:
            return _error_response(401, _UnauthenticatedError.message)
        operations = await _parse_batch_access_body(request)
        if operations is None:
            return _error_response(400, "invalid batch access request")
        try:
            results = await reader.read_access_batch(token=token, operations=operations)
        except _ReadError as exc:
            return _error_response(exc.status_code, exc.message)
        except Exception:
            # Any unexpected fault is a fail-closed dependency failure; it never
            # becomes an ALLOW and never discloses metadata or content.
            return _error_response(503, _DependencyFailureError.message)
        serialized_results: list[dict[str, Any]] = []
        for result in results:
            document: dict[str, str] = {"id": result.document_id, "title": result.title}
            if result.operation == "content":
                # Only the closed ``content`` operation may ever serialize a body;
                # metadata results never carry (or default) a ``body`` key.
                document["body"] = result.body if result.body is not None else ""
            serialized_results.append({"operation": result.operation, "document": document})
        return JSONResponse(
            content={"results": serialized_results},
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/v1/documents/batch-read")
    async def batch_read_documents(request: Request) -> JSONResponse:
        token = _extract_bearer(request.headers.get("authorization"))
        if token is None:
            return _error_response(401, _UnauthenticatedError.message)
        document_ids = await _parse_batch_body(request)
        if document_ids is None:
            return _error_response(400, "invalid batch request")
        try:
            documents = await reader.read_batch(token=token, document_ids=document_ids)
        except _ReadError as exc:
            return _error_response(exc.status_code, exc.message)
        except Exception:
            # Any unexpected fault is a fail-closed dependency failure; it never
            # becomes an ALLOW and never discloses document content.
            return _error_response(503, _DependencyFailureError.message)
        return JSONResponse(
            content={
                "documents": [
                    {"id": document.document_id, "title": document.title, "body": document.body}
                    for document in documents
                ]
            },
            headers={"Cache-Control": "no-store"},
        )

    return app


def create_app_from_env() -> FastAPI:
    """Build the real application from validated environment configuration."""
    config = ReferenceAppConfig.from_env()
    store = DocumentStore(config.sqlite_path)
    store.initialize()
    client = HttpMtmfClient(build_client_config(config))
    reader = DocumentReader(
        config=config,
        store=store,
        token_verifier=UserTokenVerifier(config),
        session_keys=SessionKeyDeriver(),
        client=client,
    )
    return create_app(CreateDependencies(reader=reader, client=client))


def main() -> None:
    """Run the reference application under Uvicorn."""
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    uvicorn.run(
        create_app_from_env(),
        host="0.0.0.0",  # container-internal bind behind an isolated network
        port=8080,
        log_level="info",
        log_config=None,
    )


if __name__ == "__main__":
    main()
