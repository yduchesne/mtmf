"""Bounded, redirect-refusing HTTPS transport for the MTMF client.

The transport is the *only* place that talks to the network. It never
follows redirects (so a redirect can never carry a bearer token to another
origin), never consults proxy or ``netrc`` environment configuration
(``trust_env=False``), enforces TLS verification, and bounds every response
body before it is parsed. It makes no authorization decision.
"""

from __future__ import annotations

import ssl

import httpx

from mtmf_client.config import ClientConfig
from mtmf_client.errors import DependencyUnavailableError, RemoteProtocolError
from mtmf_client.observability import (
    ClientInstrumentation,
    ClientStatusClass,
    NoopClientInstrumentation,
)

__all__ = ["HttpTransport", "RawResponse"]

_CLIENT_VERSION = "0.1.0"


def _status_class(status_code: int) -> ClientStatusClass:
    if 200 <= status_code < 300:
        return ClientStatusClass.SUCCESS
    if 300 <= status_code < 400:
        return ClientStatusClass.REDIRECT
    if 400 <= status_code < 500:
        return ClientStatusClass.CLIENT_ERROR
    if 500 <= status_code < 600:
        return ClientStatusClass.SERVER_ERROR
    return ClientStatusClass.UNKNOWN


class RawResponse:
    """A bounded, already-read HTTP response.

    The body is a validated-size ``bytes`` value or empty for a redirect
    response (whose body is never consumed). No token is stored here.
    """

    __slots__ = ("body", "content_type", "headers", "status_code")

    def __init__(
        self,
        *,
        status_code: int,
        headers: httpx.Headers,
        body: bytes,
    ) -> None:
        self.status_code = status_code
        self.headers = headers
        self.body = body
        content_type = headers.get("content-type")
        self.content_type = content_type.split(";", 1)[0].strip().lower() if content_type else None

    @property
    def is_redirect(self) -> bool:
        """Whether the response is a redirect (3xx) that was not followed."""
        return 300 <= self.status_code < 400


class HttpTransport:
    """Owns one bounded ``httpx.Client`` shared by token and PDP calls."""

    __slots__ = ("_client", "_instrumentation", "_max_bytes")

    def __init__(
        self,
        config: ClientConfig,
        *,
        transport: httpx.BaseTransport | None = None,
        instrumentation: ClientInstrumentation | None = None,
    ) -> None:
        timeout = httpx.Timeout(
            connect=config.connect_timeout,
            read=config.read_timeout,
            write=config.write_timeout,
            pool=config.pool_timeout,
        )
        verify: ssl.SSLContext | bool = (
            ssl.create_default_context(cafile=config.ca_bundle) if config.ca_bundle else True
        )
        self._max_bytes = config.max_response_bytes
        self._instrumentation = instrumentation or NoopClientInstrumentation()
        self._client = httpx.Client(
            verify=verify,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
            headers={"User-Agent": f"mtmf-client/{_CLIENT_VERSION}"},
        )

    def post_form(self, url: str, *, data: dict[str, str]) -> RawResponse:
        """POST an ``application/x-www-form-urlencoded`` request."""
        return self._request(
            "POST",
            url,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data=data,
        )

    def post_json(
        self,
        url: str,
        *,
        body: str,
        headers: dict[str, str],
    ) -> RawResponse:
        """POST an already-serialized JSON body with explicit headers."""
        request_headers = {"Accept": "application/json", **headers}
        return self._request(
            "POST",
            url,
            headers=request_headers,
            content=body.encode("utf-8"),
        )

    def close(self) -> None:
        """Close the underlying connection pool."""
        self._client.close()

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes | None = None,
        data: dict[str, str] | None = None,
    ) -> RawResponse:
        """Issue one request and return a bounded response.

        :raises DependencyUnavailableError: on a transport/timeout failure.
        :raises RemoteProtocolError: when the response body exceeds the bound.
        """
        try:
            with self._client.stream(
                method,
                url,
                headers=headers,
                content=content,
                data=data,
            ) as response:
                self._record_response(response.status_code)
                if response.is_redirect:
                    # The body of a redirect is never read or forwarded.
                    return RawResponse(
                        status_code=response.status_code,
                        headers=response.headers,
                        body=b"",
                    )
                body = self._read_bounded(response)
                return RawResponse(
                    status_code=response.status_code,
                    headers=response.headers,
                    body=body,
                )
        except httpx.HTTPError as exc:
            raise DependencyUnavailableError("the MTMF transport call failed") from exc

    def _record_response(self, status_code: int) -> None:
        """Record the outbound response class; never let telemetry raise."""
        try:
            self._instrumentation.record_http_response(status_class=_status_class(status_code))
        except Exception:
            return

    def _read_bounded(self, response: httpx.Response) -> bytes:
        """Read at most ``max_response_bytes`` from ``response``.

        A declared ``Content-Length`` over the bound is rejected before the
        body is read; the streamed byte count is always enforced too.
        """
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                declared_length = int(declared)
            except ValueError:
                declared_length = None
            if declared_length is not None and declared_length > self._max_bytes:
                raise RemoteProtocolError("the MTMF response exceeds the permitted size")
            if declared_length is not None and declared_length < 0:
                raise RemoteProtocolError("the MTMF response declared an invalid size")
        collected = bytearray()
        for chunk in response.iter_bytes():
            collected += chunk
            if len(collected) > self._max_bytes:
                raise RemoteProtocolError("the MTMF response exceeds the permitted size")
        return bytes(collected)
