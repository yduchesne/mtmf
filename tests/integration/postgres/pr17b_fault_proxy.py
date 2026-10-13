"""Test-only deterministic Keycloak Admin REST fault proxy (PR 17-B I15).

This module exists solely for the PR 17-B live acceptance harness. It is not
imported by production code, is never shipped in a runtime image, and adds no
public or remotely reachable failpoint.

The proxy sits between the development initializer and the real Keycloak Admin
REST API and forwards every request unchanged, except that it can deterministically
drop the response to a user-creation ``POST`` *after* the real Keycloak has
already committed the creation. That reproduces the "creation committed but the
caller experienced a timeout / lost response" boundary without replacing
Keycloak with a fake: the upstream call is real and the user really exists.

Fault modes:

- ``none``: pure pass-through.
- ``drop_response``: forward a create ``POST`` (real commit), then close the
  connection without replying so the caller observes a transport failure.
- ``error_before_forward``: answer a create ``POST`` with HTTP 400 without
  forwarding, modelling an unsuccessful creation.
- ``drop_and_fail_reads``: forward a create ``POST`` (real commit), drop its
  response, and fail subsequent user-lookup ``GET`` requests so the caller's
  authoritative re-read also fails (indeterminate outcome).
"""

from __future__ import annotations

import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

__all__ = ["FaultProxy"]

#: Request paths whose final segment is the Keycloak user-creation collection.
_USER_COLLECTION_SUFFIX = "/users"

_FORWARDED_HEADERS = ("Authorization", "Content-Type", "Accept")


class FaultProxy:
    """A bounded, loopback-only Admin REST pass-through with deterministic faults."""

    def __init__(
        self,
        upstream_base: str,
        ca_file: str,
        *,
        fault: str = "none",
        realm: str = "mtmf-pr14-dev",
    ) -> None:
        if fault not in {
            "none",
            "drop_response",
            "error_before_forward",
            "drop_and_fail_reads",
            "strip_location",
            "wrong_realm_location",
        }:
            raise ValueError(f"unknown fault mode {fault!r}")
        self._upstream = upstream_base.rstrip("/")
        self._fault = fault
        self._realm = realm
        self._client = httpx.Client(
            verify=ssl.create_default_context(cafile=ca_file) if ca_file else True,
            timeout=30.0,
            follow_redirects=False,
        )
        self.requests: list[tuple[str, str]] = []
        self.create_posts = 0
        proxy = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: object) -> None:
                """Suppress default request logging (never log credentials)."""

            def do_GET(self) -> None:
                proxy._handle(self, "GET")

            def do_POST(self) -> None:
                proxy._handle(self, "POST")

            def do_PUT(self) -> None:
                proxy._handle(self, "PUT")

            def do_DELETE(self) -> None:
                proxy._handle(self, "DELETE")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.port = int(self._server.server_address[1])
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> FaultProxy:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._client.close()
        self._thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        """The loopback base URL the initializer should use as its Admin REST base."""
        return f"http://127.0.0.1:{self.port}"

    def create_post_count(self) -> int:
        """Number of user-creation POSTs observed (proves no blind retry)."""
        return self.create_posts

    # -- internals ---------------------------------------------------------
    def _is_create(self, method: str, path: str) -> bool:
        if method != "POST":
            return False
        return path.split("?", 1)[0].rstrip("/").endswith(_USER_COLLECTION_SUFFIX)

    def _is_user_lookup(self, method: str, path: str) -> bool:
        return method == "GET" and "/users" in path

    def _handle(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length) if length else None
        path = handler.path
        self.requests.append((method, path))
        is_create = self._is_create(method, path)
        if is_create:
            self.create_posts += 1
        if is_create and self._fault == "error_before_forward":
            self._reply(handler, 400, b'{"error":"forced"}', "application/json")
            return
        if (
            self._fault == "drop_and_fail_reads"
            and method == "GET"
            and self._is_user_lookup(method, path)
            and self.create_posts > 0
        ):
            self._reply(handler, 503, b'{"error":"forced"}', "application/json")
            return
        drop = is_create and self._fault in {"drop_response", "drop_and_fail_reads"}
        self._forward(
            handler,
            method,
            body,
            drop_response=drop,
            location_fault=self._fault if is_create else None,
        )

    def _forward(
        self,
        handler: BaseHTTPRequestHandler,
        method: str,
        body: bytes | None,
        *,
        drop_response: bool,
        location_fault: str | None = None,
    ) -> None:
        request = httpx.Request(method, self._upstream + handler.path, content=body)
        for name in _FORWARDED_HEADERS:
            value = handler.headers.get(name)
            if value is not None:
                request.headers[name] = value
        try:
            response = self._client.send(request)
            status = response.status_code
            payload = response.content
            content_type = response.headers.get("content-type", "application/json")
            location = response.headers.get("location")
        except httpx.HTTPError:
            self._reply(handler, 502, b'{"error":"upstream"}', "application/json")
            return
        if drop_response:
            # The upstream commit already happened; close without a response so
            # the caller experiences a lost/timeout response, then re-reads.
            handler.close_connection = True
            return
        if location is not None:
            # Rewrite the real Keycloak origin to this proxy's loopback origin so
            # the test exercises path/realm provenance validation rather than an
            # origin mismatch against the test-only HTTP transport.
            marker = "/admin/"
            index = location.find(marker)
            if index != -1:
                location = f"http://127.0.0.1:{self.port}" + location[index:]
        if location_fault == "strip_location":
            location = None
        elif location_fault == "wrong_realm_location" and location:
            location = location.replace(f"/realms/{self._realm}/", "/realms/other-realm/")
        self._reply(handler, status, payload, content_type, location=location)

    @staticmethod
    def _reply(
        handler: BaseHTTPRequestHandler,
        status: int,
        payload: bytes,
        content_type: str | None,
        *,
        location: str | None = None,
    ) -> None:
        handler.send_response(status)
        handler.send_header("Content-Type", content_type or "application/json")
        if location is not None:
            handler.send_header("Location", location)
        handler.send_header("Content-Length", str(len(payload)))
        handler.end_headers()
        if payload:
            handler.wfile.write(payload)
