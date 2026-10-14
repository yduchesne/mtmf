#!/usr/bin/env python3
"""PR 20B acceptance-only deterministic fault fronting component.

This is a development/acceptance tool. It is **never** part of the default
development stack, production MTMF, or the official client. It is intended to
run inside the isolated ``mtmf-pr20a-acceptance`` project, only reachable by
the reference-app container, presenting the **same pinned acceptance TLS leaf**
as the canonical internal terminator. It terminates TLS, forwards every request
to the plaintext MTMF service, and can deterministically substitute **only the
remote ``/v1/authorization/evaluate`` response** for one configured test case.

Safety properties:

- the fault mode is read from a local control file, never from an HTTP control
  surface and never from the reference application;
- with no control file (or ``none``) it is a byte-faithful HTTP pass-through;
- it never disables TLS verification and never rewrites non-evaluate paths;
- it logs no payload and no credential.

Fault modes: ``none``, ``refuse``, ``delay``, ``http_502``, ``http_503``,
``non_json``, ``malformed_json``, ``mismatch``.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

LISTEN_HOST = os.environ.get("MTMF_PR20B_PROXY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("MTMF_PR20B_PROXY_LISTEN_PORT", "29501"))
TARGET_HOST = os.environ.get("MTMF_PR20B_PROXY_TARGET_HOST", "service")
TARGET_PORT = int(os.environ.get("MTMF_PR20B_PROXY_TARGET_PORT", "28001"))
TLS_CERT = os.environ.get("MTMF_PR20B_PROXY_TLS_CERT", "")
TLS_KEY = os.environ.get("MTMF_PR20B_PROXY_TLS_KEY", "")
FAULT_FILE = os.environ.get("MTMF_PR20B_FAULT_FILE", "")
FAULT_DELAY_SECONDS = float(os.environ.get("MTMF_PR20B_FAULT_DELAY_SECONDS", "20"))

EVALUATE_PATH = "/v1/authorization/evaluate"
_KNOWN_FAULTS = frozenset(
    {"none", "refuse", "delay", "http_502", "http_503", "non_json", "malformed_json", "mismatch"}
)
_FORWARDED_HEADERS_SKIP = frozenset({"host", "content-length", "connection", "transfer-encoding"})


def _current_fault() -> str:
    """Return the configured fault mode, defaulting to a clean pass-through."""
    if not FAULT_FILE:
        return "none"
    try:
        value = Path(FAULT_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return "none"
    return value if value in _KNOWN_FAULTS else "none"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    upstream = httpx.Client(
        base_url=f"http://{TARGET_HOST}:{TARGET_PORT}",
        timeout=httpx.Timeout(connect=5.0, read=60.0, write=60.0, pool=5.0),
        follow_redirects=False,
    )

    def log_message(self, *args: object) -> None:
        """Suppress request logging (never log credentials)."""

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    # -- internals ---------------------------------------------------------
    def _handle(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        fault = _current_fault() if self.path.split("?", 1)[0] == EVALUATE_PATH else "none"
        if fault == "refuse":
            self.close_connection = True
            return
        if fault == "delay":
            time.sleep(FAULT_DELAY_SECONDS)
        try:
            response = self._forward(method, body)
        except httpx.HTTPError:
            self._reply(502, b"upstream unavailable", "text/plain")
            return
        status, payload, content_type = response
        if fault == "http_502":
            self._reply(502, b'{"error":"forced 502"}', "text/plain")
            return
        if fault == "http_503":
            self._reply(503, b'{"error":"forced 503"}', "text/plain")
            return
        if fault == "non_json":
            self._reply(200, b"forced non-json body", "text/plain")
            return
        if fault == "malformed_json":
            self._reply(200, b"{not valid json", "application/json")
            return
        if fault == "mismatch":
            payload = _tamper_request_id(payload)
        self._reply(status, payload, content_type)

    def _forward(self, method: str, body: bytes | None) -> tuple[int, bytes, str | None]:
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in _FORWARDED_HEADERS_SKIP
        }
        request = self.upstream.build_request(method, self.path, content=body, headers=headers)
        response = self.upstream.send(request, stream=False)
        return response.status_code, response.content, response.headers.get("content-type")

    def _reply(self, status: int, payload: bytes, content_type: str | None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type or "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)


def _tamper_request_id(payload: bytes) -> bytes:
    """Return ``payload`` with the first decision correlated to a wrong id."""
    try:
        document = json.loads(payload)
    except ValueError:
        return payload
    decisions = document.get("decisions")
    if isinstance(decisions, list) and decisions:
        decisions[0]["request_id"] = "tampered-correlation-0000"
    return json.dumps(document).encode("utf-8")


def main() -> None:
    """Serve the TLS fault fronting component until terminated."""
    if not TLS_CERT or not TLS_KEY:
        raise SystemExit("MTMF_PR20B_PROXY_TLS_CERT and _KEY are required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print(
        f"PR 20B fault proxy listening on {LISTEN_HOST}:{LISTEN_PORT} -> "
        f"{TARGET_HOST}:{TARGET_PORT}",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
