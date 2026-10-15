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

import itertools
import json
import os
import ssl
import sys
import threading
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
#: Acceptance-only non-secret decision evidence (JSONL). Records only the
#: correlation id, exact Action, effect and resource id of a successful real
#: upstream evaluation; never request/response bodies or credentials.
EVIDENCE_FILE = os.environ.get("MTMF_PR20B_EVIDENCE_FILE", "")
_EVIDENCE_LOCK = threading.Lock()
_EVIDENCE_COUNTER = itertools.count(1)

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
        try:
            self._handle_inner(method)
        except BrokenPipeError, ConnectionResetError, OSError:
            # The caller may have abandoned a faulted request (e.g. timeout);
            # never let a closed socket crash the handler thread.
            self.close_connection = True

    def _handle_inner(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        is_evaluate = self.path.split("?", 1)[0] == EVALUATE_PATH
        fault = _current_fault() if is_evaluate else "none"
        if is_evaluate and fault != "none":
            _record_fault(fault)
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
        elif is_evaluate and fault == "none":
            if status == 200:
                _record_evidence(body, payload, content_type)
            else:
                _record_error(status, payload, content_type)
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


def _record_error(status: int, payload: bytes, content_type: str | None) -> None:
    """Append the non-secret status/code of a non-200 real upstream response."""
    if not EVIDENCE_FILE or content_type is None:
        return
    if not content_type.startswith("application/json"):
        return
    code: object = None
    try:
        document = json.loads(payload)
        if isinstance(document, dict):
            error = document.get("error")
            if isinstance(error, dict):
                code = error.get("code")
    except ValueError, TypeError:
        code = None
    with _EVIDENCE_LOCK:
        sequence = next(_EVIDENCE_COUNTER)
        line = json.dumps(
            {"n": sequence, "error_status": status, "error_code": code}, sort_keys=True
        )
    try:
        with open(EVIDENCE_FILE, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        return


def _record_fault(mode: str) -> None:
    """Append a non-secret activation record for one injected fault mode."""
    if not EVIDENCE_FILE:
        return
    with _EVIDENCE_LOCK:
        sequence = next(_EVIDENCE_COUNTER)
        line = json.dumps({"n": sequence, "fault": mode}, sort_keys=True)
    try:
        with open(EVIDENCE_FILE, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        return


def _record_evidence(
    request_body: bytes | None, response_payload: bytes, content_type: str | None
) -> None:
    """Append non-secret decision evidence for one successful real evaluation.

    Only the correlation id, exact Action, effect and non-secret resource id are
    recorded. Request/response bodies and credentials are never retained.
    """
    if not EVIDENCE_FILE or not response_payload:
        return
    if content_type is None or not content_type.startswith("application/json"):
        return
    try:
        request = json.loads(request_body) if request_body else {}
        response = json.loads(response_payload)
    except ValueError, TypeError:
        return
    if not isinstance(request, dict) or not isinstance(response, dict):
        return
    actions = {
        item.get("request_id"): item
        for item in request.get("actions", [])
        if isinstance(item, dict)
    }
    decisions: list[dict[str, object]] = []
    for decision in response.get("decisions", []):
        if not isinstance(decision, dict):
            continue
        request_id = decision.get("request_id")
        action = actions.get(request_id)
        resource = action.get("resource") if isinstance(action, dict) else None
        decisions.append(
            {
                "request_id": request_id,
                "action": action.get("action") if isinstance(action, dict) else None,
                "effect": decision.get("effect"),
                "resource_id": resource.get("id") if isinstance(resource, dict) else None,
            }
        )
    with _EVIDENCE_LOCK:
        sequence = next(_EVIDENCE_COUNTER)
        line = json.dumps({"n": sequence, "decisions": decisions}, sort_keys=True)
    try:
        with open(EVIDENCE_FILE, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
    except OSError:
        return


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
