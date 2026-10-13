#!/usr/bin/env python3
"""PR 17-C Amendment 3 — canonical TLS path reliability harness.

Measures, per request and without any retry, the phases of a full canonical
issuer check against one of three paths:

* ``A`` host      -> loopback-published Keycloak (``127.0.0.1:28443``)
* ``B`` container -> Keycloak directly (``keycloak:8443``)
* ``C`` container -> canonical authority (``keycloak.mtmf.test:28443``) ->
  forwarder -> Keycloak

The TLS handshake always verifies the development CA and uses SNI
``keycloak.mtmf.test`` regardless of the TCP target, so B and C exercise the
same certificate/hostname validation. Each request mirrors the canonical probe:
a fresh connection for discovery and a fresh connection for JWKS. Failures are
first-attempt failures: no request is retried.

Development-only; prints bounded metadata (never payloads, tokens, or secrets).
Exits non-zero if any request fails or exceeds the per-request timeout.

Usage (host, path A):
    python tests/integration/pr17c_forwarder_reliability.py \
        --label A --target-host 127.0.0.1 --target-port 28443 \
        --ca-file /tmp/mtmf-dev-ca/dev-ca.crt --count 50

Usage (container, path B/C):
    ... --target-host keycloak --target-port 8443 \
        --ca-file /certs/mtmf-ca.crt --count 50
"""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import socket
import ssl
import statistics
import sys
import time
from dataclasses import dataclass, field

CANONICAL_ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-dev"
SNI_HOSTNAME = "keycloak.mtmf.test"
HOST_HEADER = "keycloak.mtmf.test:28443"
DISCOVERY_PATH = "/realms/mtmf-dev/.well-known/openid-configuration"
EXPECTED_JWKS_PATH = "/realms/mtmf-dev/protocol/openid-connect/certs"
MAX_BODY_BYTES = 262144


@dataclass(slots=True)
class PhaseTiming:
    """Timing for one fresh TLS GET (bounded, non-secret)."""

    dns: float
    connect: float
    handshake: float
    get: float
    status: int
    body: bytes


@dataclass(slots=True)
class RequestResult:
    """Per-request phase timings and outcome (bounded, non-secret)."""

    index: int
    success: bool
    failure: str = ""
    dns: float = 0.0
    connect: float = 0.0
    handshake: float = 0.0
    discovery: float = 0.0
    jwks: float = 0.0

    @property
    def total(self) -> float:
        return self.dns + self.connect + self.handshake + self.discovery + self.jwks


@dataclass(slots=True)
class Batch:
    """A sequential or concurrent batch of requests."""

    label: str
    results: list[RequestResult] = field(default_factory=list)

    def summary(self) -> dict[str, object]:
        ok = [r for r in self.results if r.success]
        durations = sorted(r.total for r in ok)
        return {
            "label": self.label,
            "requests": len(self.results),
            "successes": len(ok),
            "failures": len(self.results) - len(ok),
            "max_seconds": round(durations[-1], 4) if durations else None,
            "p95_seconds": round(_percentile(durations, 95), 4) if durations else None,
            "median_seconds": round(statistics.median(durations), 4) if durations else None,
            "failure_types": sorted({r.failure for r in self.results if not r.success}),
        }


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    index = min(len(values) - 1, max(0, round(percentile / 100 * (len(values) - 1))))
    return values[index]


def _tls_get(
    *,
    target_host: str,
    target_port: int,
    ca_file: str,
    path: str,
    timeout: float,
) -> PhaseTiming:
    """Open a fresh verified TLS connection and perform one bounded GET."""
    t0 = time.monotonic()
    infos = socket.getaddrinfo(target_host, target_port, type=socket.SOCK_STREAM)
    dns = time.monotonic() - t0
    address = infos[0][4][0]
    context = ssl.create_default_context(cafile=ca_file)
    t1 = time.monotonic()
    raw = socket.create_connection((address, target_port), timeout=timeout)
    connect = time.monotonic() - t1
    t2 = time.monotonic()
    stream = context.wrap_socket(raw, server_hostname=SNI_HOSTNAME)
    handshake = time.monotonic() - t2
    stream.settimeout(timeout)
    try:
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {HOST_HEADER}\r\n"
            "Accept: application/json\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        t3 = time.monotonic()
        stream.sendall(request)
        response = http.client.HTTPResponse(stream)
        response.begin()
        body = response.read(MAX_BODY_BYTES + 1)
        if len(body) > MAX_BODY_BYTES:
            raise RuntimeError("response too large")
        get = time.monotonic() - t3
        return PhaseTiming(dns, connect, handshake, get, response.status, body)
    finally:
        stream.close()


def one_request(
    index: int,
    *,
    target_host: str,
    target_port: int,
    ca_file: str,
    timeout: float,
) -> RequestResult:
    """Perform one full canonical check (discovery + JWKS) with no retry."""
    result = RequestResult(index=index, success=False)
    try:
        discovery = _tls_get(
            target_host=target_host,
            target_port=target_port,
            ca_file=ca_file,
            path=DISCOVERY_PATH,
            timeout=timeout,
        )
        result.dns = discovery.dns
        result.connect = discovery.connect
        result.handshake = discovery.handshake
        result.discovery = discovery.get
        if discovery.status != 200:
            raise RuntimeError(f"discovery HTTP {discovery.status}")
        document = json.loads(discovery.body)
        if document.get("issuer") != CANONICAL_ISSUER:
            raise RuntimeError("discovery issuer mismatch")
        jwks_uri = document.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri.endswith(EXPECTED_JWKS_PATH):
            raise RuntimeError("unexpected jwks_uri")

        jwks = _tls_get(
            target_host=target_host,
            target_port=target_port,
            ca_file=ca_file,
            path=EXPECTED_JWKS_PATH,
            timeout=timeout,
        )
        result.jwks = jwks.dns + jwks.connect + jwks.handshake + jwks.get
        if jwks.status != 200:
            raise RuntimeError(f"jwks HTTP {jwks.status}")
        keys = json.loads(jwks.body).get("keys")
        if not isinstance(keys, list) or not keys:
            raise RuntimeError("no jwks keys")
        result.success = True
    except (OSError, ssl.SSLError, ValueError, RuntimeError, TimeoutError) as exc:
        result.failure = type(exc).__name__
    return result


def run_batch(
    *,
    label: str,
    count: int,
    concurrency: int,
    target_host: str,
    target_port: int,
    ca_file: str,
    timeout: float,
) -> Batch:
    """Run ``count`` requests at the given concurrency, with no retries."""
    batch = Batch(label=label)
    if concurrency <= 1:
        batch.results = [
            one_request(
                i,
                target_host=target_host,
                target_port=target_port,
                ca_file=ca_file,
                timeout=timeout,
            )
            for i in range(count)
        ]
        return batch
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(
                one_request,
                i,
                target_host=target_host,
                target_port=target_port,
                ca_file=ca_file,
                timeout=timeout,
            )
            for i in range(count)
        ]
        batch.results = [future.result() for future in futures]
    return batch


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the requested batch, and report bounded statistics."""
    parser = argparse.ArgumentParser(description="PR 17-C forwarder TLS reliability harness")
    parser.add_argument("--label", default="C")
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--target-port", type=int, required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--json-out", default="")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    batch = run_batch(
        label=args.label,
        count=args.count,
        concurrency=args.concurrency,
        target_host=args.target_host,
        target_port=args.target_port,
        ca_file=args.ca_file,
        timeout=args.timeout,
    )
    if args.verbose:
        for result in batch.results:
            print(
                f"[{batch.label}] {result.index}: "
                f"{'ok' if result.success else 'FAIL ' + result.failure} "
                f"total={result.total:.3f} dns={result.dns:.3f} "
                f"connect={result.connect:.3f} handshake={result.handshake:.3f} "
                f"discovery={result.discovery:.3f} jwks={result.jwks:.3f}"
            )
    summary = batch.summary()
    print(json.dumps(summary, sort_keys=True))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(summary, handle, indent=2, sort_keys=True)
    return 0 if summary["failures"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
