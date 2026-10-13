#!/usr/bin/env python3
"""Canonical development issuer preflight probe (PR 17-C).

This self-contained, dependency-free probe verifies that a single canonical
development Keycloak authority is reachable and correct from the namespace it
runs in. It checks, in order and fail-closed:

1. DNS resolution of the canonical hostname;
2. TCP reachability on the canonical port (``28443``);
3. TLS trust and hostname/SAN verification against the MTMF development CA;
4. discovery ``issuer`` exact equality with the canonical trust anchor;
5. discovery ``jwks_uri`` exact equality with the canonical Keycloak certs
   endpoint, checked **before** the JWKS request is made;
6. JWKS endpoint availability and shape.

It is run twice by the development launcher: once on the WSL host and once
inside the isolated MTMF Compose network, because a host success does **not**
prove container reachability and vice versa. It never disables TLS
verification, never accepts a mismatched issuer or JWKS URI, and never falls
back to another host.

Usage:
    python scripts/mtmf-dev-probe.py \
        --issuer https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev \
        --ca-file /tmp/mtmf-dev-ca/dev-ca.crt
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

DEFAULT_TIMEOUT_SECONDS = 5.0

#: Exact canonical development issuer (PR 17-C). Must agree with
#: ``CANONICAL_KC_ISSUER`` in ``scripts/mtmf-dev-stack.py``; a unit test asserts
#: the two literals are identical.
CANONICAL_ISSUER = "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev"

#: Exact canonical Keycloak JWKS resource appended to the canonical issuer.
EXPECTED_JWKS_SUFFIX = "/protocol/openid-connect/certs"
EXPECTED_JWKS_URI = CANONICAL_ISSUER + EXPECTED_JWKS_SUFFIX


class ProbeError(RuntimeError):
    """The canonical development issuer did not pass preflight."""


@dataclass(slots=True)
class ProbeReport:
    """Non-secret, ordered preflight diagnostics for one namespace."""

    namespace: str
    host: str
    port: int
    addresses: list[str] = field(default_factory=list)
    checks: list[str] = field(default_factory=list)

    def record(self, message: str) -> None:
        """Append one successful, non-secret diagnostic line."""
        self.checks.append(message)


def _parse_issuer(issuer: str) -> tuple[str, int]:
    """Return the canonical ``(host, port)`` for ``issuer`` or fail closed.

    The supplied issuer must be the literal canonical issuer; any other
    host/port/scheme/path (including values containing the canonical hostname
    as a substring) is rejected. The untrusted value is never echoed.
    """
    if issuer != CANONICAL_ISSUER:
        raise ProbeError(
            "the issuer must exactly equal the canonical development issuer "
            f"{CANONICAL_ISSUER} (rejected the supplied value)"
        )
    parsed = urllib.parse.urlparse(issuer)
    if parsed.scheme != "https" or parsed.hostname != "keycloak.mtmf.test":
        raise ProbeError("the canonical issuer must use https://keycloak.mtmf.test")
    if parsed.port != 28443:
        raise ProbeError("the canonical issuer must use port 28443")
    return parsed.hostname, parsed.port


def _require_expected_jwks_uri(jwks_uri: object) -> str:
    """Return the JWKS URI only when it is the exact canonical endpoint.

    This is a pure, network-free check applied to the untrusted discovery
    document before any JWKS request. Prefix/suffix/hostname-only matching,
    normalization, percent-decoding, and relative URLs are all rejected.
    """
    if not isinstance(jwks_uri, str) or jwks_uri != EXPECTED_JWKS_URI:
        raise ProbeError(
            "discovery jwks_uri does not equal the expected canonical Keycloak endpoint"
        )
    return jwks_uri


def resolve_host(host: str) -> list[str]:
    """Resolve ``host`` to a bounded, deduplicated address list."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ProbeError(
            f"the canonical development hostname {host!r} does not resolve in this "
            "namespace; add the operator-managed hosts/DNS mapping and retry"
        ) from exc
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ProbeError(f"no addresses resolved for {host!r}")
    return addresses


def check_tcp(host: str, port: int, *, timeout: float) -> None:
    """Require a TCP connection to ``host:port`` within the timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except OSError as exc:
        raise ProbeError(f"cannot reach the canonical authority {host}:{port}: {exc}") from exc


def tls_context(ca_file: str) -> ssl.SSLContext:
    """Build a verifying TLS context for the development CA (never insecure)."""
    try:
        return ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError) as exc:
        raise ProbeError(f"cannot load the development CA file {ca_file!r}: {exc}") from exc


def _fetch(url: str, context: ssl.SSLContext, *, timeout: float, what: str) -> bytes:
    """Fetch ``url`` with verification, bounded, and no redirect following."""
    request = urllib.request.Request(url, method="GET")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args: object, **kwargs: object) -> None:
            return None

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context), _NoRedirect()
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise ProbeError(f"{what} returned HTTP {response.status}")
            return response.read(262144)
    except urllib.error.HTTPError as exc:
        raise ProbeError(f"{what} returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise ProbeError(f"{what} failed TLS/transport verification: {exc.reason}") from exc
    except (OSError, ValueError) as exc:
        raise ProbeError(f"{what} could not be read: {exc}") from exc


def check_issuer(issuer: str, ca_file: str, *, namespace: str, timeout: float) -> ProbeReport:
    """Run the full canonical-issuer preflight and return collected diagnostics."""
    host, port = _parse_issuer(issuer)
    anchor = CANONICAL_ISSUER
    report = ProbeReport(namespace=namespace, host=host, port=port)
    report.addresses = resolve_host(host)
    report.record(f"dns {host} -> {', '.join(report.addresses)}")
    check_tcp(host, port, timeout=timeout)
    report.record(f"tcp {host}:{port} reachable")
    context = tls_context(ca_file)
    discovery_url = f"{anchor}/.well-known/openid-configuration"
    discovery = json.loads(_fetch(discovery_url, context, timeout=timeout, what="discovery"))
    report.record(f"tls verified against {ca_file}")
    if not isinstance(discovery, dict):
        raise ProbeError("discovery document is not a JSON object")
    if discovery.get("issuer") != anchor:
        raise ProbeError(
            "discovery issuer mismatch: the live issuer does not equal the canonical "
            "trust anchor; refusing to continue"
        )
    report.record(f"discovery issuer == {anchor}")
    jwks_uri = _require_expected_jwks_uri(discovery.get("jwks_uri"))
    report.record(f"discovery jwks_uri == {jwks_uri}")
    jwks = json.loads(_fetch(jwks_uri, context, timeout=timeout, what="jwks"))
    if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list) or not jwks["keys"]:
        raise ProbeError("the JWKS document contains no signing keys")
    report.record(f"jwks {jwks_uri} contains {len(jwks['keys'])} key(s)")
    return report


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the preflight, and print non-secret diagnostics."""
    parser = argparse.ArgumentParser(description="MTMF canonical development issuer preflight")
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--namespace", default="host")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--json", action="store_true", help="emit a machine-readable report")
    args = parser.parse_args(argv)
    try:
        report = check_issuer(
            args.issuer, args.ca_file, namespace=args.namespace, timeout=args.timeout
        )
    except ProbeError as exc:
        print(f"preflight[{args.namespace}] failed: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(
            json.dumps(
                {
                    "namespace": report.namespace,
                    "host": report.host,
                    "port": report.port,
                    "addresses": report.addresses,
                    "checks": report.checks,
                },
                sort_keys=True,
            )
        )
    else:
        for line in report.checks:
            print(f"preflight[{report.namespace}] {line}")
        print(f"preflight[{report.namespace}] OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
