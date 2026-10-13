#!/usr/bin/env python3
"""Development-only local CA and Keycloak leaf certificate management (PR 17-C).

This helper creates a disposable, uncommitted local certificate authority and
a server leaf certificate for the canonical MTMF development issuer authority
``https://keycloak.mtmf.test:28443`` using the system OpenSSL tooling. It is
development-only, idempotent, and never overwrites an existing private key
unless the operator explicitly asks to rotate.

The generated material lives under ``MTMF_DEV_CA_DIR`` (default
``/tmp/mtmf-dev-ca``):

- ``dev-ca.key``   — CA private key (owner-only, never committed)
- ``dev-ca.crt``   — CA certificate (public; import into the trust stores)
- ``server.key``   — Keycloak leaf private key
- ``server.crt``   — Keycloak leaf certificate

Only the *public* CA certificate is mounted into the restricted MTMF service
and initializer; the leaf and CA private keys never enter the runtime
containers. The Keycloak container runs as UID ``1000`` in the rootless Podman
user namespace, so ``harden`` maps the leaf key owner to that container UID
using ``podman unshare chown`` instead of making the private key world
readable. If the mapping cannot be applied the command fails closed.

Usage:
    python scripts/mtmf-dev-certs.py generate
    python scripts/mtmf-dev-certs.py generate --rotate
    python scripts/mtmf-dev-certs.py harden
    python scripts/mtmf-dev-certs.py check
    python scripts/mtmf-dev-certs.py print-paths
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

#: Canonical development issuer hostname and its certificate SAN.
DEFAULT_HOSTNAME = "keycloak.mtmf.test"

#: Additional SAN entries that keep the documented loopback host-network
#: fallback and local `localhost` checks TLS-verified.
DEFAULT_SAN = "DNS:keycloak.mtmf.test,DNS:localhost,IP:127.0.0.1"

#: Keycloak's in-container UID for the pinned image (``quay.io/keycloak/keycloak``).
KEYCLOAK_CONTAINER_UID = 1000

_CA_KEY = "dev-ca.key"
_CA_CERT = "dev-ca.crt"
_SERVER_KEY = "server.key"
_SERVER_CERT = "server.crt"
_SERIAL = "dev-ca.srl"


class CertError(RuntimeError):
    """Certificate material could not be generated, verified, or hardened."""


@dataclass(frozen=True, slots=True)
class CertPaths:
    """Resolved paths to the managed certificate material."""

    directory: Path
    ca_key: Path
    ca_cert: Path
    server_key: Path
    server_cert: Path

    @classmethod
    def resolve(cls, directory: Path) -> CertPaths:
        """Return the deterministic path set for ``directory``."""
        return cls(
            directory=directory,
            ca_key=directory / _CA_KEY,
            ca_cert=directory / _CA_CERT,
            server_key=directory / _SERVER_KEY,
            server_cert=directory / _SERVER_CERT,
        )


def default_directory() -> Path:
    """Return the configured development CA directory."""
    value = os.environ.get("MTMF_DEV_CA_DIR", "").strip()
    return Path(value) if value else Path(tempfile.gettempdir()) / "mtmf-dev-ca"


def _require_openssl() -> str:
    """Return the OpenSSL executable or fail closed."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise CertError("openssl is required to generate development certificates")
    return openssl


def _run(args: list[str], *, secret_stdin: str | None = None) -> None:
    """Run one OpenSSL command quietly, never echoing secret material."""
    completed = subprocess.run(
        args,
        input=secret_stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        # Do not echo command output that may contain key material.
        raise CertError(f"openssl command failed ({args[1] if len(args) > 1 else 'openssl'})")


def _openssl() -> str:
    return _require_openssl()


def _make_ca(paths: CertPaths) -> None:
    """Create the local CA key and self-signed certificate."""
    _run(
        [
            _openssl(),
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-sha256",
            "-days",
            "3650",
            "-nodes",
            "-keyout",
            str(paths.ca_key),
            "-out",
            str(paths.ca_cert),
            "-subj",
            "/CN=MTMF Development Local CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
        ]
    )


def _make_leaf(paths: CertPaths, hostname: str) -> None:
    """Create and sign the canonical-hostname server leaf certificate."""
    san = f"DNS:{hostname},DNS:localhost,IP:127.0.0.1"
    with tempfile.TemporaryDirectory(prefix="mtmf-dev-certs-") as work:
        csr = Path(work) / "server.csr"
        ext = Path(work) / "server-ext.cnf"
        ext.write_text(
            "\n".join(
                [
                    "basicConstraints=critical,CA:FALSE",
                    "keyUsage=critical,digitalSignature,keyEncipherment",
                    "extendedKeyUsage=serverAuth",
                    f"subjectAltName={san}",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        _run(
            [
                _openssl(),
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-keyout",
                str(paths.server_key),
                "-out",
                str(csr),
                "-subj",
                f"/CN={hostname}",
            ]
        )
        _run(
            [
                _openssl(),
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(paths.ca_cert),
                "-CAkey",
                str(paths.ca_key),
                "-CAcreateserial",
                "-out",
                str(paths.server_cert),
                "-days",
                "825",
                "-sha256",
                "-extfile",
                str(ext),
            ]
        )


def _set_permissions(paths: CertPaths) -> None:
    """Apply owner-only private keys and world-readable public certificates."""
    paths.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(paths.directory, 0o700)
    for private in (paths.ca_key, paths.server_key):
        if private.exists():
            os.chmod(private, 0o600)
    for public in (paths.ca_cert, paths.server_cert):
        if public.exists():
            os.chmod(public, 0o644)


def _exists(paths: CertPaths) -> bool:
    return all(
        path.exists() for path in (paths.ca_key, paths.ca_cert, paths.server_key, paths.server_cert)
    )


def generate(directory: Path, *, hostname: str = DEFAULT_HOSTNAME, rotate: bool = False) -> bool:
    """Generate certificate material if absent; return whether it was created.

    Existing material is preserved unless ``rotate`` is explicitly requested.
    """
    paths = CertPaths.resolve(directory)
    if _exists(paths) and not rotate:
        check(directory, hostname=hostname)
        return False
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Never partially reuse a half-written key set: only regenerate the missing
    # pair. Rotation removes the previous material first so no stale key is
    # silently reused by the new CA.
    if rotate:
        for path in (paths.ca_key, paths.ca_cert, paths.server_key, paths.server_cert):
            path.unlink(missing_ok=True)
        (directory / _SERIAL).unlink(missing_ok=True)
    if not paths.ca_key.exists() or not paths.ca_cert.exists():
        _make_ca(paths)
    if not paths.server_key.exists() or not paths.server_cert.exists():
        _make_leaf(paths, hostname)
    _set_permissions(paths)
    check(directory, hostname=hostname)
    return True


def harden(directory: Path, *, container_uid: int = KEYCLOAK_CONTAINER_UID) -> None:
    """Map the leaf key owner to the Keycloak container UID without widening.

    Rootless Podman maps the owner to the container's UID inside the user
    namespace, so the Keycloak process can read a mode ``0600`` key while the
    host copy is never world-readable. Fails closed when Podman is unavailable
    or the mapping fails; the private key is never made group/other readable.
    """
    paths = CertPaths.resolve(directory)
    if not paths.server_key.exists():
        raise CertError("no leaf key exists to harden; run `generate` first")
    if shutil.which("podman") is None:
        raise CertError("podman is required to map the leaf key to the container UID")
    result = subprocess.run(
        [
            "podman",
            "unshare",
            "chown",
            f"{container_uid}:{container_uid}",
            str(paths.server_key),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise CertError(
            "failed to map the leaf key to the container UID; refusing to widen its permissions"
        )
    mode = paths.server_key.stat().st_mode & 0o777
    if mode & 0o077:
        raise CertError("leaf key is group/other accessible after hardening")


def _certificate_san(cert: Path) -> str:
    """Return the certificate's subjectAltName or fail closed."""
    result = subprocess.run(
        [_openssl(), "x509", "-in", str(cert), "-noout", "-ext", "subjectAltName"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise CertError("could not read the server certificate extensions")
    return result.stdout.strip()


def verify_chain(paths: CertPaths) -> None:
    """Require the leaf to verify against the CA and remain valid now."""
    result = subprocess.run(
        [
            _openssl(),
            "verify",
            "-CAfile",
            str(paths.ca_cert),
            str(paths.server_cert),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise CertError("the server certificate does not verify against the local CA")


def check(directory: Path, *, hostname: str = DEFAULT_HOSTNAME) -> None:
    """Fail closed unless the leaf has the canonical SAN and verifies."""
    paths = CertPaths.resolve(directory)
    if not _exists(paths):
        raise CertError(f"certificate material is incomplete under {directory}")
    san = _certificate_san(paths.server_cert)
    if f"DNS:{hostname}" not in san:
        raise CertError(f"the server certificate is missing SAN DNS:{hostname}")
    verify_chain(paths)
    if paths.ca_key.stat().st_mode & 0o077:
        raise CertError("the CA private key is group/other accessible")


def print_paths(directory: Path) -> None:
    """Print the resolved public/private path set (never key contents)."""
    paths = CertPaths.resolve(directory)
    for label, path in (
        ("MTMF_DEV_CA_DIR", paths.directory),
        ("MTMF_DEV_CA_CERT_FILE", paths.ca_cert),
        ("MTMF_DEV_SERVER_CERT_FILE", paths.server_cert),
        ("MTMF_DEV_SERVER_KEY_FILE", paths.server_key),
    ):
        print(f"{label}={path}")


def main(argv: list[str] | None = None) -> int:
    """Parse a subcommand and run the development certificate operation."""
    parser = argparse.ArgumentParser(description="MTMF development CA/certificate helper")
    parser.add_argument("--dir", default=str(default_directory()))
    parser.add_argument("--hostname", default=DEFAULT_HOSTNAME)
    sub = parser.add_subparsers(dest="command", required=True)
    generate_parser = sub.add_parser("generate", help="create missing CA/leaf material")
    generate_parser.add_argument("--rotate", action="store_true", help="replace existing material")
    harden_parser = sub.add_parser("harden", help="map the leaf key to the container UID")
    harden_parser.add_argument("--container-uid", type=int, default=KEYCLOAK_CONTAINER_UID)
    sub.add_parser("check", help="verify SAN, chain, and private-key permissions")
    sub.add_parser("print-paths", help="print resolved paths")
    args = parser.parse_args(argv)
    directory = Path(args.dir)
    try:
        if args.command == "generate":
            created = generate(directory, hostname=args.hostname, rotate=args.rotate)
            if created:
                print(f"generated development CA/leaf material under {directory}")
            else:
                print(f"development CA/leaf material already present under {directory}")
        elif args.command == "harden":
            harden(directory, container_uid=args.container_uid)
            print("mapped the leaf key to the Keycloak container UID")
        elif args.command == "check":
            check(directory, hostname=args.hostname)
            print("development certificate material is valid")
        else:
            print_paths(directory)
    except CertError as exc:
        print(f"certificate error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
