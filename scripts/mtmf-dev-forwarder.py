#!/usr/bin/env python3
"""MTMF-owned development TLS TCP forwarder (PR 17-C).

The canonical development issuer authority is
``https://keycloak.mtmf.test:28443`` while the pinned Keycloak image keeps its
internal HTTPS listener on ``8443``. This tiny, non-privileged forwarder
accepts TCP connections on the canonical port inside the isolated MTMF
Compose network and forwards them byte-for-byte to ``keycloak:8443``. TLS is
**not** terminated or inspected here, so Keycloak's certificate, hostname,
and issuer validation remain intact end to end and no second issuer exists.

It is development-only, never host-published, exposes no health or admin
surface, performs no policy or DNS rewriting, and logs only bounded connection
metadata. It is started by ``compose.dev.yaml`` and is owned by the explicit
``mtmf`` Compose project.

Usage:
    python scripts/mtmf-dev-forwarder.py
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys

#: Canonical issuer port the forwarder listens on inside the MTMF network.
LISTEN_HOST = os.environ.get("MTMF_DEV_FORWARDER_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("MTMF_DEV_FORWARDER_PORT", "28443"))
TARGET_HOST = os.environ.get("MTMF_DEV_FORWARDER_TARGET_HOST", "keycloak")
TARGET_PORT = int(os.environ.get("MTMF_DEV_FORWARDER_TARGET_PORT", "8443"))
CONNECT_TIMEOUT_SECONDS = float(os.environ.get("MTMF_DEV_FORWARDER_CONNECT_TIMEOUT", "5"))
CONNECT_ATTEMPTS = int(os.environ.get("MTMF_DEV_FORWARDER_CONNECT_ATTEMPTS", "8"))


async def _open_target() -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Open the Keycloak listener, retrying briefly across a restart window."""
    delay = 0.2
    for _ in range(CONNECT_ATTEMPTS):
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(TARGET_HOST, TARGET_PORT),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except OSError:
            await asyncio.sleep(delay)
            delay = min(delay * 2, 2.0)
    return None


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Copy bytes until EOF, then half-close the destination."""
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except OSError:
        pass
    except asyncio.IncompleteReadError:
        pass
    finally:
        with contextlib.suppress(AttributeError, ConnectionError, RuntimeError):
            writer.write_eof()


async def _handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    """Forward one connection to the pinned Keycloak HTTPS listener."""
    target = await _open_target()
    if target is None:
        client_writer.close()
        return
    target_reader, target_writer = target
    try:
        await asyncio.gather(
            _pipe(client_reader, target_writer),
            _pipe(target_reader, client_writer),
        )
    finally:
        target_writer.close()
        client_writer.close()


async def main() -> None:
    """Serve the canonical-port TCP forwarder until terminated."""
    server = await asyncio.start_server(_handle, LISTEN_HOST, LISTEN_PORT)
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    # Bounded, non-secret startup line only.
    print(
        f"mtmf development forwarder listening on {addresses} -> {TARGET_HOST}:{TARGET_PORT}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
