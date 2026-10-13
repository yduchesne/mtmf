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
surface, performs no policy or DNS rewriting, and logs only bounded, non-secret
startup metadata. It is started by ``compose.dev.yaml`` and is owned by the
explicit ``mtmf`` Compose project.

Reliability (PR 17-C Amendment 3)
---------------------------------
The target address is resolved once through a small bounded resolver and cached
until a connect fails, so each accepted client does not re-issue the bare-name
``keycloak`` DNS search query (which intermittently exceeded the resolver
timeout and stalled client handshakes). The target connection is opened lazily,
only after the client sends its first bytes, so a bare TCP reachability probe
never opens an incomplete TLS connection. Each client is handled by two
independent streaming pumps with bounded, explicit teardown (cancel/join, close,
wait_closed) so client/target reset, half-close, refusal, timeout, or
cancellation cannot leak tasks or hang the listener.

Usage:
    python scripts/mtmf-dev-forwarder.py
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import os
import socket
import sys

#: Canonical issuer port the forwarder listens on inside the MTMF network.
LISTEN_HOST = os.environ.get("MTMF_DEV_FORWARDER_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("MTMF_DEV_FORWARDER_PORT", "28443"))
TARGET_HOST = os.environ.get("MTMF_DEV_FORWARDER_TARGET_HOST", "keycloak")
TARGET_PORT = int(os.environ.get("MTMF_DEV_FORWARDER_TARGET_PORT", "8443"))
#: Bounded per-attempt target connect timeout.
CONNECT_TIMEOUT_SECONDS = float(os.environ.get("MTMF_DEV_FORWARDER_CONNECT_TIMEOUT", "5"))
#: Bounded number of target connection attempts (resolving again between them).
CONNECT_ATTEMPTS = int(os.environ.get("MTMF_DEV_FORWARDER_CONNECT_ATTEMPTS", "3"))
#: Bounded wait for a client's first bytes before giving up on the connection.
FIRST_BYTE_TIMEOUT_SECONDS = float(os.environ.get("MTMF_DEV_FORWARDER_FIRST_BYTE_TIMEOUT", "5"))
#: Bounded grace for the target to finish a response after the client half-closes.
PUMP_DRAIN_TIMEOUT_SECONDS = float(os.environ.get("MTMF_DEV_FORWARDER_DRAIN_TIMEOUT", "10"))

CHUNK_SIZE = 65536


class _TargetResolver:
    """Resolve the Keycloak target address with a bounded, invalidatable cache.

    Resolving the bare service name on every connection repeatedly issued the
    DNS search query for ``<name>.<search-domain>``, which intermittently hit
    the resolver timeout and stalled a client's TLS handshake by 5-10 s. The
    address is resolved once and reused; a failed connect invalidates the cache
    so a rebuilt Keycloak is re-discovered rather than assumed to keep its IP.
    """

    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port
        self._address: tuple[str, int] | None = None

    @property
    def address(self) -> tuple[str, int] | None:
        """Return the cached target address, or ``None`` when unresolved."""
        return self._address

    def invalidate(self) -> None:
        """Discard the cached address so the next resolve is fresh."""
        self._address = None

    async def resolve(self) -> tuple[str, int] | None:
        """Resolve the target with bounded IPv4-only getaddrinfo."""
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(
                    self._host,
                    self._port,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                    flags=socket.AI_ADDRCONFIG,
                ),
            )
        except OSError:
            return None
        if not infos:
            return None
        self._address = infos[0][4]
        return self._address


async def _open_target(
    resolver: _TargetResolver,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Open the Keycloak listener with a bounded connect, re-resolving on failure."""
    for _ in range(CONNECT_ATTEMPTS):
        address = resolver.address
        if address is None:
            address = await resolver.resolve()
        if address is None:
            await asyncio.sleep(0.2)
            continue
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(address[0], address[1]),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except OSError:
            resolver.invalidate()
            await asyncio.sleep(0.2)
    return None


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Stream bytes one direction; on EOF propagate a half-close when supported."""
    try:
        while True:
            chunk = await reader.read(CHUNK_SIZE)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except OSError:
        pass
    except asyncio.IncompleteReadError:
        pass
    finally:
        with contextlib.suppress(OSError, RuntimeError):
            if writer.can_write_eof():
                writer.write_eof()


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    """Close a writer and await its completion, suppressing expected errors."""
    with contextlib.suppress(OSError, RuntimeError):
        writer.close()
    with contextlib.suppress(OSError, RuntimeError):
        await writer.wait_closed()


async def _handle(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    *,
    resolver: _TargetResolver,
) -> None:
    """Forward one client connection to the pinned Keycloak HTTPS listener."""
    target_writer: asyncio.StreamWriter | None = None
    try:
        # Lazy connect: wait for the client's first bytes. A bare TCP
        # reachability check that connects and closes without data never opens a
        # target connection and never disturbs Keycloak.
        try:
            first = await asyncio.wait_for(
                client_reader.read(CHUNK_SIZE), timeout=FIRST_BYTE_TIMEOUT_SECONDS
            )
        except OSError, TimeoutError:
            return
        if not first:
            return

        target = await _open_target(resolver)
        if target is None:
            return
        target_reader, target_writer = target
        try:
            target_writer.write(first)
            await target_writer.drain()
        except OSError:
            return

        client_to_target = asyncio.create_task(_pipe(client_reader, target_writer))
        target_to_client = asyncio.create_task(_pipe(target_reader, client_writer))
        tasks = {client_to_target, target_to_client}
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if target_to_client in done:
                # The target closed: no further response is possible.
                for task in pending:
                    task.cancel()
            elif pending:
                # The client finished/half-closed: give the target a bounded
                # window to deliver the remainder of the response.
                _, still_pending = await asyncio.wait(pending, timeout=PUMP_DRAIN_TIMEOUT_SECONDS)
                for task in still_pending:
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
    except asyncio.CancelledError:
        raise
    except OSError:
        # A per-client transport error is contained and never terminates the
        # listener; no payload or secret detail is logged.
        return
    finally:
        if target_writer is not None:
            await _close_writer(target_writer)
        await _close_writer(client_writer)


async def main() -> None:
    """Serve the canonical-port TCP forwarder until terminated."""
    resolver = _TargetResolver(TARGET_HOST, TARGET_PORT)
    # Warm the resolver cache before accepting clients so the first request does
    # not pay the DNS search-query cost. Failure is fine: Keycloak may not be
    # reachable yet, and connections resolve lazily.
    await resolver.resolve()
    handler = functools.partial(_handle, resolver=resolver)
    server = await asyncio.start_server(handler, LISTEN_HOST, LISTEN_PORT)
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
