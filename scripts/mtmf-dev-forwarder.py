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
startup/error metadata. It is started by ``compose.dev.yaml`` and is owned by
the explicit ``mtmf`` Compose project.

Reliability (PR 17-C Amendment 3 + Fixup 1)
------------------------------------------
* **Bounded DNS.** The target address is resolved through a small cached
  resolver with a real caller-facing deadline. A timed-out/blocked resolver
  worker cannot mutate the cache: the cache commit happens only in the awaiting
  coroutine and only when the invalidation generation is unchanged.
* **Race-safe cache.** One ``asyncio.Lock`` serializes lookups and an
  invalidation generation prevents a stale in-flight result from overwriting a
  newer invalidation.
* **Cancellation-safe pumps.** ``_handle`` owns both pump tasks and both
  writers; a single bounded, shielded cleanup path cancels and joins every pump
  and closes/awaits both writers on success, error, or cancellation.
* **Lazy target connect.** The target connection is opened only after the
  client sends its first bytes, so a bare TCP reachability probe never opens an
  incomplete TLS connection.

Usage:
    python scripts/mtmf-dev-forwarder.py
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import math
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
#: Bounded budget for cancelling/joining pumps and closing writers during cleanup.
CLEANUP_TIMEOUT_SECONDS = float(os.environ.get("MTMF_DEV_FORWARDER_CLEANUP_TIMEOUT", "2"))
#: Backoff between bounded target-connect attempts.
CONNECT_BACKOFF_SECONDS = 0.2

CHUNK_SIZE = 65536


def _parse_resolve_timeout() -> float:
    """Return a finite, strictly positive resolver deadline or exit.

    Validation happens at import/startup so an invalid value fails before the
    listener is created.
    """
    raw = os.environ.get("MTMF_DEV_FORWARDER_RESOLVE_TIMEOUT", "").strip()
    if not raw:
        return 2.0
    try:
        value = float(raw)
    except ValueError:
        raise SystemExit(
            "MTMF_DEV_FORWARDER_RESOLVE_TIMEOUT must be a finite positive number"
        ) from None
    if not math.isfinite(value) or value <= 0:
        raise SystemExit("MTMF_DEV_FORWARDER_RESOLVE_TIMEOUT must be a finite positive number")
    return value


#: Caller-facing DNS resolution deadline.
RESOLVE_TIMEOUT_SECONDS = _parse_resolve_timeout()


class _TargetResolver:
    """Resolve the Keycloak target address with a bounded, race-safe cache.

    The DNS lookup runs in a worker thread (``asyncio.to_thread``) behind a real
    ``asyncio.wait_for`` deadline. Only the awaiting coroutine commits a result,
    and only when the invalidation generation has not changed, so a late or
    timed-out worker can never mutate cached state. A single ``asyncio.Lock``
    coalesces concurrent lookups while the cache is empty.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        resolve_timeout: float = RESOLVE_TIMEOUT_SECONDS,
    ) -> None:
        if not math.isfinite(resolve_timeout) or resolve_timeout <= 0:
            raise ValueError("resolve_timeout must be a finite positive number")
        self._host = host
        self._port = port
        self._resolve_timeout = resolve_timeout
        self._address: tuple[str, int] | None = None
        #: Monotonic invalidation generation; incremented synchronously.
        self._generation = 0
        self._lock = asyncio.Lock()

    @property
    def address(self) -> tuple[str, int] | None:
        """Return the cached target address, or ``None`` when unresolved."""
        return self._address

    def invalidate(self) -> None:
        """Synchronously discard the cached address and bump the generation."""
        self._generation += 1
        self._address = None

    def _lookup(self) -> tuple[str, int] | None:
        """Blocking IPv4-only resolution (runs in a worker thread)."""
        try:
            infos = socket.getaddrinfo(
                self._host,
                self._port,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                flags=socket.AI_ADDRCONFIG,
            )
        except OSError:
            return None
        if not infos:
            return None
        return infos[0][4]

    async def resolve(self) -> tuple[str, int] | None:
        """Resolve the target within the deadline; ``None`` on any failure.

        The cache is committed only by this coroutine and only when the
        generation is unchanged, so a timed-out worker thread that finishes
        later cannot populate the cache with a stale address. ``CancelledError``
        propagates to the caller.
        """
        async with self._lock:
            if self._address is not None:
                return self._address
            generation = self._generation
            try:
                result = await asyncio.wait_for(
                    asyncio.to_thread(self._lookup),
                    timeout=self._resolve_timeout,
                )
            except TimeoutError, OSError:
                return None
            if result is None:
                return None
            if generation != self._generation or self._address is not None:
                # Invalidated while this lookup was in flight.
                return None
            self._address = result
            return result


async def _open_target(
    resolver: _TargetResolver,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
    """Open the Keycloak listener with bounded connect attempts and re-resolution."""
    for _ in range(CONNECT_ATTEMPTS):
        address = resolver.address
        if address is None:
            address = await resolver.resolve()
        if address is None:
            await asyncio.sleep(CONNECT_BACKOFF_SECONDS)
            continue
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(address[0], address[1]),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except OSError:
            resolver.invalidate()
            await asyncio.sleep(CONNECT_BACKOFF_SECONDS)
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
    """Close a writer and await its completion within a bounded budget."""
    with contextlib.suppress(OSError, RuntimeError):
        writer.close()
    with contextlib.suppress(OSError, RuntimeError, TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), timeout=CLEANUP_TIMEOUT_SECONDS)


async def _finish_cleanup(
    tasks: set[asyncio.Task[None]],
    target_writer: asyncio.StreamWriter | None,
    client_writer: asyncio.StreamWriter,
) -> None:
    """Cancel/join every registered pump, then close both writers.

    Runs as the single owner cleanup path. Bounded so it cannot hang the
    handler: pumps are joined within ``CLEANUP_TIMEOUT_SECONDS`` and writers are
    closed with a bounded ``wait_closed``. Expected disconnect errors are
    suppressed; an unexpected pump exception is surfaced as a bounded,
    non-secret diagnostic rather than silently discarded. Writers are closed
    only after the pumps have had their cancellation/join opportunity.
    """
    for task in tasks:
        if not task.done():
            task.cancel()
    results: list[object] = []
    if tasks:
        try:
            gathered = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=CLEANUP_TIMEOUT_SECONDS,
            )
            results = list(gathered)
        except TimeoutError:
            for task in tasks:
                if not task.done():
                    task.cancel()
    unexpected = [
        result
        for result in results
        if isinstance(result, BaseException)
        and not isinstance(result, (asyncio.CancelledError, OSError))
    ]
    if unexpected:
        print(
            f"mtmf development forwarder: unexpected pump error ({type(unexpected[0]).__name__})",
            file=sys.stderr,
            flush=True,
        )
    if target_writer is not None:
        await _close_writer(target_writer)
    await _close_writer(client_writer)


async def _handle(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    *,
    resolver: _TargetResolver,
) -> None:
    """Forward one client connection to the pinned Keycloak HTTPS listener."""
    target_writer: asyncio.StreamWriter | None = None
    tasks: set[asyncio.Task[None]] = set()
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
        tasks.add(client_to_target)
        target_to_client = asyncio.create_task(_pipe(target_reader, client_writer))
        tasks.add(target_to_client)
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        if target_to_client in done:
            # The target closed: no further response is possible.
            for task in pending:
                task.cancel()
        elif pending:
            # The client finished/half-closed: give the target a bounded window
            # to deliver the remainder of the response.
            _, still_pending = await asyncio.wait(pending, timeout=PUMP_DRAIN_TIMEOUT_SECONDS)
            for task in still_pending:
                task.cancel()
    except asyncio.CancelledError:
        raise
    except OSError:
        # A per-client transport error is contained and never terminates the
        # listener; no payload or secret detail is logged.
        return
    finally:
        # Single owner cleanup. Shield the cleanup task so a cancellation of the
        # handler cannot abandon the pumps; if the handler is cancelled while
        # waiting, join the same cleanup task and re-raise cancellation.
        cleanup_task = asyncio.ensure_future(_finish_cleanup(tasks, target_writer, client_writer))
        try:
            await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.shield(cleanup_task)
            raise


async def main() -> None:
    """Serve the canonical-port TCP forwarder until terminated."""
    resolver = _TargetResolver(TARGET_HOST, TARGET_PORT, resolve_timeout=RESOLVE_TIMEOUT_SECONDS)
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
    except ValueError as exc:
        print(f"mtmf development forwarder configuration error: {exc}", file=sys.stderr)
        sys.exit(2)
