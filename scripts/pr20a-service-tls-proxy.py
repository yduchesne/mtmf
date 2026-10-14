#!/usr/bin/env python3
"""PR 20A development-only TLS terminator in front of the MTMF HTTP service.

The official ``mtmf-client`` refuses a non-HTTPS MTMF base URL. The PR 20A
acceptance topology therefore publishes the restricted MTMF service over a
plaintext internal listener and puts this tiny, isolated TLS terminator in
front of it **inside** the ``mtmf-pr20a-acceptance`` network. The reference app
connects to the terminator, verifies the development CA, and never disables
TLS verification. The terminator performs no authentication, no policy, and no
request rewriting; it only terminates TLS on the client side and forwards bytes
to the plaintext service.

It is development acceptance tooling only. It is never host-published, logs no
payload or secret, and is owned by the explicit acceptance Compose project.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import ssl
import sys

LISTEN_HOST = os.environ.get("MTMF_PR20A_PROXY_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("MTMF_PR20A_PROXY_LISTEN_PORT", "29501"))
TARGET_HOST = os.environ.get("MTMF_PR20A_PROXY_TARGET_HOST", "service")
TARGET_PORT = int(os.environ.get("MTMF_PR20A_PROXY_TARGET_PORT", "28001"))
TLS_CERT = os.environ.get("MTMF_PR20A_PROXY_TLS_CERT", "")
TLS_KEY = os.environ.get("MTMF_PR20A_PROXY_TLS_KEY", "")

CHUNK_SIZE = 65536
HANDSHAKE_TIMEOUT = float(os.environ.get("MTMF_PR20A_PROXY_HANDSHAKE_TIMEOUT", "10"))


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Forward bytes one direction; propagate a half-close when supported."""
    try:
        while True:
            chunk = await reader.read(CHUNK_SIZE)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError, RuntimeError):
            if writer.can_write_eof():
                writer.write_eof()


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """TLS-terminate one client connection and relay it to the service."""
    target_writer: asyncio.StreamWriter | None = None
    try:
        target_reader, target_writer = await asyncio.open_connection(TARGET_HOST, TARGET_PORT)
    except OSError:
        writer.close()
        return
    try:
        await asyncio.gather(
            _pipe(reader, target_writer),
            _pipe(target_reader, writer),
            return_exceptions=True,
        )
    finally:
        for stream_writer in (target_writer, writer):
            with contextlib.suppress(OSError, RuntimeError):
                stream_writer.close()
        for stream_writer in (target_writer, writer):
            with contextlib.suppress(OSError, RuntimeError):
                await stream_writer.wait_closed()


async def main() -> None:
    """Serve the TLS terminator until terminated."""
    if not TLS_CERT or not TLS_KEY:
        raise SystemExit("MTMF_PR20A_PROXY_TLS_CERT and _KEY are required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
    server = await asyncio.start_server(
        _handle,
        LISTEN_HOST,
        LISTEN_PORT,
        ssl=context,
        ssl_handshake_timeout=HANDSHAKE_TIMEOUT,
    )
    print(
        f"PR 20A TLS terminator listening on {LISTEN_HOST}:{LISTEN_PORT} -> "
        f"{TARGET_HOST}:{TARGET_PORT}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
