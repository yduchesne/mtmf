"""PR 17-C Amendment 3 — deterministic forwarder lifecycle tests (FW01-FW20).

These tests exercise the real production ``_handle`` / ``_pipe`` /
``_open_target`` path against in-process asyncio echo/one-shot targets and a
controlled resolver. No external network, Podman, or Keycloak is used. Each
test runs its own event loop via :func:`asyncio.run`.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import sys
import time
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "mtmf-dev-forwarder.py"
_spec = importlib.util.spec_from_file_location("mtmf_dev_forwarder", _SCRIPT)
assert _spec is not None and _spec.loader is not None
forwarder = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = forwarder
_spec.loader.exec_module(forwarder)

_REPO_ROOT = Path(__file__).resolve().parents[3]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


async def _echo_target(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _start_target(handler: Any) -> tuple[asyncio.AbstractServer, int]:
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


class _Harness:
    """Runs the production handler behind a local asyncio server."""

    def __init__(self, resolver: Any) -> None:
        self.resolver = resolver
        self.server: asyncio.AbstractServer | None = None
        self.port = 0
        self.tasks: list[asyncio.Task[Any]] = []

    async def __aenter__(self) -> _Harness:
        async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if task is not None:
                self.tasks.append(task)
            await forwarder._handle(reader, writer, resolver=self.resolver)

        self.server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc: object) -> None:
        assert self.server is not None
        self.server.close()
        await self.server.wait_closed()


class _FlakyResolver:
    """Resolver whose target is unavailable while ``down`` is true."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.down = True

    @property
    def address(self) -> Any:
        return None if self.down else self._real.address

    def invalidate(self) -> None:
        self._real.invalidate()

    async def resolve(self) -> Any:
        return None if self.down else await self._real.resolve()


async def _echo_roundtrip(port: int, payload: bytes, *, timeout: float = 5.0) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(payload)
        await writer.drain()
        return await asyncio.wait_for(reader.readexactly(len(payload)), timeout=timeout)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _send_and_read_eof(port: int, payload: bytes, *, timeout: float = 5.0) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(payload)
        await writer.drain()
        with contextlib.suppress(TimeoutError):
            return await asyncio.wait_for(reader.read(), timeout=timeout)
        return b""
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


# --------------------------------------------------------------------------
# FW01-FW04: byte transparency
# --------------------------------------------------------------------------


def test_fw01_client_to_target_bytes():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            payload = bytes(range(256)) * 8
            assert await _echo_roundtrip(harness.port, payload) == payload
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw02_target_to_client_bytes():
    async def scenario() -> None:
        async def one_shot(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(65536)
            writer.write(b"target-payload-123")
            await writer.drain()
            writer.close()

        target, tport = await _start_target(one_shot)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            assert await _send_and_read_eof(harness.port, b"go") == b"target-payload-123"
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw03_simultaneous_bidirectional():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            payload = b"bidirectional" * 5000
            writer.write(payload)
            await writer.drain()
            received = await asyncio.wait_for(reader.readexactly(len(payload)), timeout=5)
            assert received == payload
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw04_multi_chunk_over_64k():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            payload = bytes((i * 7) % 256 for i in range(200_000))
            assert await _echo_roundtrip(harness.port, payload) == payload
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


# --------------------------------------------------------------------------
# FW05-FW08: EOF / half-close / reset
# --------------------------------------------------------------------------


def test_fw05_client_half_close_then_response():
    async def scenario() -> None:
        async def read_all_then_reply(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.read()
            writer.write(b"after-eof")
            await writer.drain()
            writer.close()

        target, tport = await _start_target(read_all_then_reply)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.write(b"half-close-me")
            await writer.drain()
            writer.write_eof()
            received = await asyncio.wait_for(reader.read(), timeout=5)
            assert received == b"after-eof"
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw06_target_eof_reaches_client():
    async def scenario() -> None:
        async def send_then_close(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.read(65536)
            writer.write(b"final")
            await writer.drain()
            writer.close()

        target, tport = await _start_target(send_then_close)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            assert await _send_and_read_eof(harness.port, b"x") == b"final"
            await asyncio.sleep(0.05)
            # No lingering per-client handler tasks (all completed, none pending).
            assert all(task.done() for task in harness.tasks)
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw07_client_reset_during_target_response():
    async def scenario() -> None:
        async def slow_sender(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.read(65536)
            for _ in range(20):
                writer.write(b"x" * 4096)
                await writer.drain()
                await asyncio.sleep(0.01)
            writer.close()

        target, tport = await _start_target(slow_sender)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            _reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.write(b"start")
            await writer.drain()
            await asyncio.sleep(0.02)
            writer.transport.abort()  # type: ignore[attr-defined]
            await asyncio.sleep(0.2)
            # Listener survives and a fresh connection is still served.
            assert harness.server is not None and harness.server.is_serving()
            fresh_reader, fresh_writer = await asyncio.open_connection("127.0.0.1", harness.port)
            fresh_writer.write(b"y")
            await fresh_writer.drain()
            response = await asyncio.wait_for(fresh_reader.read(16), timeout=3)
            assert response
            fresh_writer.close()
            with contextlib.suppress(Exception):
                await fresh_writer.wait_closed()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw08_target_reset_during_client_upload():
    async def scenario() -> None:
        async def aborting_target(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.read(1024)
            writer.transport.abort()  # type: ignore[attr-defined]

        target, tport = await _start_target(aborting_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            with contextlib.suppress(ConnectionError, OSError):
                writer.write(b"y" * 200_000)
                await writer.drain()
                await asyncio.wait_for(reader.read(), timeout=3)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            await asyncio.sleep(0.1)
            assert harness.server is not None and harness.server.is_serving()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


# --------------------------------------------------------------------------
# FW09-FW11: refusal / timeout / cancellation
# --------------------------------------------------------------------------


def test_fw09_target_connection_refused():
    async def scenario() -> None:
        probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        dead_port = probe.sockets[0].getsockname()[1]
        probe.close()
        await probe.wait_closed()
        resolver = forwarder._TargetResolver("127.0.0.1", dead_port)
        async with _Harness(resolver) as harness:
            start = time.monotonic()
            assert await _send_and_read_eof(harness.port, b"data") == b""
            assert time.monotonic() - start < 5.0
            assert harness.server is not None and harness.server.is_serving()

    asyncio.run(scenario())


def test_fw10_target_connect_timeout(monkeypatch: pytest.MonkeyPatch):
    async def scenario() -> None:
        monkeypatch.setattr(forwarder, "CONNECT_TIMEOUT_SECONDS", 0.2)
        monkeypatch.setattr(forwarder, "CONNECT_ATTEMPTS", 1)
        # TEST-NET-1 (RFC 5737) is not reachable; the connect must be bounded.
        resolver = forwarder._TargetResolver("192.0.2.1", 8443)
        start = time.monotonic()
        target = await forwarder._open_target(resolver)
        elapsed = time.monotonic() - start
        assert target is None
        assert elapsed < 3.0

    asyncio.run(scenario())


def test_fw11_cancellation_during_pump():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            _reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.write(b"start")
            await writer.drain()
            await asyncio.sleep(0.05)
            assert harness.tasks
            harness.tasks[0].cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await harness.tasks[0]
            assert harness.tasks[0].done()
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


# --------------------------------------------------------------------------
# FW12: write_eof unsupported / raising
# --------------------------------------------------------------------------


class _FakeReader:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    async def read(self, _size: int) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _FakeWriter:
    def __init__(self, *, can_eof: bool, raise_eof: bool) -> None:
        self._can_eof = can_eof
        self._raise_eof = raise_eof
        self.written = b""

    def write(self, data: bytes) -> None:
        self.written += data

    async def drain(self) -> None:
        return None

    def can_write_eof(self) -> bool:
        return self._can_eof

    def write_eof(self) -> None:
        if self._raise_eof:
            raise OSError(107, "Transport endpoint is not connected")


@pytest.mark.parametrize(
    ("can_eof", "raise_eof"),
    [(False, False), (True, True)],
)
def test_fw12_write_eof_unsupported_or_raises(can_eof: bool, raise_eof: bool):
    async def scenario() -> None:
        reader = _FakeReader([b"payload", b""])
        writer = _FakeWriter(can_eof=can_eof, raise_eof=raise_eof)
        await forwarder._pipe(reader, writer)  # type: ignore[arg-type]
        assert writer.written == b"payload"

    asyncio.run(scenario())


# --------------------------------------------------------------------------
# FW13-FW17: concurrency, stall, sequential, recovery, malformed
# --------------------------------------------------------------------------


def test_fw13_twenty_concurrent_clients():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            payloads = [f"client-{i}-".encode() * 200 for i in range(20)]

            async def worker(payload: bytes) -> bytes:
                return await _echo_roundtrip(harness.port, payload)

            results = await asyncio.gather(*(worker(p) for p in payloads))
            assert results == payloads
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw14_stalled_client_does_not_block_healthy():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            stalled_reader, stalled_writer = await asyncio.open_connection(
                "127.0.0.1", harness.port
            )
            # Send nothing; the forwarder waits for the first byte.
            await asyncio.sleep(0.05)
            healthy = await asyncio.gather(
                *(_echo_roundtrip(harness.port, b"healthy") for _ in range(5))
            )
            assert healthy == [b"healthy"] * 5
            stalled_writer.close()
            with contextlib.suppress(Exception):
                await stalled_writer.wait_closed()
            stalled_reader.feed_eof()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw15_fifty_sequential_connections_no_leak():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            baseline = len(asyncio.all_tasks())
            for _ in range(50):
                assert await _echo_roundtrip(harness.port, b"seq") == b"seq"
            await asyncio.sleep(0.1)
            assert len(asyncio.all_tasks()) <= baseline + 2
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw16_target_recovers_without_forwarder_restart():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        resolver = _FlakyResolver(forwarder._TargetResolver("127.0.0.1", tport))
        async with _Harness(resolver) as harness:
            assert await _send_and_read_eof(harness.port, b"down") == b""
            resolver.down = False
            assert await _echo_roundtrip(harness.port, b"recovered") == b"recovered"
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fw17_listener_survives_aborted_client():
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            _reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.transport.abort()  # type: ignore[attr-defined]
            await asyncio.sleep(0.05)
            assert harness.server is not None and harness.server.is_serving()
            assert await _echo_roundtrip(harness.port, b"next") == b"next"
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


# --------------------------------------------------------------------------
# FW18-FW20: no payload logging, TLS validation preserved, stable Compose
# --------------------------------------------------------------------------


def test_fw18_no_payload_in_forwarder_output(capsys: pytest.CaptureFixture[str]):
    async def scenario() -> None:
        target, tport = await _start_target(_echo_target)
        async with _Harness(forwarder._TargetResolver("127.0.0.1", tport)) as harness:
            assert await _echo_roundtrip(harness.port, b"SECRET-PAYLOAD-42") == b"SECRET-PAYLOAD-42"
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())
    captured = capsys.readouterr()
    assert "SECRET-PAYLOAD-42" not in captured.out + captured.err


def test_fw19_canonical_issuer_jwks_constants_unchanged():
    # The forwarder is raw TCP and does not touch issuer/JWKS validation; the
    # canonical probe constants must be unchanged by this amendment.
    probe_script = _REPO_ROOT / "scripts" / "mtmf-dev-probe.py"
    spec = importlib.util.spec_from_file_location("mtmf_dev_probe_fw19", probe_script)
    assert spec is not None and spec.loader is not None
    probe = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = probe
    spec.loader.exec_module(probe)
    assert probe.CANONICAL_ISSUER == "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev"
    assert (
        probe.EXPECTED_JWKS_URI
        == "https://keycloak.mtmf.test:28443/realms/mtmf-pr14-dev/protocol/openid-connect/certs"
    )
    # The forwarder must not terminate or inspect TLS: it imports no TLS library.
    source = _SCRIPT.read_text(encoding="utf-8")
    assert "import ssl" not in source
    assert "ssl." not in source


def test_fw20_compose_model_and_launcher_unchanged():
    compose = (_REPO_ROOT / "compose.dev.yaml").read_text(encoding="utf-8")
    assert "MTMF_DEV_FORWARDER_IP" not in compose
    assert "extra_hosts" not in compose
    launcher = (_REPO_ROOT / "scripts" / "mtmf-dev-stack.py").read_text(encoding="utf-8")
    assert "_forwarder_ip" not in launcher
    nsswitch = (_REPO_ROOT / "dev" / "nsswitch.conf").read_text(encoding="utf-8")
    hosts_line = next(line for line in nsswitch.splitlines() if line.startswith("hosts:"))
    assert hosts_line.split(":", 1)[1].split()[:2] == ["dns", "files"]
    # FW18 support: the module only emits one bounded startup line.
    source = _SCRIPT.read_text(encoding="utf-8")
    assert source.count("print(") == 1
