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
import os
import subprocess
import sys
import threading
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
    # FW18 support: the module emits at most the startup line, one bounded
    # non-secret pump-error diagnostic, and one configuration-error line.
    source = _SCRIPT.read_text(encoding="utf-8")
    assert source.count("print(") <= 3


# ==========================================================================
# Fixup 1: FX-U01-FX-U26
# ==========================================================================


class _CountingResolver(forwarder._TargetResolver):
    """Resolver whose blocking lookup is a controllable, counting fake."""

    def __init__(self, result=None, *, resolve_timeout=0.2):
        super().__init__("keycloak", 8443, resolve_timeout=resolve_timeout)
        self.calls = 0
        self._result = result

    def _lookup(self):
        self.calls += 1
        return self._result or None


def _blocking_lookup(release: threading.Event, result):
    def lookup():
        release.wait(timeout=5)
        return result

    return lookup


async def _release_worker():
    # Give the worker thread a chance to finish after its event is released.
    await asyncio.sleep(0.05)


def test_fxu01_dns_resolves_and_caches():
    async def scenario():
        resolver = _CountingResolver(("10.0.0.1", 8443))
        assert await resolver.resolve() == ("10.0.0.1", 8443)
        assert await resolver.resolve() == ("10.0.0.1", 8443)
        assert resolver.address == ("10.0.0.1", 8443)
        assert resolver.calls == 1

    asyncio.run(scenario())


def test_fxu02_cached_address_no_new_dns_with_concurrent_clients():
    async def scenario():
        target, tport = await _start_target(_echo_target)
        resolver = _CountingResolver(("127.0.0.1", tport))
        await resolver.resolve()
        async with _Harness(resolver) as harness:
            payloads = [f"c{i}".encode() * 100 for i in range(20)]
            results = await asyncio.gather(*(_echo_roundtrip(harness.port, p) for p in payloads))
            assert results == payloads
        assert resolver.calls == 1
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu03_concurrent_uncached_resolve_single_call():
    async def scenario():
        release = threading.Event()
        resolver = _CountingResolver(("10.1.1.1", 8443), resolve_timeout=2.0)
        resolver._lookup = lambda: _slow_counter(resolver, release)
        tasks = [asyncio.create_task(resolver.resolve()) for _ in range(20)]
        await asyncio.sleep(0.05)
        release.set()
        results = await asyncio.gather(*tasks)
        assert all(result == ("10.1.1.1", 8443) for result in results)
        assert resolver.calls == 1

    asyncio.run(scenario())


def _slow_counter(resolver, release):
    resolver.calls += 1
    release.wait(timeout=5)
    return resolver._result


def test_fxu04_dns_oserror_none_then_retry():
    async def scenario():
        calls = {"n": 0}

        def lookup():
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("dns failure")
            return ("10.0.0.2", 8443)

        resolver = forwarder._TargetResolver("keycloak", 8443, resolve_timeout=1.0)
        resolver._lookup = lookup
        assert await resolver.resolve() is None
        assert resolver.address is None
        assert await resolver.resolve() == ("10.0.0.2", 8443)

    asyncio.run(scenario())


def test_fxu05_dns_empty_list_none():
    async def scenario():
        resolver = _CountingResolver([])
        assert await resolver.resolve() is None
        assert resolver.address is None

    asyncio.run(scenario())


def test_fxu06_dns_worker_stalls_bounded():
    async def scenario():
        release = threading.Event()
        resolver = forwarder._TargetResolver("keycloak", 8443, resolve_timeout=0.1)
        resolver._lookup = lambda: _slow_block(release) or None
        start = time.monotonic()
        assert await resolver.resolve() is None
        assert time.monotonic() - start < 1.0
        release.set()
        await _release_worker()

    asyncio.run(scenario())


def _slow_block(release):
    release.wait(timeout=5)
    return None


def test_fxu07_late_dns_result_cannot_populate_cache():
    async def scenario():
        release = threading.Event()
        resolver = forwarder._TargetResolver("keycloak", 8443, resolve_timeout=0.1)
        resolver._lookup = lambda: _slow_addr(release)
        assert await resolver.resolve() is None
        release.set()
        await _release_worker()
        assert resolver.address is None

    asyncio.run(scenario())


def _slow_addr(release):
    release.wait(timeout=5)
    return ("10.9.9.9", 8443)


def test_fxu08_invalidate_during_inflight_lookup():
    async def scenario():
        release = threading.Event()
        resolver = forwarder._TargetResolver("keycloak", 8443, resolve_timeout=2.0)
        resolver._lookup = lambda: _slow_addr(release)
        task = asyncio.create_task(resolver.resolve())
        await asyncio.sleep(0.05)
        resolver.invalidate()
        release.set()
        assert await task is None
        assert resolver.address is None
        await _release_worker()

    asyncio.run(scenario())


def test_fxu09_invalidation_after_refused_connect():
    async def scenario():
        target, tport = await _start_target(_echo_target)
        probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        dead_port = probe.sockets[0].getsockname()[1]
        probe.close()
        await probe.wait_closed()
        calls = {"n": 0}

        def lookup():
            calls["n"] += 1
            if calls["n"] == 1:
                return ("127.0.0.1", dead_port)
            return ("127.0.0.1", tport)

        resolver = forwarder._TargetResolver("keycloak", tport, resolve_timeout=1.0)
        resolver._lookup = lookup
        opened = await forwarder._open_target(resolver)
        assert opened is not None
        assert resolver.address == ("127.0.0.1", tport)
        _, writer = opened
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu10_all_attempts_fail_dns_bounded():
    async def scenario():
        resolver = forwarder._TargetResolver("keycloak", 8443, resolve_timeout=0.1)
        resolver._lookup = lambda: None
        start = time.monotonic()
        assert await forwarder._open_target(resolver) is None
        assert time.monotonic() - start < 3.0

    asyncio.run(scenario())


def test_fxu11_cancel_during_dns():
    async def scenario():
        release = threading.Event()
        resolver = forwarder._TargetResolver("keycloak", 8443, resolve_timeout=2.0)
        resolver._lookup = lambda: _slow_addr(release)
        task = asyncio.create_task(resolver.resolve())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        release.set()
        await _release_worker()
        assert resolver.address is None

    asyncio.run(scenario())


@pytest.mark.parametrize("value", ["0", "-1", "nan", "inf", "not-a-number"])
def test_fxu12_invalid_resolve_timeout_rejected(value):
    env = dict(os.environ)
    env["MTMF_DEV_FORWARDER_RESOLVE_TIMEOUT"] = value
    result = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert "finite positive" in result.stderr


def test_fxu13_no_data_no_target_connection(monkeypatch):
    async def scenario():
        target, tport = await _start_target(_echo_target)
        resolver = _CountingResolver(("127.0.0.1", tport))
        monkeypatch.setattr(forwarder, "FIRST_BYTE_TIMEOUT_SECONDS", 0.2)
        async with _Harness(resolver) as harness:
            reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            data = await asyncio.wait_for(reader.read(), timeout=2)
            assert data == b""
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            assert resolver.calls == 0
            assert all(task.done() for task in harness.tasks)
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu14_bidirectional_and_all_tasks_done():
    async def scenario():
        target, tport = await _start_target(_echo_target)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            payload = b"bidirectional" * 2000
            assert await _echo_roundtrip(harness.port, payload) == payload
            await asyncio.sleep(0.05)
            assert all(task.done() for task in harness.tasks)
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu15_half_close_response_within_grace():
    async def scenario():
        async def read_all_then_reply(reader, writer):
            await reader.read()
            await writer.drain()
            writer.write(b"tail")
            await writer.drain()
            writer.close()

        target, tport = await _start_target(read_all_then_reply)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.write(b"req")
            await writer.drain()
            writer.write_eof()
            assert await asyncio.wait_for(reader.read(), timeout=3) == b"tail"
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            await asyncio.sleep(0.05)
            assert all(task.done() for task in harness.tasks)
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu16_target_closes_first_tasks_joined():
    async def scenario():
        async def send_then_close(reader, writer):
            await reader.read(1024)
            writer.write(b"bye")
            await writer.drain()
            writer.close()

        target, tport = await _start_target(send_then_close)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            assert await _send_and_read_eof(harness.port, b"x") == b"bye"
            await asyncio.sleep(0.05)
            assert all(task.done() for task in harness.tasks)
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu17_client_reset_listener_survives():
    async def scenario():
        target, tport = await _start_target(_echo_target)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            _reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.write(b"data")
            await writer.drain()
            writer.transport.abort()  # type: ignore[attr-defined]
            await asyncio.sleep(0.1)
            assert harness.server is not None and harness.server.is_serving()
            assert await _echo_roundtrip(harness.port, b"ok") == b"ok"
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu18_target_connect_failure_after_first_bytes():
    async def scenario():
        probe = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        dead_port = probe.sockets[0].getsockname()[1]
        probe.close()
        await probe.wait_closed()
        resolver = forwarder._TargetResolver("127.0.0.1", dead_port, resolve_timeout=0.2)
        async with _Harness(resolver) as harness:
            assert await _send_and_read_eof(harness.port, b"data") == b""
            await asyncio.sleep(0.05)
            assert all(task.done() for task in harness.tasks)

    asyncio.run(scenario())


def test_fxu19_cancel_while_waiting_first_completed():
    async def scenario():
        target, tport = await _start_target(_echo_target)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            _reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.write(b"start")
            await writer.drain()
            await asyncio.sleep(0.05)
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


def test_fxu20_cancel_during_drain_window():
    async def scenario():
        gate = asyncio.Event()

        async def delayed_reply(reader, writer):
            await reader.read()
            await gate.wait()
            writer.write(b"late")
            await writer.drain()
            writer.close()

        target, tport = await _start_target(delayed_reply)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            writer = (await asyncio.open_connection("127.0.0.1", harness.port))[1]
            writer.write(b"req")
            await writer.drain()
            writer.write_eof()
            await asyncio.sleep(0.05)
            harness.tasks[0].cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await harness.tasks[0]
            assert harness.tasks[0].done()
            gate.set()
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu21_cancel_while_pump_blocked_in_drain():
    async def scenario():
        async def flood(reader, writer):
            await reader.read(1024)
            chunk = b"z" * 65536
            for _ in range(200):
                writer.write(chunk)
                await writer.drain()
            writer.close()

        target, tport = await _start_target(flood)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            _reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.write(b"go")
            await writer.drain()
            await asyncio.sleep(0.1)
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


def test_fxu22_cancel_during_writer_wait_closed(monkeypatch):
    async def scenario():
        target, tport = await _start_target(_echo_target)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        closing = asyncio.Event()
        original_close = forwarder._close_writer

        async def slow_close(writer):
            await closing.wait()
            await original_close(writer)

        monkeypatch.setattr(forwarder, "_close_writer", slow_close)
        async with _Harness(resolver) as harness:
            _reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
            writer.write(b"x")
            await writer.drain()
            await asyncio.sleep(0.05)
            harness.tasks[0].cancel()
            await asyncio.sleep(0.05)
            closing.set()
            with contextlib.suppress(asyncio.CancelledError):
                await harness.tasks[0]
            assert harness.tasks[0].done()
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu23_pump_oserror_listener_usable(monkeypatch):
    async def scenario():
        calls = {"n": 0}
        original_pipe = forwarder._pipe

        async def flaky_pipe(reader, writer):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OSError("simulated disconnect")
            await original_pipe(reader, writer)

        monkeypatch.setattr(forwarder, "_pipe", flaky_pipe)
        target, tport = await _start_target(_echo_target)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            writer = (await asyncio.open_connection("127.0.0.1", harness.port))[1]
            writer.write(b"x")
            await writer.drain()
            await asyncio.sleep(0.1)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            assert harness.server is not None and harness.server.is_serving()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())


def test_fxu24_unexpected_pump_exception_surfaced(monkeypatch, capsys):
    async def scenario():
        async def bad_pipe(_reader, _writer):
            raise RuntimeError("programming defect")

        monkeypatch.setattr(forwarder, "_pipe", bad_pipe)
        target, tport = await _start_target(_echo_target)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            writer = (await asyncio.open_connection("127.0.0.1", harness.port))[1]
            writer.write(b"x")
            await writer.drain()
            await asyncio.sleep(0.1)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())
    captured = capsys.readouterr()
    assert "unexpected pump error (RuntimeError)" in captured.err


def test_fxu25_cleanup_budget_bounded():
    async def scenario():
        class _SlowWriter:
            def close(self):
                return None

            async def wait_closed(self):
                await asyncio.sleep(1.0)

        tasks = {asyncio.ensure_future(asyncio.sleep(100))}
        start = time.monotonic()
        await asyncio.wait_for(
            forwarder._finish_cleanup(tasks, _SlowWriter(), _SlowWriter()), timeout=3.0
        )
        assert time.monotonic() - start < 3.0
        for task in tasks:
            if not task.done():
                task.cancel()

    asyncio.run(scenario())


def test_fxu26_fifty_handler_cancellations_no_growth():
    async def scenario():
        target, tport = await _start_target(_echo_target)
        resolver = forwarder._TargetResolver("127.0.0.1", tport)
        async with _Harness(resolver) as harness:
            baseline = len(asyncio.all_tasks())
            for _ in range(50):
                _reader, writer = await asyncio.open_connection("127.0.0.1", harness.port)
                writer.write(b"x")
                await writer.drain()
                await asyncio.sleep(0)
                assert harness.tasks
                task = harness.tasks[-1]
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            await asyncio.sleep(0.1)
            assert len(asyncio.all_tasks()) <= baseline + 2
        target.close()
        await target.wait_closed()

    asyncio.run(scenario())
