"""Single-request private AF_UNIX transport with SO_PEERCRED gating."""

from __future__ import annotations

import socket
import struct
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .protocol import (
    MAX_ADMISSION_FRAME,
    MAX_OPERATOR_FRAME,
    ProtocolError,
    decode_frame,
    encode_frame,
)

__all__ = ["serve_once"]

_DEADLINE_SECONDS = 5


def serve_once(
    socket_path: Path,
    *,
    allowed_peer_uid: int,
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    admission: bool = False,
) -> None:
    """Accept exactly one authorized peer, one frame, and return one response."""
    path = Path(socket_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        server.listen(1)
        server.settimeout(_DEADLINE_SECONDS)
        connection, _ = server.accept()
        with connection:
            connection.settimeout(_DEADLINE_SECONDS)
            peer_uid = _peer_uid(connection)
            if peer_uid != allowed_peer_uid:
                return
            frame = _read_frame(
                connection, MAX_ADMISSION_FRAME if admission else MAX_OPERATOR_FRAME
            )
            try:
                payload = decode_frame(frame, admission=admission)
                response = handler(payload)
            except ProtocolError:
                response = {"v": 1, "error": "INVALID"}
            except Exception:
                response = {"v": 1, "error": "UNAVAILABLE"}
            connection.sendall(encode_frame(response))
    finally:
        server.close()
        if path.exists():
            path.unlink()


def _peer_uid(connection: socket.socket) -> int:
    creds = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return int(uid)


def _read_frame(connection: socket.socket, limit: int) -> bytes:
    header = _read_exact(connection, 4)
    length = struct.unpack(">I", header)[0]
    if length == 0 or length + 4 > limit:
        raise ProtocolError("invalid frame length")
    return header + _read_exact(connection, length)


def _read_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise ProtocolError("connection closed mid-frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
