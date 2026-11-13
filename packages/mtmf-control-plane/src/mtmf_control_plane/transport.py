"""Private AF_UNIX transport with exact SO_PEERCRED gating."""

from __future__ import annotations

import os
import socket
import stat
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

__all__ = ["serve_forever"]

_DEADLINE_SECONDS = 5


def serve_forever(
    socket_path: Path,
    *,
    allowed_peer_uid: int,
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    admission: bool = False,
    max_connections: int | None = None,
) -> None:
    """Serve one frame per connection on an owned AF_UNIX socket.

    An existing path is never unlinked: startup fails closed unless the path is
    a socket owned by the current effective UID. The caller is responsible for
    the approved directory owner/group/mode; this function sets the socket mode
    to ``0660`` and rejects unknown peers before reading a frame.
    """
    path = Path(socket_path)
    if path.exists():
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid():
            raise RuntimeError("refusing to replace an unknown or foreign socket path")
        if max_connections is None:
            raise RuntimeError("worker socket already exists; fail closed")
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(path))
        path.chmod(0o660)
        server.listen(8)
        server.settimeout(_DEADLINE_SECONDS)
        served = 0
        while max_connections is None or served < max_connections:
            try:
                connection, _ = server.accept()
            except TimeoutError:
                if max_connections is not None:
                    break
                continue
            served += 1
            _serve_connection(
                connection,
                allowed_peer_uid=allowed_peer_uid,
                handler=handler,
                admission=admission,
            )
    finally:
        server.close()
        if path.exists():
            info = path.lstat()
            if stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid():
                path.unlink()


def _serve_connection(
    connection: socket.socket,
    *,
    allowed_peer_uid: int,
    handler: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    admission: bool,
) -> None:
    with connection:
        connection.settimeout(_DEADLINE_SECONDS)
        if _peer_uid(connection) != allowed_peer_uid:
            return
        try:
            frame = _read_frame(
                connection, MAX_ADMISSION_FRAME if admission else MAX_OPERATOR_FRAME
            )
            payload = decode_frame(frame, admission=admission)
            response = handler(payload)
            encoded = encode_frame(response, admission=admission)
        except ProtocolError:
            encoded = encode_frame({"v": 1, "error": "INVALID"}, admission=admission)
        except Exception:
            encoded = encode_frame({"v": 1, "error": "UNAVAILABLE"}, admission=admission)
        connection.sendall(encoded)


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
