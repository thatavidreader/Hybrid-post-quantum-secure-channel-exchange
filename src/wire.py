"""Socket helpers shared by handshake and record layer.

Handshake message framing:  [1B type][4B big-endian length][payload]
(Record frames use a different, sequence-numbered format; see record_layer.py.)
"""
from __future__ import annotations

import socket
import struct

HS_HEADER_LEN = 5
MAX_HS_PAYLOAD = 64 * 1024  # a hybrid ClientHello is ~2.3 KB; cap to stop memory abuse

CLIENT_HELLO, SERVER_HELLO, CLIENT_FINISHED, SERVER_FINISHED, ALERT = 1, 2, 3, 4, 5


class ConnectionClosed(Exception):
    """Peer closed (or reset) the TCP connection."""


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes (TCP is a byte stream; recv may return less)."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (ConnectionResetError, ConnectionAbortedError) as e:
            raise ConnectionClosed(str(e)) from e
        if not chunk:
            raise ConnectionClosed("peer closed connection")
        buf += chunk
    return bytes(buf)


def send_msg(sock: socket.socket, msg_type: int, payload: bytes) -> int:
    """Send one handshake message; returns bytes put on the wire."""
    frame = struct.pack("!BI", msg_type, len(payload)) + payload
    sock.sendall(frame)
    return len(frame)


def recv_msg(sock: socket.socket) -> tuple[int, bytes, int]:
    """Receive one handshake message -> (type, payload, wire_bytes)."""
    hdr = recv_exact(sock, HS_HEADER_LEN)
    msg_type, length = struct.unpack("!BI", hdr)
    if length > MAX_HS_PAYLOAD:
        raise ConnectionClosed(f"handshake message too large ({length})")
    return msg_type, recv_exact(sock, length), HS_HEADER_LEN + length


def tune(sock: socket.socket) -> None:
    """Disable Nagle: small handshake messages must not wait for coalescing,
    otherwise latency benchmarks would measure the Nagle timer, not the protocol."""
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
