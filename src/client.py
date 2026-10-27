"""Client: connects, runs the handshake with a downgrade policy, exposes a Session."""
from __future__ import annotations

import argparse
import socket
import struct
import time
from dataclasses import dataclass
from typing import Iterable

from . import crypto_suite as cs
from .crypto_suite import Mode
from .handshake import ClientHandshake, HandshakeError
from .logger import SecurityLogger
from .record_layer import MAX_PLAINTEXT, RecordError, SecureChannel
from .server import OP_BYE, OP_DONE, OP_ECHO, OP_SINK
from .wire import (ALERT, CLIENT_FINISHED, CLIENT_HELLO, SERVER_FINISHED, SERVER_HELLO,
                   ConnectionClosed, recv_msg, send_msg, tune)

_CHUNK = MAX_PLAINTEXT - 1  # one byte of every record is the opcode


@dataclass
class Session:
    channel: SecureChannel
    mode: Mode
    peer: str
    logger: SecurityLogger
    handshake_seconds: float
    wire_bytes_sent: int      # handshake bytes incl. JSON/base64/framing
    wire_bytes_recv: int
    raw_bytes_sent: int       # only keys/ciphertexts/signature/nonces/MACs
    raw_bytes_recv: int

    def _recv(self) -> bytes:
        try:
            return self.channel.recv()
        except RecordError as e:
            self.logger.log(e.event, self.peer, self.mode.value, reason=str(e))
            raise

    def echo(self, data: bytes) -> bytes:
        """Round-trip `data` through the server (chunked to the record size)."""
        out = bytearray()
        for i in range(0, max(len(data), 1), _CHUNK):
            self.channel.send(bytes([OP_ECHO]) + data[i:i + _CHUNK])
            reply = self._recv()
            assert reply[:1] == bytes([OP_ECHO])
            out += reply[1:]
        return bytes(out)

    def upload(self, nbytes: int) -> int:
        """Send `nbytes` of dummy data, return the count the server confirms."""
        block = bytes([OP_SINK]) + b"\xa5" * _CHUNK
        sent = 0
        while sent < nbytes:
            n = min(_CHUNK, nbytes - sent)
            self.channel.send(block if n == _CHUNK else bytes([OP_SINK]) + b"\xa5" * n)
            sent += n
        self.channel.send(bytes([OP_DONE]))
        reply = self._recv()
        return struct.unpack("!Q", reply[1:9])[0]

    def close(self) -> None:
        try:
            self.channel.send(bytes([OP_BYE]))
        except OSError:
            pass
        self.channel.close()


class SecureClient:
    def __init__(self, pinned_server_key: bytes, min_mode: Mode | None = None,
                 offered_modes: Iterable[Mode] = cs.ALL_MODES,
                 logger: SecurityLogger | None = None, timeout: float = 60.0) -> None:
        self.pinned = pinned_server_key
        self.min_mode = min_mode
        self.offered = tuple(offered_modes)
        self.logger = logger or SecurityLogger("client")
        self.timeout = timeout

    def connect(self, host: str, port: int) -> Session:
        peer = f"{host}:{port}"
        sock = socket.create_connection((host, port), timeout=self.timeout)
        tune(sock)
        hs = ClientHandshake(self.pinned, self.offered, self.min_mode)
        sent = recvd = 0
        t0 = time.perf_counter()
        try:
            sent += send_msg(sock, CLIENT_HELLO, hs.make_client_hello())
            t, payload, n = recv_msg(sock)
            recvd += n
            if t == ALERT:
                raise HandshakeError("server sent handshake_failure alert")
            if t != SERVER_HELLO:
                raise HandshakeError("expected ServerHello")
            sent += send_msg(sock, CLIENT_FINISHED, hs.handle_server_hello(payload))
            t, payload, n = recv_msg(sock)
            recvd += n
            if t != SERVER_FINISHED:
                raise HandshakeError("expected ServerFinished")
            hs.handle_server_finished(payload)
        except HandshakeError as e:
            self.logger.log(e.event, peer, hs.mode.value if hs.mode else None, reason=str(e))
            sock.close()
            raise
        except (ConnectionClosed, OSError) as e:  # includes socket.timeout
            self.logger.log("HANDSHAKE_FAIL", peer, None, reason=f"connection error: {e}")
            sock.close()
            raise HandshakeError(f"connection error: {e}") from e
        elapsed = time.perf_counter() - t0
        assert hs.mode is not None and hs.keys is not None
        self.logger.log("HANDSHAKE_OK", peer, hs.mode.value, handshake_ms=round(elapsed * 1e3, 3),
                        wire_bytes_sent=sent, wire_bytes_recv=recvd)
        return Session(SecureChannel(sock, hs.keys, "client"), hs.mode, peer, self.logger, elapsed,
                       sent, recvd, hs.sizes.raw_sent, hs.sizes.raw_recv)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Hybrid PQ secure channel client")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--pin", default="keys/server_ed25519.pub", help="file with the server's hex Ed25519 key")
    ap.add_argument("--min-mode", choices=[m.value for m in cs.ALL_MODES], default=None)
    ap.add_argument("--offer", default="classical,pqc,hybrid")
    ap.add_argument("--message", default="hello over a post-quantum channel")
    ap.add_argument("--log", default="results/client.log.jsonl")
    a = ap.parse_args(argv)
    client = SecureClient(cs.load_pinned_key(a.pin), Mode(a.min_mode) if a.min_mode else None,
                          [Mode(m) for m in a.offer.split(",")], SecurityLogger("client", a.log))
    try:
        s = client.connect(a.host, a.port)
    except HandshakeError as e:
        print(f"connection aborted: {e}")
        return 1
    reply = s.echo(a.message.encode())
    print(f"mode={s.mode.value} backend={cs.backend_name()} handshake={s.handshake_seconds*1e3:.1f} ms "
          f"echo={reply.decode()!r}")
    s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
