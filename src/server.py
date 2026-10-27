"""Threaded TCP server: runs the handshake, then a tiny application protocol.

Application protocol (inside encrypted records; first byte = opcode):
    ECHO  -> server replies ECHO with the same payload      (round-trip / latency tests)
    SINK  -> server discards payload, counts bytes          (throughput tests)
    DONE  -> server replies DONE + 8-byte total counted     (end of an upload)
    BYE   -> close
Any record-layer error (bad tag / replay / gap) is logged and the connection is
closed immediately: after an integrity failure the stream state cannot be trusted.
"""
from __future__ import annotations

import argparse
import socket
import struct
import threading
from typing import Iterable

from . import crypto_suite as cs
from .crypto_suite import Mode, ServerIdentity
from .handshake import HandshakeError, ServerHandshake
from .logger import SecurityLogger
from .record_layer import RecordError, SecureChannel
from .wire import (ALERT, CLIENT_FINISHED, CLIENT_HELLO, SERVER_FINISHED, SERVER_HELLO,
                   ConnectionClosed, recv_msg, send_msg, tune)

OP_ECHO, OP_SINK, OP_DONE, OP_BYE = 1, 2, 3, 4


class SecureServer:
    def __init__(self, identity: ServerIdentity, host: str = "127.0.0.1", port: int = 0,
                 modes: Iterable[Mode] = cs.ALL_MODES, logger: SecurityLogger | None = None,
                 timeout: float = 60.0) -> None:
        self.identity = identity
        self.host, self.port = host, port
        self.modes = tuple(modes)
        self.logger = logger or SecurityLogger("server")
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._conns: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ---- lifecycle
    def start(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(64)
        self.port = s.getsockname()[1]
        self._sock = s
        threading.Thread(target=self._accept_loop, daemon=True, name="server-accept").start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        with self._lock:
            for c in list(self._conns):
                try:
                    c.close()
                except OSError:
                    pass

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except OSError:
                return
            with self._lock:
                self._conns.add(conn)
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()

    # ---- one connection
    def _serve(self, conn: socket.socket, addr: tuple) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        try:
            tune(conn)
            conn.settimeout(self.timeout)
            hs = self._handshake(conn, peer)
            if hs is None:
                return
            self._app_loop(conn, peer, hs)
        except OSError:
            pass  # peer vanished; nothing more to do
        finally:
            with self._lock:
                self._conns.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _handshake(self, conn: socket.socket, peer: str) -> ServerHandshake | None:
        hs = ServerHandshake(self.identity, self.modes)
        try:
            t, payload, _ = recv_msg(conn)
            if t != CLIENT_HELLO:
                raise HandshakeError("expected ClientHello")
            send_msg(conn, SERVER_HELLO, hs.handle_client_hello(payload))
            t, payload, _ = recv_msg(conn)
            if t != CLIENT_FINISHED:
                raise HandshakeError("expected ClientFinished")
            send_msg(conn, SERVER_FINISHED, hs.handle_client_finished(payload))
        except HandshakeError as e:
            self.logger.log(e.event, peer, hs.mode.value if hs.mode else None, reason=str(e))
            try:  # generic alert only: do not leak why to a possible attacker
                send_msg(conn, ALERT, b'{"v":1,"reason":"handshake_failure"}')
            except OSError:
                pass
            return None
        except (ConnectionClosed, OSError) as e:
            self.logger.log("HANDSHAKE_FAIL", peer, None, reason=f"connection error: {e}")
            return None
        assert hs.mode is not None
        self.logger.log("HANDSHAKE_OK", peer, hs.mode.value,
                        raw_bytes_sent=hs.sizes.raw_sent, raw_bytes_recv=hs.sizes.raw_recv)
        return hs

    def _app_loop(self, conn: socket.socket, peer: str, hs: ServerHandshake) -> None:
        assert hs.keys is not None and hs.mode is not None
        ch = SecureChannel(conn, hs.keys, "server")
        total = 0
        while True:
            try:
                msg = ch.recv()
            except RecordError as e:
                self.logger.log(e.event, peer, hs.mode.value, reason=str(e))
                return
            except ConnectionClosed:
                return
            op, data = (msg[0], msg[1:]) if msg else (None, b"")
            if op == OP_ECHO:
                ch.send(bytes([OP_ECHO]) + data)
            elif op == OP_SINK:
                total += len(data)
            elif op == OP_DONE:
                ch.send(bytes([OP_DONE]) + struct.pack("!Q", total))
                total = 0
            else:  # BYE or unknown opcode
                return


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Hybrid PQ secure channel server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--modes", default="classical,pqc,hybrid", help="comma-separated supported modes")
    ap.add_argument("--key-dir", default="keys")
    ap.add_argument("--log", default="results/server.log.jsonl")
    a = ap.parse_args(argv)
    ident = ServerIdentity.load_or_create(a.key_dir)
    srv = SecureServer(ident, a.host, a.port, [Mode(m) for m in a.modes.split(",")],
                       SecurityLogger("server", a.log))
    srv.start()
    print(f"server listening on {a.host}:{srv.port}  modes={a.modes}  kem-backend={cs.backend_name()}")
    print(f"pin this key in clients ({a.key_dir}/server_ed25519.pub): {ident.public_raw.hex()}")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()
