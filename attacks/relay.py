"""Frame-aware man-in-the-middle TCP relay (building block for the attack scripts).

The relay sits between client and server and parses our two frame formats so an
attack hook can modify, drop or duplicate individual frames:

    handshake frame:  [1B type][4B len][payload]   (first 2 frames per direction)
    record frame:     [4B len][8B seq][ct+tag]     (everything after)

It is an *active network attacker* model (Dolev-Yao style) used ONLY against our
own server on localhost, to demonstrate that the defences work.
"""
from __future__ import annotations

import socket
import struct
import threading
from dataclasses import dataclass
from typing import Callable

from src.wire import ALERT, HS_HEADER_LEN, MAX_HS_PAYLOAD, ConnectionClosed, recv_exact


@dataclass
class Frame:
    kind: str            # "hs" or "rec"
    data: bytes          # hs: payload ; rec: body (seq || ct || tag)
    msg_type: int = 0    # hs only
    index: int = 0       # position among frames of this kind in this direction (0-based)

    def encode(self) -> bytes:
        if self.kind == "hs":
            return struct.pack("!BI", self.msg_type, len(self.data)) + self.data
        return struct.pack("!I", len(self.data)) + self.data


Hook = Callable[[Frame], "list[Frame]"]


def passthrough(frame: Frame) -> list[Frame]:
    return [frame]


class MitmProxy:
    def __init__(self, upstream: tuple[str, int], c2s: Hook = passthrough, s2c: Hook = passthrough,
                 host: str = "127.0.0.1", port: int = 0) -> None:
        self.upstream, self.c2s, self.s2c = upstream, c2s, s2c
        self.host, self.port = host, port
        self.trace: list[str] = []           # human-readable record of what the attacker did
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, self.port))
        s.listen(16)
        self.port = s.getsockname()[1]
        self._sock = s
        threading.Thread(target=self._accept, daemon=True, name="mitm-accept").start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _accept(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                return
            try:
                server = socket.create_connection(self.upstream)
            except OSError:
                client.close()
                continue
            for s in (client, server):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            threading.Thread(target=self._pump, args=(client, server, self.c2s), daemon=True).start()
            threading.Thread(target=self._pump, args=(server, client, self.s2c), daemon=True).start()

    @staticmethod
    def _read_frames(src: socket.socket):
        """Yield Frames from `src`: 2 handshake frames (or fewer if ALERT), then records."""
        hs_seen = rec_seen = 0
        while True:
            if hs_seen < 2:
                t, length = struct.unpack("!BI", recv_exact(src, HS_HEADER_LEN))
                if length > MAX_HS_PAYLOAD:
                    raise ConnectionClosed("oversize")
                yield Frame("hs", recv_exact(src, length), t, hs_seen)
                hs_seen = 2 if t == ALERT else hs_seen + 1
            else:
                (length,) = struct.unpack("!I", recv_exact(src, 4))
                if length > 1 << 20:
                    raise ConnectionClosed("oversize")
                yield Frame("rec", recv_exact(src, length), 0, rec_seen)
                rec_seen += 1

    def _pump(self, src: socket.socket, dst: socket.socket, hook: Hook) -> None:
        try:
            for frame in self._read_frames(src):
                for out in hook(frame):
                    dst.sendall(out.encode())
        except (ConnectionClosed, OSError):
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass
