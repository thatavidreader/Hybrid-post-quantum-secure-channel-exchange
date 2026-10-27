"""Record layer: framing + AES-256-GCM + sequence numbers + replay checks.

Frame on the wire:   [4B len][8B seq][ciphertext || 16B GCM tag]
    len  = number of bytes after the length field (8 + len(ciphertext+tag))
    seq  = explicit 64-bit big-endian counter, per direction, starting at 0
    nonce= 4-byte per-direction prefix (from HKDF) || seq   (12 bytes, unique per record)
    AAD  = "PQSC1 record" || direction || seq

WHY an explicit seq in the frame AND in the nonce/AAD: the receiver can tell a
replay (old seq) from a drop (future seq) from tampering (tag failure), and an
attacker cannot rewrite the seq field without breaking the tag.

Receiver classification (see `RecordReceiver.open`):
    1. authenticate the frame under its CLAIMED seq   -> fail  => BAD_TAG
    2. seq <  expected                                 => REPLAY_DETECTED
    3. seq >  expected                                 => SEQ_GAP
    4. seq == expected                                 => accept, expected += 1
Authenticating first means a record is only called a "replay" if it is a genuine,
previously valid record - not a forged one with a lowered counter (that is BAD_TAG).
Any error is fatal: the caller must close the connection (fail closed).
"""
from __future__ import annotations

import socket
import struct

from cryptography.exceptions import InvalidTag

from . import crypto_suite as cs
from .wire import ConnectionClosed, recv_exact

MAX_PLAINTEXT = 16 * 1024
TAG_LEN = 16
SEQ_LEN = 8
LEN_LEN = 4
MAX_BODY = SEQ_LEN + MAX_PLAINTEXT + TAG_LEN
MAX_SEQ = (1 << 64) - 1

C2S, S2C = b"c2s", b"s2c"


class RecordError(Exception):
    """Fatal record-layer error. `event` is the JSON-lines event name."""

    event = "RECORD_ERROR"


class BadTag(RecordError):
    event = "BAD_TAG"


class ReplayDetected(RecordError):
    event = "REPLAY_DETECTED"


class SeqGap(RecordError):
    event = "SEQ_GAP"


def _nonce(iv: bytes, seq: int) -> bytes:
    return iv + struct.pack("!Q", seq)


def _aad(direction: bytes, seq: int) -> bytes:
    return cs.PROTOCOL_LABEL + b" record" + direction + struct.pack("!Q", seq)


class RecordSender:
    def __init__(self, key: bytes, iv: bytes, direction: bytes) -> None:
        self._key, self._iv, self._dir = key, iv, direction
        self.seq = 0

    def seal(self, plaintext: bytes) -> bytes:
        """Encrypt one record and return the complete frame (incl. length prefix)."""
        if len(plaintext) > MAX_PLAINTEXT:
            raise ValueError("record too large; chunk first")
        if self.seq >= MAX_SEQ:
            raise RecordError("sequence space exhausted; rekey required")
        ct = cs.aead_encrypt(self._key, _nonce(self._iv, self.seq), plaintext, _aad(self._dir, self.seq))
        body = struct.pack("!Q", self.seq) + ct
        self.seq += 1
        return struct.pack("!I", len(body)) + body


class RecordReceiver:
    def __init__(self, key: bytes, iv: bytes, direction: bytes) -> None:
        self._key, self._iv, self._dir = key, iv, direction
        self.expected = 0

    def open(self, body: bytes) -> bytes:
        """Verify + decrypt a frame body (everything after the length prefix)."""
        if len(body) < SEQ_LEN + TAG_LEN:
            raise BadTag("frame too short")
        (seq,) = struct.unpack("!Q", body[:SEQ_LEN])
        try:
            pt = cs.aead_decrypt(self._key, _nonce(self._iv, seq), body[SEQ_LEN:], _aad(self._dir, seq))
        except InvalidTag as e:
            raise BadTag(f"GCM authentication failed (claimed seq={seq})") from e
        if seq < self.expected:
            raise ReplayDetected(f"authentic record seq={seq} already consumed (expected {self.expected})")
        if seq > self.expected:
            raise SeqGap(f"record seq={seq} but expected {self.expected}: records were dropped/reordered")
        self.expected += 1
        return pt


def read_frame_body(sock: socket.socket) -> bytes:
    """Read one length-prefixed frame body from the socket."""
    (length,) = struct.unpack("!I", recv_exact(sock, LEN_LEN))
    if length > MAX_BODY or length < SEQ_LEN + TAG_LEN:
        raise BadTag(f"illegal frame length {length}")
    return recv_exact(sock, length)


class SecureChannel:
    """Encrypted, ordered, replay-protected message channel over a connected socket.

    `role` is "client" or "server" and decides which directional key is used for
    sending vs receiving (reflection protection: a record echoed back at its
    sender fails authentication because the direction differs).
    """

    def __init__(self, sock: socket.socket, keys: cs.SessionKeys, role: str) -> None:
        self.sock = sock
        if role == "client":
            self._tx = RecordSender(keys.c2s_key, keys.c2s_iv, C2S)
            self._rx = RecordReceiver(keys.s2c_key, keys.s2c_iv, S2C)
        else:
            self._tx = RecordSender(keys.s2c_key, keys.s2c_iv, S2C)
            self._rx = RecordReceiver(keys.c2s_key, keys.c2s_iv, C2S)

    def send(self, data: bytes) -> None:
        """Send `data`, split into <=16 KiB records."""
        for i in range(0, max(len(data), 1), MAX_PLAINTEXT):
            self.sock.sendall(self._tx.seal(data[i:i + MAX_PLAINTEXT]))

    def recv(self) -> bytes:
        """Receive exactly one record's plaintext. Raises RecordError / ConnectionClosed."""
        return self._rx.open(read_frame_body(self.sock))

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


__all__ = ["SecureChannel", "RecordSender", "RecordReceiver", "RecordError", "BadTag",
           "ReplayDetected", "SeqGap", "ConnectionClosed", "MAX_PLAINTEXT", "C2S", "S2C"]
