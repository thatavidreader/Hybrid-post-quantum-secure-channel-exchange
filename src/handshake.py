"""Handshake state machines (sans-IO: they consume/produce bytes, no sockets).

Flow
----
    Client                                   Server
    ClientHello  ------------------------->
                 <-------------------------  ServerHello (+ Ed25519 signature)
    ClientFinished ----------------------->
                 <-------------------------  ServerFinished

Messages are canonical JSON (sorted keys, no whitespace, base64 for binary).
JSON costs bytes on the wire; we report both *raw* payload bytes and *wire* bytes
so the overhead is visible. It is chosen for viva-readability, not efficiency.

Security argument (short)
-------------------------
* The server signs H(ClientHello || ServerHello-without-signature), where the
  ClientHello is the EXACT byte string the server received. The client verifies
  that signature over the ClientHello IT SENT. If a MITM edited the ClientHello
  (e.g. stripped hybrid), the two byte strings differ => signature check fails.
* The signature key is PINNED by the client (no CA), so a forged ServerHello
  cannot verify.
* Session keys come from HKDF with the transcript hash as salt, and both sides
  exchange Finished MACs under keys derived from it: a final, independent check
  that both ends saw the same transcript and derived the same keys.
* Client policy `min_mode` gives an additional, signature-independent defence.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import crypto_suite as cs
from .crypto_suite import Mode

VERSION = 1
NONCE_LEN = 32
SIG_LABEL = cs.PROTOCOL_LABEL + b" server signature\x00"


# --------------------------------------------------------------------------- errors
class HandshakeError(Exception):
    """Generic handshake failure. `event` is the JSON-lines event it maps to."""

    event = "HANDSHAKE_FAIL"


class DowngradeDetected(HandshakeError):
    event = "DOWNGRADE_DETECTED"


class SignatureInvalid(HandshakeError):
    event = "SIG_INVALID"


# --------------------------------------------------------------------------- encoding
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: Any, expect_len: int | None = None, field_name: str = "field") -> bytes:
    if not isinstance(s, str):
        raise HandshakeError(f"{field_name}: expected base64 string")
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as e:
        raise HandshakeError(f"{field_name}: bad base64") from e
    if expect_len is not None and len(b) != expect_len:
        raise HandshakeError(f"{field_name}: expected {expect_len} bytes, got {len(b)}")
    return b


def canonical(obj: dict) -> bytes:
    """Deterministic JSON: both sides must serialise identically to hash/sign it."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _parse(payload: bytes, what: str) -> dict:
    try:
        obj = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as e:
        raise HandshakeError(f"{what}: malformed JSON") from e
    if not isinstance(obj, dict) or obj.get("v") != VERSION:
        raise HandshakeError(f"{what}: bad structure/version")
    return obj


def _transcript_hash(client_hello: bytes, server_hello_body: bytes) -> bytes:
    return cs.sha256(client_hello + server_hello_body)


def _full_transcript_hash(client_hello: bytes, server_hello_full: bytes) -> bytes:
    """Hash used by the Finished MACs; includes the signature too."""
    return cs.sha256(client_hello + server_hello_full)


def _finished_mac(key: bytes, who: bytes, th: bytes) -> bytes:
    return hmac.new(key, cs.PROTOCOL_LABEL + b" finished " + who + th, "sha256").digest()


@dataclass
class SizeCounter:
    """Raw = only cryptographic bytes (keys, ciphertext, signature, nonces, MACs).
    Wire = actual bytes sent incl. JSON/base64/framing; computed by the I/O layer."""

    raw_sent: int = 0
    raw_recv: int = 0


# --------------------------------------------------------------------------- client
@dataclass
class ClientHandshake:
    """Client side. `pinned_server_key` is the raw 32-byte Ed25519 public key."""

    pinned_server_key: bytes
    offered_modes: Iterable[Mode] = cs.ALL_MODES
    min_mode: Mode | None = None
    kem: cs.MLKEM = field(default_factory=cs.get_kem)

    mode: Mode | None = field(default=None, init=False)
    keys: cs.SessionKeys | None = field(default=None, init=False)
    sizes: SizeCounter = field(default_factory=SizeCounter, init=False)
    _ch: bytes = field(default=b"", init=False)
    _th_full: bytes = field(default=b"", init=False)

    def __post_init__(self) -> None:
        self.offered_modes = tuple(self.offered_modes)
        self._x_priv = None
        self._dk = None

    # -- message 1
    def make_client_hello(self) -> bytes:
        msg: dict[str, Any] = {
            "v": VERSION,
            "modes": [m.value for m in self.offered_modes],
            "nonce": _b64(os.urandom(NONCE_LEN)),
        }
        raw = NONCE_LEN
        if any(m.uses_x25519 for m in self.offered_modes):
            self._x_priv, xpub = cs.x25519_keygen()
            msg["x25519"] = _b64(xpub)
            raw += len(xpub)
        if any(m.uses_mlkem for m in self.offered_modes):
            ek, self._dk = self.kem.keygen()
            msg["mlkem"] = _b64(ek)
            raw += len(ek)
        self._ch = canonical(msg)
        self.sizes.raw_sent += raw
        return self._ch

    # -- message 2 -> 3
    def handle_server_hello(self, payload: bytes) -> bytes:
        """Validate ServerHello, derive keys, return ClientFinished payload.

        Check order is deliberate:
          1. structure, 2. mode was one we offered, 3. POLICY (min_mode),
          4. signature over transcript, 5. key agreement.
        Policy comes before the signature because it is cheap, local and
        fail-closed: a below-policy mode is rejected no matter who sent it.
        """
        sh = _parse(payload, "ServerHello")
        try:
            mode = Mode(sh.get("mode"))
        except ValueError as e:
            raise HandshakeError("ServerHello: unknown mode") from e
        if mode not in self.offered_modes:
            raise HandshakeError(f"ServerHello: mode {mode.value} was not offered")

        # (3) Downgrade policy
        if self.min_mode is not None and mode.rank < self.min_mode.rank:
            raise DowngradeDetected(
                f"server selected '{mode.value}' but policy requires at least '{self.min_mode.value}'"
            )

        # (4) Signature over the transcript the CLIENT believes happened.
        sig = _unb64(sh.get("sig"), 64, "sig")
        body = {k: v for k, v in sh.items() if k != "sig"}
        body_bytes = canonical(body)
        th = _transcript_hash(self._ch, body_bytes)
        if not cs.ed25519_verify(self.pinned_server_key, sig, SIG_LABEL + th):
            raise SignatureInvalid(
                "ServerHello signature does not verify under the pinned key over the "
                "transcript (wrong server key, or ClientHello/ServerHello altered in transit)"
            )
        self.sizes.raw_recv += NONCE_LEN + 64

        # (5) Key agreement for the chosen mode
        secrets: list[bytes] = []
        try:
            if mode.uses_x25519:
                spub = _unb64(sh.get("x25519"), 32, "server x25519")
                secrets.append(cs.x25519_shared(self._x_priv, spub))
                self.sizes.raw_recv += 32
            if mode.uses_mlkem:
                ct = _unb64(sh.get("mlkem_ct"), cs.MLKEM768_CT_LEN, "mlkem_ct")
                secrets.append(self.kem.decaps(self._dk, ct))
                self.sizes.raw_recv += len(ct)
        except HandshakeError:
            raise
        except Exception as e:  # e.g. X25519 low-order point
            raise HandshakeError(f"key agreement failed: {e}") from e

        self.mode = mode
        self.keys = cs.derive_session_keys(mode, secrets, th)
        self._th_full = _full_transcript_hash(self._ch, payload)
        mac = _finished_mac(self.keys.finished_c, b"client", self._th_full)
        self.sizes.raw_sent += len(mac)
        return canonical({"v": VERSION, "mac": _b64(mac)})

    # -- message 4
    def handle_server_finished(self, payload: bytes) -> None:
        assert self.keys is not None
        msg = _parse(payload, "ServerFinished")
        mac = _unb64(msg.get("mac"), 32, "mac")
        expected = _finished_mac(self.keys.finished_s, b"server", self._th_full)
        if not hmac.compare_digest(mac, expected):
            raise HandshakeError("ServerFinished MAC mismatch (transcript or key disagreement)")
        self.sizes.raw_recv += 32


# --------------------------------------------------------------------------- server
@dataclass
class ServerHandshake:
    identity: cs.ServerIdentity
    supported_modes: Iterable[Mode] = cs.ALL_MODES
    kem: cs.MLKEM = field(default_factory=cs.get_kem)

    mode: Mode | None = field(default=None, init=False)
    keys: cs.SessionKeys | None = field(default=None, init=False)
    sizes: SizeCounter = field(default_factory=SizeCounter, init=False)
    _th_full: bytes = field(default=b"", init=False)

    def __post_init__(self) -> None:
        self.supported_modes = tuple(self.supported_modes)

    def handle_client_hello(self, payload: bytes) -> bytes:
        """Pick the strongest mutually supported mode and answer with a signed ServerHello."""
        ch = _parse(payload, "ClientHello")
        nonce = _unb64(ch.get("nonce"), NONCE_LEN, "client nonce")
        raw_in = NONCE_LEN
        modes_raw = ch.get("modes")
        if not isinstance(modes_raw, list):
            raise HandshakeError("ClientHello: modes must be a list")
        known = {x.value for x in cs.ALL_MODES}
        offered = {Mode(m) for m in modes_raw if isinstance(m, str) and m in known}

        xpub = ekey = None
        if "x25519" in ch:
            xpub = _unb64(ch["x25519"], 32, "client x25519")
            raw_in += 32
        if "mlkem" in ch:
            ekey = _unb64(ch["mlkem"], cs.MLKEM768_EK_LEN, "client mlkem key")
            raw_in += len(ekey)

        mode = next(
            (m for m in cs.PREFERENCE
             if m in offered and m in self.supported_modes
             and (not m.uses_x25519 or xpub is not None)
             and (not m.uses_mlkem or ekey is not None)),
            None,
        )
        if mode is None:
            raise HandshakeError("no mutually supported mode")

        body: dict[str, Any] = {"v": VERSION, "mode": mode.value, "nonce": _b64(os.urandom(NONCE_LEN))}
        secrets: list[bytes] = []
        raw_out = NONCE_LEN + 64
        try:
            if mode.uses_x25519:
                priv, pub = cs.x25519_keygen()
                body["x25519"] = _b64(pub)
                secrets.append(cs.x25519_shared(priv, xpub))
                raw_out += 32
            if mode.uses_mlkem:
                ss, ct = self.kem.encaps(ekey)
                body["mlkem_ct"] = _b64(ct)
                secrets.append(ss)
                raw_out += len(ct)
        except Exception as e:
            raise HandshakeError(f"key agreement failed: {e}") from e

        body_bytes = canonical(body)
        th = _transcript_hash(payload, body_bytes)  # payload = EXACT bytes received
        sig = self.identity.sign(SIG_LABEL + th)
        full = canonical({**body, "sig": _b64(sig)})

        self.mode = mode
        self.keys = cs.derive_session_keys(mode, secrets, th)
        self._th_full = _full_transcript_hash(payload, full)
        self.sizes.raw_recv += raw_in
        self.sizes.raw_sent += raw_out
        return full

    def handle_client_finished(self, payload: bytes) -> bytes:
        assert self.keys is not None
        msg = _parse(payload, "ClientFinished")
        mac = _unb64(msg.get("mac"), 32, "mac")
        expected = _finished_mac(self.keys.finished_c, b"client", self._th_full)
        if not hmac.compare_digest(mac, expected):
            raise HandshakeError("ClientFinished MAC mismatch (transcript or key disagreement)")
        out = _finished_mac(self.keys.finished_s, b"server", self._th_full)
        self.sizes.raw_recv += 32
        self.sizes.raw_sent += len(out)
        return canonical({"v": VERSION, "mac": _b64(out)})
