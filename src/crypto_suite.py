"""Crypto suite: thin wrappers around vetted primitives, one place per concern.

We deliberately write NO custom primitives. This module only *selects* and
*combines* library primitives:

* X25519            -> `cryptography`   (classical key agreement)
* ML-KEM-768        -> `liboqs` if importable, else pure-Python `kyber-py`
* Ed25519           -> `cryptography`   (server authentication / transcript signature)
* HKDF-SHA256       -> `cryptography`   (key schedule)
* AES-256-GCM       -> `cryptography`   (record protection)

WHY a `Mode` enum with a rank: the downgrade policy ("require at least hybrid")
needs an ordering. We rank classical < pqc < hybrid, because hybrid is secure if
EITHER component holds, whereas pqc-only bets everything on a young algorithm
and classical-only is broken by a quantum adversary.
"""
from __future__ import annotations

import enum
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL_LABEL = b"PQSC1"  # domain-separation label baked into every derivation/signature


# --------------------------------------------------------------------------- modes
class Mode(str, enum.Enum):
    CLASSICAL = "classical"
    PQC = "pqc"
    HYBRID = "hybrid"

    @property
    def rank(self) -> int:
        return {"classical": 0, "pqc": 1, "hybrid": 2}[self.value]

    @property
    def uses_x25519(self) -> bool:
        return self in (Mode.CLASSICAL, Mode.HYBRID)

    @property
    def uses_mlkem(self) -> bool:
        return self in (Mode.PQC, Mode.HYBRID)


ALL_MODES: tuple[Mode, ...] = (Mode.CLASSICAL, Mode.PQC, Mode.HYBRID)
# Server preference: strongest first.
PREFERENCE: tuple[Mode, ...] = (Mode.HYBRID, Mode.PQC, Mode.CLASSICAL)


# --------------------------------------------------------------------------- ML-KEM
MLKEM768_EK_LEN = 1184   # encapsulation (public) key, FIPS 203
MLKEM768_CT_LEN = 1088   # ciphertext
MLKEM768_SS_LEN = 32     # shared secret


class MLKEM(Protocol):
    """Minimal KEM interface so the protocol code is backend-agnostic."""

    name: str

    def keygen(self) -> tuple[bytes, Any]: ...
    def encaps(self, ek: bytes) -> tuple[bytes, bytes]: ...   # -> (shared_secret, ciphertext)
    def decaps(self, dk: Any, ct: bytes) -> bytes: ...


class KyberPyMLKEM:
    """Pure-Python ML-KEM-768 (FIPS 203) from the `kyber-py` package.

    Works everywhere without a C toolchain. Much slower than native code, which
    we state explicitly in the limitations rather than hiding.
    """

    name = "kyber-py"

    def __init__(self) -> None:
        from kyber_py.ml_kem import ML_KEM_768  # imported lazily: optional dependency

        self._k = ML_KEM_768

    def keygen(self) -> tuple[bytes, Any]:
        ek, dk = self._k.keygen()
        return ek, dk

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        ss, ct = self._k.encaps(ek)
        return ss, ct

    def decaps(self, dk: Any, ct: bytes) -> bytes:
        return self._k.decaps(dk, ct)


class LiboqsMLKEM:
    """Native ML-KEM-768 via liboqs-python (used automatically if importable).

    NOTE: written against the liboqs-python API but NOT exercised on the author's
    Windows machine (liboqs could not be built there) - see README.
    """

    def __init__(self) -> None:
        import oqs  # type: ignore

        self._oqs = oqs
        enabled = set(oqs.get_enabled_kem_mechanisms())
        # Newer liboqs uses the FIPS 203 name; older releases call it Kyber768.
        self._alg = "ML-KEM-768" if "ML-KEM-768" in enabled else "Kyber768"
        if self._alg not in enabled:
            raise ImportError("liboqs has no ML-KEM-768/Kyber768")
        self.name = "liboqs"

    def keygen(self) -> tuple[bytes, Any]:
        with self._oqs.KeyEncapsulation(self._alg) as kem:
            ek = kem.generate_keypair()
            dk = kem.export_secret_key()
        return ek, dk

    def encaps(self, ek: bytes) -> tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation(self._alg) as kem:
            ct, ss = kem.encap_secret(ek)
        return ss, ct

    def decaps(self, dk: Any, ct: bytes) -> bytes:
        with self._oqs.KeyEncapsulation(self._alg, secret_key=dk) as kem:
            return kem.decap_secret(ct)


_BACKEND: MLKEM | None = None


def get_kem() -> MLKEM:
    """Return the ML-KEM backend: liboqs if importable, else kyber-py.

    Override with env PQSC_KEM_BACKEND=kyber-py|liboqs. We never silently fake
    the PQC part: if the forced backend is unavailable this raises.
    """
    global _BACKEND
    if _BACKEND is not None:
        return _BACKEND
    forced = os.environ.get("PQSC_KEM_BACKEND", "").lower()
    if forced == "kyber-py":
        _BACKEND = KyberPyMLKEM()
    elif forced == "liboqs":
        _BACKEND = LiboqsMLKEM()
    else:
        try:
            _BACKEND = LiboqsMLKEM()
        except Exception:  # ImportError, or liboqs failing to build/load
            _BACKEND = KyberPyMLKEM()
    return _BACKEND


def backend_name() -> str:
    return get_kem().name


# --------------------------------------------------------------------------- X25519
def x25519_keygen() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, pub


def x25519_shared(priv: X25519PrivateKey, peer_pub: bytes) -> bytes:
    """ECDH. `cryptography` raises ValueError on all-zero (low-order) output."""
    return priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))


# --------------------------------------------------------------------------- Ed25519
def raw_public_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed25519_verify(pub_raw: bytes, signature: bytes, message: bytes) -> bool:
    """True iff `signature` is valid for `message` under the PINNED raw key."""
    from cryptography.exceptions import InvalidSignature

    try:
        Ed25519PublicKey.from_public_bytes(pub_raw).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass
class ServerIdentity:
    """Long-term Ed25519 identity of the server.

    The client does not use a CA: it PINS this public key (trust-on-provisioning),
    which keeps the prototype small and the trust assumption explicit.
    """

    private_key: Ed25519PrivateKey

    @property
    def public_raw(self) -> bytes:
        return raw_public_bytes(self.private_key.public_key())

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    @classmethod
    def generate(cls) -> "ServerIdentity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load_or_create(cls, key_dir: str | Path, name: str = "server") -> "ServerIdentity":
        """Load `<name>_ed25519.pem` or create it (plus a hex `.pub` for clients to pin)."""
        d = Path(key_dir)
        d.mkdir(parents=True, exist_ok=True)
        pem = d / f"{name}_ed25519.pem"
        if pem.exists():
            priv = serialization.load_pem_private_key(pem.read_bytes(), password=None)
            assert isinstance(priv, Ed25519PrivateKey)
            ident = cls(priv)
        else:
            ident = cls.generate()
            pem.write_bytes(
                ident.private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),  # prototype only; production needs an HSM/KMS
                )
            )
        (d / f"{name}_ed25519.pub").write_text(ident.public_raw.hex())
        return ident


def load_pinned_key(path: str | Path) -> bytes:
    return bytes.fromhex(Path(path).read_text().strip())


# --------------------------------------------------------------------------- KDF
@dataclass(frozen=True)
class SessionKeys:
    """Directional keys: client->server and server->client never share a key."""

    c2s_key: bytes
    s2c_key: bytes
    c2s_iv: bytes       # 4-byte nonce prefix (the other 8 bytes are the sequence number)
    s2c_iv: bytes
    finished_c: bytes   # MAC keys for the Finished messages
    finished_s: bytes


_KEY_LAYOUT = (("c2s_key", 32), ("s2c_key", 32), ("c2s_iv", 4), ("s2c_iv", 4),
               ("finished_c", 32), ("finished_s", 32))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def derive_session_keys(mode: Mode, shared_secrets: list[bytes], transcript_hash: bytes) -> SessionKeys:
    """HKDF-SHA256(IKM = concat(shared secrets), salt = transcript hash).

    WHY the transcript as salt: it binds the keys to everything both sides saw
    (modes offered, public keys, ciphertext, nonces). If a MITM altered any byte
    the two ends derive DIFFERENT keys, so Finished MACs fail even if the
    signature check were skipped. WHY the mode in `info`: keys derived for one
    mode can never be confused with another.

    For hybrid, concatenation is a sound combiner here because the KEM
    ciphertext/public keys are in the hashed transcript (cf. the X-Wing /
    TLS hybrid designs): the result is safe if either secret is unbroken.
    """
    total = sum(n for _, n in _KEY_LAYOUT)
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=total,
        salt=transcript_hash,
        info=PROTOCOL_LABEL + b" key schedule|" + mode.value.encode(),
    ).derive(b"".join(shared_secrets))
    parts: dict[str, bytes] = {}
    off = 0
    for name, n in _KEY_LAYOUT:
        parts[name] = okm[off:off + n]
        off += n
    return SessionKeys(**parts)


# --------------------------------------------------------------------------- AEAD
def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on any modification."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)
