import pytest
from cryptography.exceptions import InvalidTag

from src import crypto_suite as cs


def test_mlkem_roundtrip_and_sizes():
    kem = cs.get_kem()
    ek, dk = kem.keygen()
    ss, ct = kem.encaps(ek)
    assert len(ek) == cs.MLKEM768_EK_LEN and len(ct) == cs.MLKEM768_CT_LEN
    assert len(ss) == cs.MLKEM768_SS_LEN
    assert kem.decaps(dk, ct) == ss


def test_mlkem_wrong_ciphertext_gives_different_secret():
    """ML-KEM uses implicit rejection: no exception, but an unrelated secret."""
    kem = cs.get_kem()
    ek, dk = kem.keygen()
    ss, ct = kem.encaps(ek)
    bad = bytes([ct[0] ^ 1]) + ct[1:]
    assert kem.decaps(dk, bad) != ss


def test_x25519_agreement():
    a, apub = cs.x25519_keygen()
    b, bpub = cs.x25519_keygen()
    assert cs.x25519_shared(a, bpub) == cs.x25519_shared(b, apub)


def test_kdf_directional_and_transcript_bound():
    th = cs.sha256(b"t1")
    k = cs.derive_session_keys(cs.Mode.HYBRID, [b"a" * 32, b"b" * 32], th)
    assert k.c2s_key != k.s2c_key
    assert k == cs.derive_session_keys(cs.Mode.HYBRID, [b"a" * 32, b"b" * 32], th)
    assert k != cs.derive_session_keys(cs.Mode.HYBRID, [b"a" * 32, b"b" * 32], cs.sha256(b"t2"))
    assert k != cs.derive_session_keys(cs.Mode.PQC, [b"a" * 32, b"b" * 32], th)


def test_aead_detects_modification():
    key, nonce = b"k" * 32, b"n" * 12
    ct = cs.aead_encrypt(key, nonce, b"hello", b"aad")
    assert cs.aead_decrypt(key, nonce, ct, b"aad") == b"hello"
    with pytest.raises(InvalidTag):
        cs.aead_decrypt(key, nonce, ct, b"other-aad")


def test_ed25519_pinned_verify():
    a, b = cs.ServerIdentity.generate(), cs.ServerIdentity.generate()
    sig = a.sign(b"m")
    assert cs.ed25519_verify(a.public_raw, sig, b"m")
    assert not cs.ed25519_verify(b.public_raw, sig, b"m")
    assert not cs.ed25519_verify(a.public_raw, sig, b"m2")
