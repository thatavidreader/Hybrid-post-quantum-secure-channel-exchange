"""Sans-IO handshake tests (no sockets): fast, deterministic, cover every check."""
import pytest

from src import crypto_suite as cs
from src.crypto_suite import Mode
from src.handshake import (ClientHandshake, DowngradeDetected, HandshakeError,
                           ServerHandshake, SignatureInvalid, canonical)
import json


def run(client: ClientHandshake, server: ServerHandshake, mutate_ch=None):
    ch = client.make_client_hello()
    if mutate_ch:
        ch = mutate_ch(ch)
    sh = server.handle_client_hello(ch)
    cf = client.handle_server_hello(sh)
    sf = server.handle_client_finished(cf)
    client.handle_server_finished(sf)


@pytest.mark.parametrize("mode", list(cs.ALL_MODES))
def test_each_mode_agrees_on_keys(identity, mode):
    c = ClientHandshake(identity.public_raw, offered_modes=[mode])
    s = ServerHandshake(identity)
    run(c, s)
    assert c.mode == s.mode == mode
    assert c.keys == s.keys


def test_negotiates_strongest_mutual_mode(identity):
    c = ClientHandshake(identity.public_raw)
    s = ServerHandshake(identity)
    run(c, s)
    assert c.mode == Mode.HYBRID


def test_stripped_client_hello_caught_by_signature(identity):
    def strip(ch: bytes) -> bytes:
        d = json.loads(ch)
        d["modes"] = ["classical"]
        d.pop("mlkem")
        return canonical(d)

    c = ClientHandshake(identity.public_raw)  # no policy
    with pytest.raises(SignatureInvalid):
        run(c, ServerHandshake(identity), mutate_ch=strip)


def test_policy_rejects_classical_only_server(identity):
    c = ClientHandshake(identity.public_raw, min_mode=Mode.HYBRID)
    with pytest.raises(DowngradeDetected):
        run(c, ServerHandshake(identity, supported_modes=[Mode.CLASSICAL]))


def test_unpinned_server_key_rejected(identity):
    other = cs.ServerIdentity.generate()
    c = ClientHandshake(identity.public_raw)
    with pytest.raises(SignatureInvalid):
        run(c, ServerHandshake(other))


def test_tampered_server_hello_rejected(identity):
    c = ClientHandshake(identity.public_raw)
    s = ServerHandshake(identity)
    sh = s.handle_client_hello(c.make_client_hello())
    d = json.loads(sh)
    d["mode"] = "classical"
    with pytest.raises((SignatureInvalid, HandshakeError)):
        c.handle_server_hello(canonical(d))


def test_bad_finished_rejected(identity):
    c = ClientHandshake(identity.public_raw)
    s = ServerHandshake(identity)
    cf = c.handle_server_hello(s.handle_client_hello(c.make_client_hello()))
    d = json.loads(cf)
    d["mac"] = "A" * 43 + "="
    with pytest.raises(HandshakeError):
        s.handle_client_finished(canonical(d))


def test_garbage_client_hello_rejected(identity):
    for junk in (b"", b"not json", b"[]", b'{"v":2}', b'{"v":1,"modes":"x","nonce":"AA=="}'):
        with pytest.raises(HandshakeError):
            ServerHandshake(identity).handle_client_hello(junk)


def test_raw_sizes_are_tracked(identity):
    c = ClientHandshake(identity.public_raw, offered_modes=[Mode.HYBRID])
    s = ServerHandshake(identity)
    run(c, s)
    # client sent: nonce 32 + x25519 32 + ek 1184 + mac 32
    assert c.sizes.raw_sent == 32 + 32 + 1184 + 32
    # server sent: nonce 32 + sig 64 + x25519 32 + ct 1088 + mac 32
    assert s.sizes.raw_sent == 32 + 64 + 32 + 1088 + 32
    assert c.sizes.raw_sent == s.sizes.raw_recv and s.sizes.raw_sent == c.sizes.raw_recv
