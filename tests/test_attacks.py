"""End-to-end attack scenarios through the real MITM proxies over TCP."""
import pytest

from src.crypto_suite import Mode
from src.handshake import DowngradeDetected, SignatureInvalid
from src.record_layer import BadTag, RecordError, ReplayDetected, SeqGap
from src.wire import ConnectionClosed
from attacks.mitm_downgrade import DowngradeProxy
from attacks.tamper_replay import RecordAttackProxy
from conftest import wait_for_event


@pytest.fixture()
def proxy_factory():
    made = []

    def make(cls, upstream_port, *a, **kw):
        p = cls(("127.0.0.1", upstream_port), *a, **kw)
        p.start()
        made.append(p)
        return p

    yield make
    for p in made:
        p.stop()


@pytest.mark.matrix("T7", "MITM strips hybrid/PQC from ClientHello; client has NO policy",
                    "Client aborts with SIG_INVALID (transcript signature mismatch)")
def test_downgrade_without_policy_caught_by_signature(server_factory, client_factory, proxy_factory, actual):
    srv = server_factory()
    mitm = proxy_factory(DowngradeProxy, srv.port)
    cli = client_factory()  # no min_mode
    with pytest.raises(SignatureInvalid):
        cli.connect("127.0.0.1", mitm.port)
    assert mitm.trace, "attack must actually have been applied"
    assert cli.logger.count("SIG_INVALID") == 1 and cli.logger.count("HANDSHAKE_OK") == 0
    actual(f"proxy: {mitm.trace[0]}; client raised SignatureInvalid; client log={cli.logger.event_names()}")


@pytest.mark.matrix("T8", "MITM strips hybrid/PQC from ClientHello; client has min_mode=hybrid",
                    "Client aborts with DOWNGRADE_DETECTED")
def test_downgrade_with_policy_detected(server_factory, client_factory, proxy_factory, actual):
    srv = server_factory()
    mitm = proxy_factory(DowngradeProxy, srv.port)
    cli = client_factory(min_mode=Mode.HYBRID)
    with pytest.raises(DowngradeDetected):
        cli.connect("127.0.0.1", mitm.port)
    assert mitm.trace
    assert cli.logger.count("DOWNGRADE_DETECTED") == 1 and cli.logger.count("HANDSHAKE_OK") == 0
    actual(f"proxy: {mitm.trace[0]}; client raised DowngradeDetected; client log={cli.logger.event_names()}")


def test_proxy_without_attack_is_transparent(server_factory, client_factory, proxy_factory):
    """Control: an idle relay must not break the protocol (so failures above are due to the attack)."""
    from attacks.relay import MitmProxy
    srv = server_factory()
    mitm = proxy_factory(MitmProxy, srv.port)
    s = client_factory().connect("127.0.0.1", mitm.port)
    assert s.mode == Mode.HYBRID and s.echo(b"x") == b"x"
    s.close()


@pytest.mark.matrix("T9", "MITM flips a bit in an encrypted record (client->server)",
                    "Server logs BAD_TAG and closes the connection")
def test_tampered_record_rejected_by_server(server_factory, client_factory, proxy_factory, actual):
    srv = server_factory()
    mitm = proxy_factory(RecordAttackProxy, srv.port, "tamper", 1, "c2s")
    s = client_factory().connect("127.0.0.1", mitm.port)
    assert s.echo(b"first") == b"first"
    with pytest.raises((ConnectionClosed, OSError, RecordError)):
        s.echo(b"second")  # record #1 is corrupted -> server aborts
    assert wait_for_event(srv.logger, "BAD_TAG")
    assert srv.logger.count("REPLAY_DETECTED") == 0
    actual(f"proxy: {mitm.trace[0]}; server log={srv.logger.event_names()}")


@pytest.mark.matrix("T10", "MITM replays a captured record (client->server)",
                    "Server logs REPLAY_DETECTED and closes the connection")
def test_replayed_record_rejected_by_server(server_factory, client_factory, proxy_factory, actual):
    srv = server_factory()
    mitm = proxy_factory(RecordAttackProxy, srv.port, "replay", 1, "c2s")
    s = client_factory().connect("127.0.0.1", mitm.port)
    s.echo(b"first")
    s.echo(b"second")  # record #1, which the proxy delivers twice
    assert wait_for_event(srv.logger, "REPLAY_DETECTED")
    assert srv.logger.count("BAD_TAG") == 0
    actual(f"proxy: {mitm.trace[0]}; server log={srv.logger.event_names()}")


@pytest.mark.matrix("T11", "MITM drops a record (client->server)", "Server logs SEQ_GAP and closes the connection")
def test_dropped_record_gives_seq_gap(server_factory, client_factory, proxy_factory, actual):
    srv = server_factory()
    mitm = proxy_factory(RecordAttackProxy, srv.port, "drop", 1, "c2s")
    s = client_factory().connect("127.0.0.1", mitm.port)
    s.echo(b"first")
    s.channel.send(b"\x01dropped")      # record #1: deleted by the proxy (no reply expected)
    s.channel.send(b"\x01after-gap")    # record #2: arrives while server expects #1
    assert wait_for_event(srv.logger, "SEQ_GAP")
    actual(f"proxy: {mitm.trace[0]}; server log={srv.logger.event_names()}")


@pytest.mark.matrix("T12", "MITM replays a server->client record", "Client raises ReplayDetected and logs REPLAY_DETECTED")
def test_replayed_record_rejected_by_client(server_factory, client_factory, proxy_factory, actual):
    srv = server_factory()
    cli = client_factory()
    mitm = proxy_factory(RecordAttackProxy, srv.port, "replay", 0, "s2c")
    s = cli.connect("127.0.0.1", mitm.port)
    s.echo(b"one")
    with pytest.raises(ReplayDetected):
        s.echo(b"two")  # next record from server is the duplicate of #0
    assert cli.logger.count("REPLAY_DETECTED") == 1
    actual(f"proxy: {mitm.trace[0]}; client log={cli.logger.event_names()}")


def test_tampered_record_rejected_by_client(server_factory, client_factory, proxy_factory):
    srv = server_factory()
    cli = client_factory()
    mitm = proxy_factory(RecordAttackProxy, srv.port, "tamper", 0, "s2c")
    s = cli.connect("127.0.0.1", mitm.port)
    with pytest.raises(BadTag):
        s.echo(b"one")
    assert cli.logger.count("BAD_TAG") == 1
