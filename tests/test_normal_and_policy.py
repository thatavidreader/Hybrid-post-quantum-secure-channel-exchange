"""End-to-end over real TCP sockets: normal operation, policy, pinning."""
import os

import pytest

from src import crypto_suite as cs
from src.crypto_suite import Mode
from src.handshake import DowngradeDetected, HandshakeError, SignatureInvalid
from conftest import wait_for_event


@pytest.mark.matrix("T1", "None (normal operation, one test per mode)", "Handshake OK; data round trip identical")
@pytest.mark.parametrize("mode", list(cs.ALL_MODES))
def test_normal_round_trip_each_mode(server_factory, client_factory, mode, actual):
    srv = server_factory()
    cli = client_factory(offered_modes=[mode])
    s = cli.connect("127.0.0.1", srv.port)
    payload = os.urandom(50_000)  # spans several 16 KiB records
    assert s.mode == mode
    assert s.echo(payload) == payload
    assert s.upload(100_000) == 100_000
    s.close()
    assert cli.logger.count("HANDSHAKE_OK") == 1
    assert wait_for_event(srv.logger, "HANDSHAKE_OK")
    actual(f"mode={s.mode.value}, 50 kB echo identical, 100 kB upload confirmed, "
           f"backend={cs.backend_name()}, client log={cli.logger.event_names()}")


def test_default_negotiation_picks_hybrid(server_factory, client_factory):
    srv = server_factory()
    s = client_factory().connect("127.0.0.1", srv.port)
    assert s.mode == Mode.HYBRID
    s.close()


@pytest.mark.matrix("T6", "Server only supports classical; client policy min_mode=hybrid",
                    "Client aborts with DOWNGRADE_DETECTED")
def test_policy_refuses_classical_only_server(server_factory, client_factory, actual):
    srv = server_factory(modes=[Mode.CLASSICAL])
    cli = client_factory(min_mode=Mode.HYBRID)
    with pytest.raises(DowngradeDetected):
        cli.connect("127.0.0.1", srv.port)
    assert cli.logger.count("DOWNGRADE_DETECTED") == 1
    assert cli.logger.count("HANDSHAKE_OK") == 0
    actual(f"client raised DowngradeDetected; client log={cli.logger.event_names()}")


def test_same_server_accepted_without_policy(server_factory, client_factory):
    """Control for T6: the identical server is fine when no policy is set."""
    srv = server_factory(modes=[Mode.CLASSICAL])
    s = client_factory().connect("127.0.0.1", srv.port)
    assert s.mode == Mode.CLASSICAL
    s.close()


def test_pqc_policy_accepts_hybrid_rejects_classical(server_factory, client_factory):
    srv = server_factory()
    s = client_factory(min_mode=Mode.PQC).connect("127.0.0.1", srv.port)
    assert s.mode == Mode.HYBRID
    s.close()
    srv2 = server_factory(modes=[Mode.CLASSICAL])
    with pytest.raises(DowngradeDetected):
        client_factory(min_mode=Mode.PQC).connect("127.0.0.1", srv2.port)


@pytest.mark.matrix("T2", "Server presents a signature from an unpinned (wrong/forged) key",
                    "Client aborts with SIG_INVALID")
def test_unpinned_server_key_rejected(server_factory, client_factory, actual):
    rogue = server_factory(ident=cs.ServerIdentity.generate())  # client pins a different key
    cli = client_factory()
    with pytest.raises(SignatureInvalid):
        cli.connect("127.0.0.1", rogue.port)
    assert cli.logger.count("SIG_INVALID") == 1
    actual(f"client raised SignatureInvalid; client log={cli.logger.event_names()}")


def test_server_logs_failure_when_client_aborts(server_factory, client_factory):
    srv = server_factory(modes=[Mode.CLASSICAL])
    with pytest.raises(DowngradeDetected):
        client_factory(min_mode=Mode.HYBRID).connect("127.0.0.1", srv.port)
    assert wait_for_event(srv.logger, "HANDSHAKE_FAIL")


def test_no_common_mode_is_handshake_fail(server_factory, client_factory):
    srv = server_factory(modes=[Mode.PQC])
    with pytest.raises(HandshakeError):
        client_factory(offered_modes=[Mode.CLASSICAL]).connect("127.0.0.1", srv.port)
    assert wait_for_event(srv.logger, "HANDSHAKE_FAIL")
