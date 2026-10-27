"""Shared fixtures + a reporting hook that feeds docs/test_matrix.md.

Each test may carry `@pytest.mark.matrix(id, attack, expected)` and call the
`actual` fixture with a short string describing what it really observed. After
the run, results/test_results.json holds the real outcomes; the matrix document
is generated from that file by tests/make_test_matrix.py (nothing hand-typed).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from src.crypto_suite import ALL_MODES, ServerIdentity, backend_name

RESULTS: list[dict] = []
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def identity() -> ServerIdentity:
    return ServerIdentity.generate()


@pytest.fixture()
def server_factory(identity):
    """Start servers on ephemeral localhost ports; stopped at test end."""
    from src.logger import SecurityLogger
    from src.server import SecureServer

    started: list = []

    def make(modes=ALL_MODES, ident=None) -> SecureServer:
        logger = SecurityLogger(role="server", console=False)
        srv = SecureServer(ident or identity, modes=modes, logger=logger)
        srv.start()
        started.append(srv)
        return srv

    yield make
    for s in started:
        s.stop()


@pytest.fixture()
def client_factory(identity):
    from src.client import SecureClient
    from src.logger import SecurityLogger

    def make(pinned=None, **kw) -> SecureClient:
        logger = SecurityLogger(role="client", console=False)
        return SecureClient(pinned or identity.public_raw, logger=logger, **kw)

    return make


@pytest.fixture()
def actual(request):
    """Call actual("...") inside a test to record the observed behaviour."""

    def rec(text: str) -> None:
        request.node.user_properties.append(("actual", text))

    return rec


def wait_for_event(logger, event: str, timeout: float = 3.0) -> bool:
    """Server threads log asynchronously; poll briefly instead of sleeping blindly."""
    end = time.time() + timeout
    while time.time() < end:
        if logger.count(event):
            return True
        time.sleep(0.02)
    return False


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when == "call" or (rep.when == "setup" and rep.outcome != "passed"):
        m = item.get_closest_marker("matrix")
        props = dict(item.user_properties)
        RESULTS.append({
            "nodeid": item.nodeid,
            "outcome": rep.outcome,
            "matrix": list(m.args) if m else None,
            "actual": props.get("actual", ""),
            "backend": backend_name(),
        })


def pytest_sessionfinish(session, exitstatus):
    out = ROOT / "results" / "test_results.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(RESULTS, indent=2))
