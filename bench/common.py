"""Shared benchmark helpers: statistics, CSV output, lab setup."""
from __future__ import annotations

import csv
import math
import statistics
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from src import crypto_suite as cs
from src.crypto_suite import ServerIdentity
from src.logger import SecurityLogger
from src.server import SecureServer

from .netem_profiles import NetemProxy, Profile

RESULTS = Path(__file__).resolve().parent.parent / "results"
SEED = 1234


def percentile(values: list[float], q: float) -> float:
    """Linear-interpolated percentile (q in [0,100]); n=100 makes p99 ~ the 2nd-largest value."""
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    k = (len(xs) - 1) * q / 100
    lo, hi = math.floor(k), math.ceil(k)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def stats(values: list[float]) -> dict[str, float]:
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        "std": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min": min(values),
        "p50": percentile(values, 50),
        "p95": percentile(values, 95),
        "p99": percentile(values, 99),
        "max": max(values),
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {path} ({len(rows)} rows)")


@contextmanager
def lab(profile: Profile, identity: ServerIdentity | None = None) -> Iterator[tuple[bytes, int, NetemProxy | None]]:
    """Start a server (+ emulator proxy unless profile.use_proxy is False).

    Yields (pinned_key, port_to_connect_to, proxy). Server and client share one
    Python process (see limitations): fine for sequential handshakes, and the
    absolute CPU numbers are therefore per-process, not per-host.
    """
    ident = identity or ServerIdentity.generate()
    server = SecureServer(ident, logger=SecurityLogger("server", console=False))
    server.start()
    proxy = None
    port = server.port
    if profile.use_proxy:
        proxy = NetemProxy(("127.0.0.1", server.port), profile, seed=SEED)
        proxy.start()
        port = proxy.port
    try:
        yield ident.public_raw, port, proxy
    finally:
        if proxy:
            proxy.stop()
        server.stop()


def backend() -> str:
    return cs.backend_name()
