"""Throughput + application latency benchmark (after the handshake).

For each (profile, mode): open a session, upload SIZE bytes (SINK records, then
DONE; the clock stops when the server's confirmation arrives, so delivery - not
just local sending - is measured), repeat `--reps` times; then measure
small-message echo round-trip latency (`--pings` samples of 64 B).

Units: throughput in MB/s with MB = 10^6 bytes (SI); latency in ms.
Because all modes use the same AES-256-GCM record layer after the handshake, the
modes are expected to be statistically identical here; the benchmark verifies that
instead of assuming it.

Outputs (results/): throughput_raw.csv, latency_raw.csv, throughput_summary.csv
"""
from __future__ import annotations

import argparse
import time

from src import crypto_suite as cs
from src.client import SecureClient
from src.logger import SecurityLogger

from .common import RESULTS, backend, lab, stats, write_csv
from .netem_profiles import PROFILES

MODES = list(cs.ALL_MODES)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--size-mb", type=float, default=10.0, help="upload size in MB (10^6 bytes)")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--pings", type=int, default=50)
    ap.add_argument("--profiles", default=",".join(p.name for p in PROFILES))
    ap.add_argument("--out", default=str(RESULTS))
    a = ap.parse_args(argv)
    out = type(RESULTS)(a.out)
    size = int(a.size_mb * 1e6)
    wanted = set(a.profiles.split(","))
    tp_rows, lat_rows, summary = [], [], []
    print(f"ML-KEM backend: {backend()}  size={size} B  reps={a.reps}  pings={a.pings}")

    for p in PROFILES:
        if p.name not in wanted:
            continue
        with lab(p) as (pin, port, proxy):
            for mode in MODES:
                client = SecureClient(pin, offered_modes=[mode], logger=SecurityLogger("client", console=False))
                tps, lats = [], []
                for rep in range(a.reps):
                    s = client.connect("127.0.0.1", port)
                    t0 = time.perf_counter()
                    confirmed = s.upload(size)
                    dt = time.perf_counter() - t0
                    assert confirmed == size
                    tp = size / dt / 1e6
                    tps.append(tp)
                    tp_rows.append({"profile": p.name, "mode": mode.value, "backend": backend(), "rep": rep,
                                    "bytes": size, "seconds": round(dt, 4), "throughput_MBps": round(tp, 4)})
                    if rep == 0:  # latency samples on the first session
                        for i in range(a.pings):
                            t1 = time.perf_counter()
                            s.echo(b"x" * 64)
                            lat = (time.perf_counter() - t1) * 1e3
                            lats.append(lat)
                            lat_rows.append({"profile": p.name, "mode": mode.value, "backend": backend(),
                                             "ping": i, "rtt_ms": round(lat, 4)})
                    s.close()
                tps_s, lat_s = stats(tps), stats(lats)
                summary.append({"profile": p.name, "mode": mode.value, "backend": backend(), "size_bytes": size,
                                "reps": a.reps, "tp_MBps_mean": round(tps_s["mean"], 4),
                                "tp_MBps_std": round(tps_s["std"], 4), "tp_MBps_min": round(tps_s["min"], 4),
                                "tp_MBps_max": round(tps_s["max"], 4),
                                "rtt_ms_mean": round(lat_s["mean"], 4), "rtt_ms_p95": round(lat_s["p95"], 4),
                                "rtt_ms_p99": round(lat_s["p99"], 4)})
                print(f"[tp] {p.name:22s} {mode.value:9s} {tps_s['mean']:8.2f} MB/s (std {tps_s['std']:.2f})  "
                      f"echo RTT mean={lat_s['mean']:.2f} ms p95={lat_s['p95']:.2f} ms", flush=True)

    write_csv(out / "throughput_raw.csv", tp_rows)
    write_csv(out / "latency_raw.csv", lat_rows)
    write_csv(out / "throughput_summary.csv", summary)


if __name__ == "__main__":
    main()
