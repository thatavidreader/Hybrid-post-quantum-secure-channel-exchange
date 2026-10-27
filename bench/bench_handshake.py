"""Handshake benchmark: crypto-only vs end-to-end, bytes, CPU, memory.

Three separate measurements (never mixed):

A. crypto-only  : both state machines driven in-process, no sockets. Isolates the
                  cost of the cryptography (keygen/encaps/decaps/sign/verify/HKDF).
                  Per-run wall time via perf_counter, split into client and server share.
B. end-to-end   : real TCP handshake (client.connect()) through the emulation proxy
                  for every network profile, incl. a zero-delay proxy and a direct
                  (no proxy) baseline so the proxy's own overhead is visible.
C. resources    : CPU time per handshake and peak Python heap per handshake.
                  CPU: dedicated batch (>=300) / N. time.process_time() proved unreliable
                  on the dev machine (counted ~1.5 s for a 3 s busy loop), so we report
                  wall time of the CPU-bound batch (== CPU time here) plus exact cycles
                  from QueryProcessCycleTime (Windows).
                  Memory: tracemalloc peak (Python allocations only; tracemalloc slows
                  code, so this is a separate untimed pass).

Bytes are reported two ways: RAW (key/ciphertext/signature/nonce/MAC sizes) and
WIRE (everything sent incl. JSON + base64 + 5-byte framing).

Outputs (results/): handshake_crypto_raw.csv, handshake_e2e_raw.csv,
handshake_summary.csv, handshake_resources.csv
"""
from __future__ import annotations

import argparse
import gc
import time
import tracemalloc

from src import crypto_suite as cs
from src.client import SecureClient
from src.crypto_suite import Mode
from src.handshake import ClientHandshake, ServerHandshake
from src.logger import SecurityLogger
from src.wire import HS_HEADER_LEN

from .common import RESULTS, backend, lab, stats, write_csv
from .netem_profiles import PROFILES, Profile

MODES = list(cs.ALL_MODES)


def process_cycles() -> int | None:
    """CPU cycles consumed by this process (Windows QueryProcessCycleTime), else None.

    WHY: on the dev machine time.process_time() under-counted a 3 s busy loop by
    ~50 % (tick-based accounting), so it cannot be trusted. Cycle counters are exact.
    """
    try:
        import ctypes
        k = ctypes.windll.kernel32  # type: ignore[attr-defined]
        k.GetCurrentProcess.restype = ctypes.c_void_p
        c = ctypes.c_ulonglong()
        k.QueryProcessCycleTime(ctypes.c_void_p(k.GetCurrentProcess()), ctypes.byref(c))
        return c.value
    except Exception:
        return None


def one_crypto_handshake(ident: cs.ServerIdentity, mode: Mode) -> dict:
    """Drive both sides in-process; time each of the 4 steps."""
    c = ClientHandshake(ident.public_raw, offered_modes=[mode])
    s = ServerHandshake(ident)
    t = time.perf_counter
    a = t(); ch = c.make_client_hello()
    b = t(); sh = s.handle_client_hello(ch)
    d = t(); cf = c.handle_server_hello(sh)
    e = t(); sf = s.handle_client_finished(cf)
    f = t(); c.handle_server_finished(sf)
    g = t()
    assert c.keys == s.keys and c.mode == mode
    client_s, server_s = (b - a) + (e - d) + (g - f), (d - b) + (f - e)
    wire_c2s = len(ch) + len(cf) + 2 * HS_HEADER_LEN
    wire_s2c = len(sh) + len(sf) + 2 * HS_HEADER_LEN
    return {
        "client_ms": client_s * 1e3, "server_ms": server_s * 1e3, "total_ms": (client_s + server_s) * 1e3,
        "raw_c2s": c.sizes.raw_sent, "raw_s2c": s.sizes.raw_sent,
        "wire_c2s": wire_c2s, "wire_s2c": wire_s2c,
    }


def bench_crypto_only(n: int, warmup: int) -> tuple[list[dict], list[dict], list[dict]]:
    ident = cs.ServerIdentity.generate()
    raw_rows, res_rows = [], []
    summary: list[dict] = []
    for mode in MODES:
        for _ in range(warmup):
            one_crypto_handshake(ident, mode)
        runs = [one_crypto_handshake(ident, mode) for _ in range(n)]
        # CPU: dedicated batch (>= 300 handshakes) so the 15.6 ms Windows counter tick is <= 0.05 ms/handshake
        gc.collect()
        cpu_n = max(n, 300)
        cyc0, wall0 = process_cycles(), time.perf_counter()
        for _ in range(cpu_n):
            one_crypto_handshake(ident, mode)
        wall = (time.perf_counter() - wall0) / cpu_n * 1e3
        cyc1 = process_cycles()
        mcyc = (cyc1 - cyc0) / cpu_n / 1e6 if cyc0 is not None and cyc1 is not None else float("nan")
        cpu = wall  # CPU-bound, single-threaded, no I/O: wall time == CPU time (see docstring)
        for i, r in enumerate(runs):
            raw_rows.append({"mode": mode.value, "backend": backend(), "run": i, **r})
        st = stats([r["total_ms"] for r in runs])
        summary.append({"scope": "crypto_only", "profile": "n/a", "mode": mode.value, "backend": backend(),
                        **{f"ms_{k}": round(v, 4) for k, v in st.items()},
                        "raw_bytes_total": runs[0]["raw_c2s"] + runs[0]["raw_s2c"],
                        "wire_bytes_total": runs[0]["wire_c2s"] + runs[0]["wire_s2c"]})
        # memory pass (untimed)
        peaks = []
        for _ in range(20):
            gc.collect()
            tracemalloc.start()
            one_crypto_handshake(ident, mode)
            peaks.append(tracemalloc.get_traced_memory()[1] / 1024)
            tracemalloc.stop()
        res_rows.append({"mode": mode.value, "backend": backend(), "n_cpu_batch": cpu_n,
                         "cpu_ms_per_handshake": round(cpu, 3), "cpu_mcycles_per_handshake": round(mcyc, 2),
                         "peak_heap_kib_mean": round(sum(peaks) / len(peaks), 1),
                         "peak_heap_kib_max": round(max(peaks), 1),
                         "cpu_note": "CPU ms = wall ms of CPU-bound single-thread batch; Mcycles from QueryProcessCycleTime (client+server, one process)"})
        print(f"[crypto-only] {mode.value:9s} mean={st['mean']:.2f} ms  p95={st['p95']:.2f} ms  "
              f"cpu={cpu:.2f} ms  peak={sum(peaks)/len(peaks):.0f} KiB")
    return raw_rows, summary, res_rows


def bench_e2e(profile: Profile, n: int, warmup: int) -> tuple[list[dict], list[dict]]:
    rows, summary = [], []
    with lab(profile) as (pin, port, proxy):
        for mode in MODES:
            client = SecureClient(pin, offered_modes=[mode], logger=SecurityLogger("client", console=False))
            for i in range(warmup + n):
                t0 = time.perf_counter()
                s = client.connect("127.0.0.1", port)
                connect_total = time.perf_counter() - t0
                assert s.mode == mode
                if i >= warmup:
                    rows.append({
                        "profile": profile.name, "delay_ms_oneway": profile.delay_ms,
                        "loss_pct": profile.loss_pct, "mode": mode.value, "backend": backend(), "run": i - warmup,
                        "e2e_handshake_ms": s.handshake_seconds * 1e3, "connect_total_ms": connect_total * 1e3,
                        "wire_c2s": s.wire_bytes_sent, "wire_s2c": s.wire_bytes_recv,
                        "raw_c2s": s.raw_bytes_sent, "raw_s2c": s.raw_bytes_recv,
                    })
                s.close()
            mrows = [r for r in rows if r["mode"] == mode.value]
            st = stats([r["e2e_handshake_ms"] for r in mrows])
            summary.append({"scope": "end_to_end", "profile": profile.name, "mode": mode.value, "backend": backend(),
                            **{f"ms_{k}": round(v, 4) for k, v in st.items()},
                            "raw_bytes_total": mrows[0]["raw_c2s"] + mrows[0]["raw_s2c"],
                            "wire_bytes_total": mrows[0]["wire_c2s"] + mrows[0]["wire_s2c"]})
            print(f"[e2e] {profile.name:22s} {mode.value:9s} mean={st['mean']:8.2f} ms  "
                  f"p95={st['p95']:8.2f} ms  p99={st['p99']:8.2f} ms")
    return rows, summary


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=100)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--profiles", default=",".join(p.name for p in PROFILES))
    ap.add_argument("--out", default=str(RESULTS))
    ap.add_argument("--crypto-only", action="store_true",
                    help="re-run only the crypto-only part; keep existing end-to-end rows in the summary")
    a = ap.parse_args(argv)
    out = type(RESULTS)(a.out)

    print(f"ML-KEM backend: {backend()}   runs={a.runs} warmup={a.warmup}")
    craw, csum, cres = bench_crypto_only(a.runs, a.warmup)
    write_csv(out / "handshake_crypto_raw.csv", craw)
    write_csv(out / "handshake_resources.csv", cres)

    if a.crypto_only:
        import csv as _csv
        old = out / "handshake_summary.csv"
        keep = [r for r in _csv.DictReader(old.open(encoding="utf-8")) if r["scope"] == "end_to_end"]
        write_csv(out / "handshake_summary.csv", csum + keep)
        return

    e2e_rows, e2e_sum = [], []
    wanted = set(a.profiles.split(","))
    for p in PROFILES:
        if p.name in wanted:
            r, s = bench_e2e(p, a.runs, a.warmup)
            e2e_rows += r
            e2e_sum += s
    write_csv(out / "handshake_e2e_raw.csv", e2e_rows)
    write_csv(out / "handshake_summary.csv", csum + e2e_sum)


if __name__ == "__main__":
    main()
