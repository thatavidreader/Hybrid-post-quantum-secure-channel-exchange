"""Draw report charts from the CSVs in results/ (no numbers are typed in here).

Style: fixed categorical colour per mode (never re-ordered), light surface,
thin marks, labelled axes with SI units, legend on every multi-series chart and
a hatch per mode so identity never relies on colour alone.
Outputs PNG (+ SVG) into results/plots/.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RESULTS = Path(__file__).resolve().parent.parent / "results"
MODES = ["classical", "pqc", "hybrid"]
COLOR = {"classical": "#2a78d6", "pqc": "#eb6834", "hybrid": "#1baf7a"}   # validated categorical slots 1-3
HATCH = {"classical": "", "pqc": "//", "hybrid": "xx"}
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#52514e", "#e3e2de", "#fcfcfb"
PROFILE_LABEL = {
    "baseline": "direct\n(no proxy)", "proxy_0ms": "proxy\n0 ms", "delay_50ms": "50 ms\none-way",
    "delay_100ms_loss_1pct": "100 ms one-way\n+ 1 % loss", "loss_5pct": "5 % loss",
}

plt.rcParams.update({
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
    "axes.edgecolor": MUTED, "axes.labelcolor": INK, "text.color": INK, "xtick.color": MUTED,
    "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False, "axes.linewidth": 0.8,
    "font.size": 10, "legend.frameon": False, "hatch.linewidth": 0.6,
})


def read(name: str, out: Path) -> list[dict]:
    p = out / name
    if not p.exists():
        print(f"skip: {p} missing")
        return []
    with p.open(encoding="utf-8") as f:
        return list(csv.DictReader(f))


def f(row: dict, key: str) -> float:
    return float(row[key])


def style(ax, ylabel: str, title: str, log: bool = False) -> None:
    ax.set_ylabel(ylabel)
    ax.set_title(title, loc="left", fontsize=11, color=INK)
    ax.grid(axis="y", color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    if log:
        ax.set_yscale("log")
        ax.set_ylim(bottom=0.05 if "latency" in title.lower() else 1)  # bars must start well below the data


def grouped(ax, groups: list[str], series: dict[str, list[float]], err: dict[str, list[float]] | None = None,
            labels: bool = True, fmt: str = "{:.1f}") -> None:
    n = len(series)
    w = 0.8 / n
    for i, (mode, vals) in enumerate(series.items()):
        xs = [g + (i - (n - 1) / 2) * w for g in range(len(groups))]
        ax.bar(xs, vals, w * 0.92, color=COLOR[mode], edgecolor=SURFACE, hatch=HATCH[mode], label=mode,
               yerr=([[min(e, v) for e, v in zip(err[mode], vals)], err[mode]] if err else None), error_kw={"elinewidth": 0.8, "capsize": 2, "ecolor": MUTED})
        if labels:
            for x, v in zip(xs, vals):
                ax.annotate(fmt.format(v), (x, v), ha="center", va="bottom", fontsize=7, color=MUTED,
                            xytext=(0, 2), textcoords="offset points")
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels(groups)
    ax.legend(title="key-exchange mode", fontsize=8, title_fontsize=8)


def save(fig, out: Path, name: str) -> None:
    (out / "plots").mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(out / "plots" / f"{name}.png", dpi=200)
    fig.savefig(out / "plots" / f"{name}.svg")
    plt.close(fig)
    print(f"wrote plots/{name}.png")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(RESULTS))
    out = Path(ap.parse_args(argv).out)
    backend = ""

    summ = read("handshake_summary.csv", out)
    if summ:
        backend = summ[0]["backend"]
        sub = f"ML-KEM backend: {backend}; n=100 per bar; bars = mean, whiskers = ±1 std"

        # 1. crypto-only handshake time
        c = {r["mode"]: r for r in summ if r["scope"] == "crypto_only"}
        fig, ax = plt.subplots(figsize=(6, 4))
        grouped(ax, ["crypto-only\n(no network)"], {m: [f(c[m], "ms_mean")] for m in MODES},
                {m: [f(c[m], "ms_std")] for m in MODES}, fmt="{:.2f} ms")
        style(ax, "Handshake time (ms)", "Handshake CPU cost: crypto only\n" + sub)
        save(fig, out, "handshake_crypto_only")

        # 2. end-to-end handshake time per profile
        e = [r for r in summ if r["scope"] == "end_to_end"]
        profs = [p for p in PROFILE_LABEL if any(r["profile"] == p for r in e)]
        by = {(r["profile"], r["mode"]): r for r in e}
        fig, ax = plt.subplots(figsize=(10, 4.6))
        grouped(ax, [PROFILE_LABEL[p] for p in profs],
                {m: [f(by[p, m], "ms_mean") for p in profs] for m in MODES},
                {m: [f(by[p, m], "ms_std") for p in profs] for m in MODES}, fmt="{:.0f}")
        style(ax, "End-to-end handshake time (ms)", "Handshake time vs network condition\n" + sub)
        save(fig, out, "handshake_e2e")

        # 2b. same, p95 (tail latency matters under loss)
        fig, ax = plt.subplots(figsize=(10, 4.6))
        grouped(ax, [PROFILE_LABEL[p] for p in profs],
                {m: [f(by[p, m], "ms_p95") for p in profs] for m in MODES}, fmt="{:.0f}")
        style(ax, "End-to-end handshake time, 95th percentile (ms)", "Handshake tail latency (p95)\n" + sub)
        save(fig, out, "handshake_e2e_p95")

        # 3. bytes on wire: raw vs wire
        fig, axs = plt.subplots(1, 2, figsize=(9, 4), sharey=True)
        for ax, key, ttl in ((axs[0], "raw_bytes_total", "Raw payload bytes\n(keys, ciphertext, signature, nonces, MACs)"),
                             (axs[1], "wire_bytes_total", "Total wire bytes\n(+ JSON, base64, framing)")):
            grouped(ax, [""], {m: [f(c[m], key)] for m in MODES}, fmt="{:.0f} B")
            style(ax, "Handshake bytes (B)", ttl)
        axs[1].set_ylabel("")
        save(fig, out, "handshake_bytes")

    res = read("handshake_resources.csv", out)
    if res:
        r = {x["mode"]: x for x in res}
        fig, axs = plt.subplots(1, 2, figsize=(9, 4))
        grouped(axs[0], [""], {m: [f(r[m], "cpu_ms_per_handshake")] for m in MODES}, fmt="{:.2f} ms")
        style(axs[0], "CPU time per handshake (ms)", "CPU time\n(client + server, one process)")
        grouped(axs[1], [""], {m: [f(r[m], "peak_heap_kib_mean")] for m in MODES}, fmt="{:.0f} KiB")
        style(axs[1], "Peak Python heap per handshake (KiB)", "Peak memory\n(tracemalloc, mean of 20)")
        save(fig, out, "handshake_cpu_memory")

    tp = read("throughput_summary.csv", out)
    if tp:
        profs = [p for p in PROFILE_LABEL if any(r["profile"] == p for r in tp)]
        by = {(r["profile"], r["mode"]): r for r in tp}
        size_mb = f(tp[0], "size_bytes") / 1e6
        fig, ax = plt.subplots(figsize=(10, 4.6))
        grouped(ax, [PROFILE_LABEL[p] for p in profs],
                {m: [f(by[p, m], "tp_MBps_mean") for p in profs] for m in MODES},
                {m: [f(by[p, m], "tp_MBps_std") for p in profs] for m in MODES}, fmt="{:.1f}")
        style(ax, "Throughput (MB/s, 1 MB = 10⁶ B)",
              f"Throughput for a {size_mb:g} MB upload (log scale)\n{backend}; bars = mean of reps, whiskers = ±1 std",
              log=True)
        save(fig, out, "throughput")

        fig, ax = plt.subplots(figsize=(10, 4.6))
        grouped(ax, [PROFILE_LABEL[p] for p in profs],
                {m: [f(by[p, m], "rtt_ms_mean") for p in profs] for m in MODES}, fmt="{:.1f}")
        style(ax, "Echo round-trip time, 64 B (ms)", "Application round-trip latency (log scale)", log=True)
        save(fig, out, "latency")


if __name__ == "__main__":
    main()
