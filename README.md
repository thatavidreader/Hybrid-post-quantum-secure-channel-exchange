# Post-Quantum Secure Channel (pq-secure-channel)

A research prototype of a client/server secure channel with **hybrid key exchange (X25519 + ML-KEM-768)**, AES-256-GCM records, and **detection of downgrade, tampering and replay attacks**. It includes a benchmark of `classical` vs `pqc` vs `hybrid` modes under emulated network conditions. Built as a B.Tech Honours mini project (Network Security).

> **Research prototype, not production cryptography.** Python implementation, pure-Python ML-KEM by default (no constant-time guarantees), no audit, manual key pinning, and **Ed25519 authentication is not post-quantum** ([docs/threat_model.md](docs/threat_model.md)). All attacks run only against this project's own server on localhost.

## Features
* **Three modes:** `classical` (X25519), `pqc` (ML-KEM-768), `hybrid` (both). The server picks the strongest mutual mode; the client can enforce a minimum with `min_mode`.
* **Downgrade protection:** the server signs a transcript hash (Ed25519, key pinned by the client) and both sides exchange Finished MACs. A client with `min_mode=hybrid` reports `DOWNGRADE_DETECTED`; a MITM-stripped ClientHello with no policy is caught as `SIG_INVALID`.
* **Record layer:** AES-256-GCM frames `[4B len][8B seq][ciphertext+tag]` with the sequence number bound in nonce and AAD. Results: `BAD_TAG`, `REPLAY_DETECTED`, `SEQ_GAP`; every error closes the connection.
* **Security logging:** JSON-lines events with colored console alerts, plus `src/log_summary.py`.
* **Network emulation:** a pure-Python delay/loss TCP proxy (no root needed); `tc netem` commands are provided for WSL2/Linux but were not used for the reported results.
* **Tests:** 46 pytest tests (every attack scenario included); [docs/test_matrix.md](docs/test_matrix.md) is generated from a real run.

## Layout
`src/` protocol (`crypto_suite`, `handshake`, `wire`, `record_layer`, `server`, `client`, `logger`) · `attacks/` MITM downgrade, tamper, replay · `bench/` benchmarks and plots · `tests/` · `docs/` · `results/` generated data.

## Setup
Python 3.10+ (developed on 3.13.5, Windows 11).
```powershell
python -m venv .venv                                            # [python3 -m venv .venv]
.\.venv\Scripts\python.exe -m pip install -r requirements.txt   # [.venv/bin/pip install -r requirements.txt]
```
**ML-KEM backend:** liboqs-python is used if importable, otherwise pure-Python `kyber-py`. liboqs could not be built on the dev machine (no CMake), so **all reported results use `kyber-py`**; the liboqs path is untested. The backend name is in every log line and CSV. Force one with `PQSC_KEM_BACKEND=kyber-py|liboqs`.

## Run
```powershell
.\demo.ps1                                            # [./demo.sh] normal -> downgrade x2 -> tamper -> replay -> log summary
.\.venv\Scripts\python.exe -m pytest                  # 46 tests
.\.venv\Scripts\python.exe tests\make_test_matrix.py  # regenerate docs/test_matrix.md
python -m src.server --port 9443                      # manual session, terminal 1 (creates keys/)
python -m src.client --port 9443 --min-mode hybrid    # terminal 2
python -m src.log_summary results\server.log.jsonl results\client.log.jsonl
```

## Reproduce the benchmarks
```powershell
python -m bench.bench_handshake --runs 100 --warmup 5   # a few minutes
python -m bench.bench_throughput --size-mb 10 --reps 3  # ~10-15 min (loss profiles are slow)
python -m bench.plot_results                            # PNG/SVG in results/plots/
```

## Summary of results
(Full tables, anomalies and limitations: [docs/results_interpretation.md](docs/results_interpretation.md); report chapter mapping and rubric checklist: [docs/report_mapping.md](docs/report_mapping.md). Backend: `kyber-py`; i7-6600U, Windows 11.)

| Mode | Handshake bytes raw / wire | Crypto-only handshake (mean ± std) |
|---|---|---|
| classical | 256 / 514 | 0.7 ± 0.3 ms |
| pqc | 2464 / 3447 | 21.5 ± 3.0 ms |
| hybrid | 2528 / 3565 | 21.1 ± 2.1 ms |

* The ~30x PQC cost is dominated by **pure-Python** ML-KEM and overstates native-library cost; don't quote it as "the cost of PQC".
* Over high-latency links the handshake is dominated by 4 one-way flights (classical: 211 ms at 50 ms one-way delay).
* After the handshake all modes share the same AES-GCM record layer; throughput differences between modes are within noise.
* The hybrid 50 ms cell contains slow bursts from host interference (p99 1162 ms); use its median (264 ms).

## Limitations
Pure-Python ML-KEM; localhost lab with client, server and proxy in one process; **emulated loss is an RTO-stall approximation, not real packet loss (stalls overlap, so bulk-transfer loss costs are optimistic)**; JSON/base64 encoding inflates wire bytes; Ed25519 authentication is not post-quantum (ML-DSA is future scope); no rekeying; noisy, non-isolated benchmark machine.
