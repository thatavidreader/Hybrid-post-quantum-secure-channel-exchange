# Results and interpretation

All numbers below come from actual runs on one machine: Intel Core i7-6600U (2.6 GHz), 32 GB RAM, Windows 11, Python 3.13.5. The ML-KEM backend was the **pure-Python `kyber-py`** throughout. Raw data is in `results/*.csv`, charts are in `results/plots/`, and the logs are in `results/bench_*.log`. Each handshake cell uses n = 100 runs after 5 discarded warm-up runs. Throughput uses 3 repetitions of a 10 MB (10^7 B) upload. Loss patterns use a fixed seed (1234).

## 1. Handshake bytes (deterministic; `handshake_summary.csv`)
| Mode | Raw payload bytes (keys, ciphertext, signature, nonces, MACs) | Total wire bytes (JSON, base64 and framing included) |
|---|---|---|
| classical | 256 | 514 |
| pqc | 2464 | 3447 |
| hybrid | 2528 | 3565 |

- PQC adds roughly 2.2 kB of raw cryptographic payload (ML-KEM-768 encapsulation key 1184 B + ciphertext 1088 B).
- Hybrid costs only 64 B more than PQC alone: one X25519 public key in each direction.
- JSON/base64 inflates the raw sizes by about 1.4x (3447/2464) for PQC and about 2x for classical. This is an artefact of the text encoding I chose, not of the cryptography. A binary encoding would shrink the wire numbers toward the raw column.

## 2. Crypto-only handshake time (no network)
| Mode | mean ± std (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|
| classical | 0.7 ± 0.3 | 1.2 | 1.6 |
| pqc | 21.5 ± 3.0 | 27.6 | 29.3 |
| hybrid | 21.1 ± 2.1 | 26.2 | 28.0 |

- The PQC and hybrid modes cost about 30x the classical one in this implementation.
- The cost is dominated by the pure-Python ML-KEM operations, not by the extra X25519 step. Hybrid is statistically indistinguishable from PQC here (about 21 ms each), since X25519 takes well under 1 ms.
- **CPU and memory** (`handshake_resources.csv`): about 0.7 ms / 1.9 Mcycles for classical, about 24 ms / 65 Mcycles for PQC, and about 22 ms / 60 Mcycles for hybrid. These cover client and server together, in one process. Peak Python heap per handshake was about 6 KiB for classical and about 248 KiB for both PQC and hybrid (tracemalloc, mean of 20).
- The CPU column is wall time of a CPU-bound batch, cross-checked against exact cycle counts. `time.process_time()` under-counted on this machine (about 1.5 s for a 3 s busy loop), so I did not use it.
- The crypto-only numbers were re-run after that fix. The end-to-end handshake data was not re-run, so the two sets come from different runs on a noisy machine. The mean of the same operation differed between runs (27 ms in the first run, 21 ms in the second). Compare orders of magnitude, not single milliseconds.

## 3. End-to-end handshake through the emulator (mean ± std; p95; `handshake_summary.csv`)
| Profile | classical | pqc | hybrid |
|---|---|---|---|
| direct (no proxy) | 2.1 ± 0.4; 2.8 | 29.2 ± 10.2; 43.7 | 24.8 ± 6.6; 39.9 |
| proxy, 0 delay | 2.9 ± 0.5; 3.9 | 26.1 ± 8.7; 32.5 | 25.8 ± 3.9; 34.6 |
| 50 ms one-way | 211.5 ± 7.8; 221.1 | 246.6 ± 13.6; 269.6 | 310.6 ± 162.8; 595.8 |
| 100 ms one-way + 1 % loss | 418.3 ± 39.5; 431.6 | 469.2 ± 52.7; 639.7 | 481.9 ± 72.4; 658.4 |
| 5 % loss | 48.6 ± 88.4; 206.8 | 79.4 ± 107.1; 243.4 | 93.1 ± 103.2; 250.2 |

All values are in ms. The p99 values are in `handshake_summary.csv`. With n = 100, p99 is essentially the second-largest sample.

What the data supports:
- **Proxy overhead is visible and small.** Classical rises from about 2.1 ms (direct) to about 2.9 ms (0 ms proxy). For PQC and hybrid the difference is within the run-to-run spread.
- **Latency dominates.** The handshake has 4 one-way flights (ClientHello, ServerHello, ClientFinished, ServerFinished). At 50 ms one-way that is about 200 ms, and classical measures 211 ms. At 100 ms one-way it is about 400 ms, and classical measures 418 ms. On a high-latency link the extra ~20-35 ms of PQC compute (and the extra segments) is a modest relative cost (roughly +17 % for PQC at 50 ms). On a local link the same compute is a roughly 10x slowdown (about 2 ms to about 25 ms).
- **Under the loss model the tail is what matters.** At 5 % loss the median classical handshake is 4.0 ms but p95 is about 207 ms, i.e. one 200 ms RTO stall. The larger PQC and hybrid messages span more segments, so they are hit more often (medians 23.5 ms and 33.9 ms, p95 of 243-250 ms). The std is large because the distribution is bimodal (stalled vs not stalled), so mean ± std is a poor summary here. Use the median and p95.

**Anomaly I did not hide:** the hybrid, 50 ms cell has std 163 ms and p99 1162 ms, against a median of 264 ms. The slow runs are contiguous bursts (run indices 39-41 and 57-64), which points to interference on the machine, not to anything specific to hybrid. I did not re-run or filter the data. For that cell, trust the median (264 ms) over the mean. The mode ordering at 50 ms (classical < pqc < hybrid) is therefore not reliable. Only the crypto-only table cleanly separates PQC from classical.

## 4. Throughput and application latency (`throughput_summary.csv`)
10 MB upload, MB/s with 1 MB = 10^6 B, mean ± std over 3 repetitions:

| Profile | classical | pqc | hybrid |
|---|---|---|---|
| direct | 206.7 ± 25.7 | 211.5 ± 5.3 | 198.3 ± 26.9 |
| proxy, 0 delay | 105.7 ± 9.4 | 105.5 ± 2.8 | 104.7 ± 3.1 |
| 50 ms one-way | 51.1 ± 5.1 | 54.8 ± 1.9 | 61.6 ± 6.0 |
| 100 ms one-way + 1 % loss | 13.8 ± 2.0 | 14.7 ± 0.5 | 13.9 ± 2.1 |
| 5 % loss | 14.1 ± 1.9 | 11.6 ± 0.1 | 11.6 ± 0.1 |

- After the handshake all three modes run the identical AES-256-GCM record layer, so throughput is expected to be mode-independent. The data agrees at the level of its noise. With only 3 repetitions the differences between modes (for example hybrid 61.6 vs classical 51.1 at 50 ms) are **not meaningful**. I would not claim any mode is faster.
- Throughput is governed by the network profile. The proxy roughly halves it (about 205 to about 105 MB/s). That is the cost of the extra hop and Python threads, not of the cryptography.
- Echo round-trip time tracks the profile (about 0.1-0.3 ms direct, about 102 ms at 50 ms one-way, about 205 ms at 100 ms one-way).

## 5. Limitations (state these in the report)
1. **Python and a pure-Python ML-KEM.** `kyber-py` is far slower than native liboqs. The absolute PQC cost (about 21 ms) is therefore **overstated** relative to a production stack, and the pqc/classical ratio of about 30x should not be quoted as "the cost of PQC". The liboqs code path exists but was not built or tested here.
2. **Localhost lab on a single machine.** There is no real NIC, and client, server and proxy share one Python process (one GIL, one CPU). CPU and memory figures are per process, not per host.
3. **Emulated loss is an RTO-stall approximation, not real packet loss.** Bytes are never dropped. Each lost 1460 B segment-equivalent stalls in-order delivery by a fixed 200 ms. There is no congestion-window collapse, fast retransmit or SACK, and the loss rate applies per segment-equivalent of each proxy read. The delay model is a lossless pipe with latency and no bandwidth cap, so throughput numbers under delay are optimistic. The TCP SYN exchange with the proxy is not delayed. Real `tc netem` in WSL2 was not used.
4. **A noisy, non-isolated machine.** Background load caused visible bursts (section 3). The 3-repetition throughput results have wide uncertainty.
5. **JSON/base64 framing** inflates wire bytes compared with a binary protocol.
6. **Fixed seed only controls the loss draws.** The cryptographic randomness is `os.urandom` and cannot be seeded, so runs are not bit-reproducible.
7. **Security scope:** Ed25519 authentication is classical (see `threat_model.md`), there is no rekeying, and this is a research prototype, not production cryptography.
