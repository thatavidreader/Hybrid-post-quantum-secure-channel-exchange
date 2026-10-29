# Results and Interpretation

*Feeds Report Chapter 5 (Experimental Results) and the findings/limitations paragraphs of Chapter 6 (Conclusion). Table and figure numbers follow the chapter-wise scheme required by the report guidelines (Table 5.x, Fig. 5.x).*

**Provenance.** Every number below is read from the CSVs in `results/` (`handshake_summary.csv`, `handshake_resources.csv`, `handshake_e2e_raw.csv`, `handshake_crypto_raw.csv`, `throughput_summary.csv`, `throughput_raw.csv`, `latency_raw.csv`) or from the pytest run recorded in `results/test_results.json`. Derived quantities (ratios, differences) are computed from those numbers and marked as derived. Nothing was estimated or taken from the literature.

**Test bed.** Intel Core i7-6600U (2.6 GHz), 32 GB RAM, Windows 11, Python 3.13.5, ML-KEM backend **`kyber-py` (pure Python)** throughout, client + server + emulator in one process on localhost. Handshake cells: n = 100 timed runs after 5 discarded warm-ups. Throughput cells: 3 repetitions of a 10 MB (10^7 B) upload. Loss draws use a fixed seed (1234).

---

## Executive Summary

1. **Security behaviour (46/46 tests pass).** All three modes complete a handshake and round-trip data correctly. Both downgrade cases are caught (policy `min_mode=hybrid` gives `DOWNGRADE_DETECTED`; a MITM-stripped ClientHello with no policy gives `SIG_INVALID`). Tampered ciphertext gives `BAD_TAG`, replayed records give `REPLAY_DETECTED`, dropped records give `SEQ_GAP`, and an unpinned server key gives `SIG_INVALID` (see `docs/test_matrix.md`).
2. **Handshake size.** Adding ML-KEM-768 grows the handshake from 256 B to 2464 B of raw cryptographic payload (9.6x), or from 514 B to 3447 B on the wire (6.7x). Hybrid adds only 64 B raw (118 B on the wire) on top of PQC-only.
3. **Handshake compute.** In this pure-Python implementation, the crypto-only handshake costs 0.73 ms (classical) vs 21.50 ms (PQC) and 21.09 ms (hybrid), about 29x. Hybrid is not measurably slower than PQC-only. This ratio is a property of the **pure-Python** backend and is not the cost of PQC in general.
4. **Network effect.** On a link with real latency the handshake is dominated by its four one-way message flights. At 50 ms one-way delay the median handshake is 210 ms (classical), 244 ms (PQC) and 264 ms (hybrid); at 100 ms one-way plus 1 % loss it is 410, 458 and 459 ms. The PQC/hybrid overhead shrinks from roughly 9-13x on a local link to roughly +12-26 % on the delayed links (derived from medians).
5. **Throughput.** After the handshake every mode runs the identical data path, and throughput is set by the emulated network and the Python I/O path, not by the key-exchange mode. Differences between modes in Table 5.5 are within run-to-run noise or confounded by run order (section 5.3).
6. **Known weak spots, stated up front.** The hybrid/50 ms cell contains slow bursts caused by interference on the test machine (p99 = 1162 ms against a median of 264 ms). The loss model is an approximation whose stalls overlap instead of accumulating, so loss costs are optimistic. Ed25519 authentication is classical. See section 5.4.

---

## 5.1 Mode-by-Mode Performance Analysis

### 5.1.1 Handshake bytes (deterministic)

*Table 5.1 - Handshake bytes on the wire (`handshake_summary.csv`, `handshake_e2e_raw.csv`)*

| Mode | Raw payload (B) | Total wire (B) | Wire client→server (B) | Wire server→client (B) |
|---|---|---|---|---|
| classical (X25519) | 256 | 514 | 210 | 304 |
| pqc (ML-KEM-768) | 2464 | 3447 | 1739 | 1708 |
| hybrid (X25519 + ML-KEM-768) | 2528 | 3565 | 1798 | 1767 |

*Raw* counts only the cryptographic fields (nonces, public keys, ciphertext, signature, Finished MACs). *Wire* counts everything sent: JSON, base64 and the 5-byte message framing.

- **PQC cost in bytes (derived):** raw 2464 / 256 = 9.6x; wire 3447 / 514 = 6.7x. The increase comes from the ML-KEM-768 encapsulation key (1184 B) and ciphertext (1088 B).
- **Hybrid vs PQC-only (derived):** +64 B raw (one 32 B X25519 public key in each direction) and +118 B on the wire.
- **Encoding overhead (derived):** wire / raw is 2.0x for classical, 1.40x for PQC and 1.41x for hybrid. The JSON/base64 encoding I chose for readability inflates small messages most; a binary encoding would move the wire column towards the raw column.

### 5.1.2 Crypto-only handshake time, CPU and memory

*Table 5.2 - Handshake without network (both state machines driven in-process; n = 100; `handshake_summary.csv`, `handshake_crypto_raw.csv`, `handshake_resources.csv`)*

| Mode | mean ± std (ms) | p50 (ms) | p95 (ms) | p99 (ms) | client share (ms) | server share (ms) | CPU (ms / Mcycles) | peak heap (KiB) |
|---|---|---|---|---|---|---|---|---|
| classical | 0.73 ± 0.27 | 0.60 | 1.25 | 1.63 | 0.41 | 0.32 | 0.69 / 1.87 | 5.9 |
| pqc | 21.50 ± 2.97 | 20.58 | 27.56 | 29.32 | 14.28 | 7.22 | 24.16 / 65.01 | 248.0 |
| hybrid | 21.09 ± 2.15 | 20.50 | 26.17 | 27.99 | 14.26 | 6.83 | 21.96 / 60.11 | 248.6 |

*Fig. 5.1 `results/plots/handshake_crypto_only.png`, Fig. 5.2 `results/plots/handshake_bytes.png`, Fig. 5.3 `results/plots/handshake_cpu_memory.png`.*

- **Ratio (derived):** PQC / classical = 21.50 / 0.73 ≈ 29x and hybrid / classical ≈ 29x (means).
- **Hybrid is not slower than PQC-only.** The two differ by 0.4 ms on a standard deviation of 2-3 ms, i.e. no measurable difference. The extra X25519 step costs well under 1 ms (the entire classical handshake takes 0.73 ms), so hybrid's extra security is practically free in compute terms here.
- **Where the time goes.** The client carries about two thirds of the PQC cost (14.3 ms vs 7.2 ms), because it performs ML-KEM key generation and decapsulation while the server performs only encapsulation.
- **CPU** is the wall time of a 300-handshake CPU-bound batch, cross-checked against exact cycle counts (`QueryProcessCycleTime`; 65 Mcycles at 2.6 GHz is about 25 ms, consistent). `time.process_time()` was rejected: it counted only about 1.5 s of a 3 s busy loop on this machine. Client and server share one process, so these figures are per handshake for both sides together.
- **Memory** is the tracemalloc peak of Python allocations only (mean of 20 handshakes): about 6 KiB classical vs about 248 KiB for PQC and hybrid. It excludes interpreter, library and socket memory.
- The crypto-only part was re-run after the CPU fix, while the end-to-end data of section 5.2 was collected in the earlier run. The crypto-only mean of the same operation differed between the two runs (PQC 27.1 ms first, 21.5 ms second), which indicates a machine that is not quiet. Compare orders of magnitude, not single milliseconds.

---

## 5.2 Profile and Latency Analysis

*Table 5.3 - End-to-end handshake time through the emulator, ms (client connect to Finished verified; n = 100 per cell; `handshake_summary.csv`).*

| Profile | Mode | mean ± std | p50 | p95 | p99 |
|---|---|---|---|---|---|
| direct (no proxy) | classical | 2.08 ± 0.36 | 2.01 | 2.76 | 3.35 |
| | pqc | 29.22 ± 10.23 | 25.66 | 43.68 | 75.43 |
| | hybrid | 24.77 ± 6.65 | 22.29 | 39.85 | 45.99 |
| proxy, 0 ms | classical | 2.93 ± 0.49 | 2.85 | 3.90 | 4.36 |
| | pqc | 26.08 ± 8.65 | 24.24 | 32.54 | 41.29 |
| | hybrid | 25.83 ± 3.89 | 24.57 | 34.60 | 41.32 |
| 50 ms one-way | classical | 211.52 ± 7.82 | 210.13 | 221.12 | 256.13 |
| | pqc | 246.58 ± 13.57 | 244.24 | 269.60 | 303.62 |
| | hybrid | 310.60 ± 162.77 | **264.16** | 595.85 | **1162.11** |
| 100 ms one-way + 1 % loss | classical | 418.29 ± 39.46 | 409.65 | 431.63 | 608.93 |
| | pqc | 469.18 ± 52.65 | 457.80 | 639.69 | 668.43 |
| | hybrid | 481.86 ± 72.41 | 459.38 | 658.35 | 676.58 |
| 5 % loss (no added delay) | classical | 48.62 ± 88.40 | 3.97 | 206.85 | 211.00 |
| | pqc | 79.39 ± 107.06 | 23.52 | 243.39 | 448.28 |
| | hybrid | 93.12 ± 103.19 | 33.91 | 250.20 | 431.30 |

*Fig. 5.4 `results/plots/handshake_e2e.png` (mean ± std), Fig. 5.5 `results/plots/handshake_e2e_p95.png` (p95).*

**Proxy overhead is visible and small.** For classical, the zero-delay proxy raises the mean from 2.08 to 2.93 ms (+0.85 ms). For PQC and hybrid the direct-vs-proxy differences are smaller than the standard deviations (for example PQC direct 29.22 ± 10.23 ms vs proxy 26.08 ± 8.65 ms), so no proxy overhead can be claimed for them.

**Latency dominates once the link is slow.** The handshake has four one-way message flights (ClientHello, ServerHello, ClientFinished, ServerFinished). At 50 ms one-way delay the minimum possible is 4 x 50 = 200 ms, and the classical median is 210.13 ms; at 100 ms one-way it is 4 x 100 = 400 ms and the classical median is 409.65 ms. The remainder of 10 ms is compute, framing and scheduling. The added cost of PQC/hybrid over classical (derived from medians) is therefore a modest relative increase on slow links and a large one on a local link:

*Table 5.4 - PQC/hybrid cost relative to classical (derived from medians in Table 5.3)*

| Profile | pqc − classical (ms) | hybrid − classical (ms) | pqc / classical | hybrid / classical |
|---|---|---|---|---|
| direct | +23.65 | +20.28 | 12.8x | 11.1x |
| proxy, 0 ms | +21.39 | +21.72 | 8.5x | 8.6x |
| 50 ms one-way | +34.11 | +54.03 | 1.16x (+16.2 %) | 1.26x (+25.7 %) |
| 100 ms + 1 % loss | +48.15 | +49.73 | 1.12x (+11.8 %) | 1.12x (+12.1 %) |

### The hybrid / 50 ms cell (median 264 ms, p99 1162 ms)

- **Headline value: the median, 264.16 ms.** Mean (310.60 ms), std (162.77 ms), p95 (595.85 ms) and p99 (1162.11 ms) of this cell are inflated by a few very slow runs (max 1292.43 ms). The other two modes in the same profile have p99 of 256.13 ms (classical) and 303.62 ms (PQC).
- **Evidence for machine interference, not protocol behaviour.** The slow runs (> 400 ms, a threshold chosen after looking at the data, used here for diagnosis only) are 11 of 100 and are *contiguous*: run indices 39-41 and 57-64. Slow runs clustered in time point to something else on the machine (a background task, thermal or scheduler effect), because a protocol effect would hit runs independently. The 89 remaining runs have a mean of 264.9 ms, close to the median of 264.16 ms (illustrative only; no table in this report excludes data).
- **No crypto or byte-count explanation exists for hybrid > PQC at 50 ms.** Crypto-only, hybrid and PQC are indistinguishable (21.09 vs 21.50 ms, Table 5.2), the wire difference is 118 B, and at 100 ms + 1 % loss the two medians differ by only 1.6 ms (458 vs 459 ms). The 20 ms gap between hybrid (264 ms) and PQC (244 ms) medians at 50 ms is therefore most likely residual interference. **The mode ordering classical < pqc < hybrid at 50 ms must not be presented as a finding.** Only the classical vs PQC/hybrid separation (Table 5.2) is solid.
- All data were kept as measured; nothing was removed or re-run to improve the cell.

### Loss profiles: read the median and p95, not the mean

At 5 % loss the classical handshake has a median of 3.97 ms but a p95 of 206.85 ms and a standard deviation (88.40 ms) larger than its median. The distribution is bimodal: runs that hit a modelled loss are delayed by one 200 ms retransmission timeout, the rest are unaffected. Larger messages span more modelled segments, so more of the PQC and hybrid handshakes are hit (medians 23.52 ms and 33.91 ms; p95 243.39 ms and 250.20 ms). With n = 100 and p99 equal to roughly the second-largest sample, p99 values (211-448 ms) are only indicative. These conclusions hold within the approximate loss model described in 5.4.

---

## 5.3 Throughput Evaluation

*Table 5.5 - 10 MB upload throughput, MB/s with 1 MB = 10^6 B (mean ± std over 3 repetitions; per-repetition min-max in brackets; `throughput_summary.csv`)*

| Profile | classical | pqc | hybrid |
|---|---|---|---|
| direct | 206.7 ± 25.7 (177.4-225.4) | 211.5 ± 5.3 (208.2-217.6) | 198.3 ± 26.9 (179.0-229.1) |
| proxy, 0 ms | 105.7 ± 9.4 (97.8-116.1) | 105.5 ± 2.8 (103.6-108.7) | 104.7 ± 3.1 (102.2-108.2) |
| 50 ms one-way | 51.1 ± 5.1 (45.2-54.3) | 54.8 ± 2.0 (52.8-56.7) | 61.6 ± 6.0 (56.9-68.4) |
| 100 ms + 1 % loss | 13.8 ± 2.0 (11.4-15.2) | 14.7 ± 0.5 (14.1-15.1) | 13.9 ± 2.1 (11.5-15.4) |
| 5 % loss | 14.1 ± 1.9 (11.9-15.3) | 11.6 ± 0.1 (11.5-11.7) | 11.6 ± 0.1 (11.6-11.7) |

*Fig. 5.6 `results/plots/throughput.png` (log scale).*

**Why the modes should be identical.** The key-exchange mode only determines how the two 32-byte directional keys are derived. After the handshake, every mode executes the same code: the same AES-256-GCM record sealing, the same 16 KiB records, the same `[4B length][8B seq][ciphertext + tag]` framing and the same socket path. No step of the data path depends on how the keys were obtained. Throughput therefore cannot depend on the mode except through the network and the host, which are the same for all three. This is an argument from the design, supported by the data below; it is not proven by 3 repetitions.

**What actually limits the rate.** The achieved rates (about 200 MB/s direct, about 105 MB/s through the proxy) are limited by the Python I/O path, the proxy's extra hop and threads, and the emulated network, not by AES-GCM itself. The proxy roughly halves throughput (206.7 → 105.7 MB/s for classical), and the emulated delay and loss lower it further. Note also that the measured transfer includes waiting for the server's confirmation, which costs one round trip: at 50 ms one-way delay (RTT about 100 ms) the whole 10 MB took only 0.15-0.22 s.

**What the data does and does not show.**
- With 3 repetitions the per-mode differences are not reliable evidence of any real effect. At 0 ms proxy the three means lie within about 1 MB/s of each other (104.7-105.7), and at 100 ms + 1 % loss within about 1 MB/s (13.8-14.7).
- Two cells look like differences: hybrid is higher at 50 ms (61.6 vs 51.1 MB/s, and the per-repetition ranges do not overlap), and classical is higher at 5 % loss (14.1 vs 11.6 MB/s). Both are unexplained by design (see above). The modes were measured one after another in a fixed order (classical, pqc, hybrid) in the same run, so any drift in machine load is confounded with the mode. Settling this would need interleaved runs and more repetitions, which I did not do.
- At 5 % loss the PQC and hybrid repetitions are tightly clustered (0.85-0.87 s each) while classical varies (0.65-0.84 s). This looks like an artefact of the loss model's discrete 200 ms stalls rather than of the mode, but I have not tested that explanation.

*Table 5.6 - Application round-trip time for a 64 B echo, ms (50 samples per cell; mean / p95; `throughput_summary.csv`, `latency_raw.csv`)*

| Profile | classical | pqc | hybrid |
|---|---|---|---|
| direct | 0.23 / 0.28 | 0.14 / 0.19 | 0.12 / 0.15 |
| proxy, 0 ms | 0.26 / 0.32 | 0.30 / 0.41 | 0.26 / 0.32 |
| 50 ms one-way | 102.63 / 103.16 | 103.36 / 103.52 | 102.34 / 103.23 |
| 100 ms + 1 % loss | 207.22 / 204.62 | 206.36 / 203.35 | 202.31 / 203.11 |
| 5 % loss | 12.46 / 111.64 | 25.05 / 201.80 | 8.84 / 1.84 |

*Fig. 5.7 `results/plots/latency.png`.* Round-trip time tracks the emulated delay (2 x 50 ms gives about 102-103 ms) and does not depend on the mode. In the lossy cells the mean can exceed the p95 (for example hybrid at 5 % loss: mean 8.84 ms, p95 1.84 ms) because a few stalled samples among 50 dominate the mean; use the distribution in `latency_raw.csv`, not the mean, there.

---

## 5.4 Limitations and Caveats

1. **Pure-Python ML-KEM (`kyber-py`) overstates PQC compute cost.** The 29x crypto-only ratio and the 9-13x local handshake ratio are properties of this backend. A native implementation (liboqs, an optimised C library) would be much faster, but I did not measure one (liboqs could not be built on this machine), so I cannot give a native ratio and do not quote one. The liboqs code path in `src/crypto_suite.py` is written but untested. Also, `kyber-py` makes no constant-time guarantees, so timing side channels are not mitigated.
2. **Ed25519 authentication is not post-quantum.** The hybrid key exchange protects the confidentiality of *recorded* traffic against a future quantum attacker (harvest-now-decrypt-later). It does not protect against an attacker who can forge Ed25519 signatures *in real time during the handshake*: such an attacker could impersonate the server and defeat both key pinning and the signed-transcript downgrade protection. Replacing the signature with ML-DSA (FIPS 204), or a hybrid Ed25519 + ML-DSA signature, is future work (`docs/threat_model.md`, section 4). The downgrade protection reported here holds against attackers who cannot yet break Ed25519.
3. **The loss model is an approximation and is optimistic for bulk data.** The proxy never drops bytes. Each 1460 B segment-equivalent is "lost" with probability p and then delays in-order delivery by one 200 ms retransmission timeout. Delays are computed from each chunk's read time, so stalls on chunks read back-to-back **overlap instead of adding up**. Evidence: a 10 MB upload at 5 % loss finished in 0.65-0.87 s, whereas about 340 serial 200 ms stalls (6850 segments x 5 %) would take about 68 s (derived). Real TCP would also suffer congestion-window collapse and repeated losses. Treat loss results as qualitative (they show that tail latency rises sharply and that larger handshakes are hit more often), not as predictions of real packet loss. The emulated delay is a lossless, unlimited-bandwidth pipe, so throughput under delay is optimistic too. Real `tc netem` (WSL2/Linux) was not used.
4. **Single machine, one process, noisy host.** Client, server and proxy share one Python process and one CPU; there is no real network interface. The host was not isolated, which produced the slow bursts in section 5.2 and the run-to-run differences in 5.1.2. Throughput has only 3 repetitions per cell.
5. **Encoding choice inflates wire bytes** (JSON/base64, 1.4-2.0x over raw; Table 5.1).
6. **Randomness cannot be seeded.** The fixed seed controls only the emulated loss draws; cryptographic randomness is `os.urandom`, so runs are not bit-reproducible.
7. **Scope of the security tests.** The 46 tests cover the listed scenarios against this implementation in a controlled localhost lab. They are not a proof of security, no formal verification or external audit was done, and denial of service and side channels are out of scope. This is a research prototype and not production cryptography.
8. **Not covered:** rekeying within a session, certificate-based trust (the client pins a raw key), and measurements of memory beyond the Python heap.
