# CHAPTER 1: INTRODUCTION

This chapter explains why post-quantum protection of network traffic matters, states the specific security problem this project addresses, and lists the measurable objectives against which the finished system is judged in Chapter 5. Statements marked **[CITE-n]** are general-knowledge claims that need a reference in the final report (see the reference list in `docs/report/02_system_analysis.md`, section 2.1.7).

## 1.1 BACKGROUND

Almost all secure network communication (TLS, SSH, VPNs) establishes its session keys with public-key mechanisms whose security rests on the difficulty of factoring or of the discrete logarithm problem, such as RSA and elliptic-curve Diffie-Hellman. Shor's algorithm would solve both problems efficiently on a sufficiently large quantum computer **[CITE-1]**. Such a machine does not exist today, but the threat is already relevant because of *harvest now, decrypt later* (HNDL): an adversary can record encrypted traffic today and decrypt it years later, once the capability exists. Data with a long confidentiality lifetime is therefore exposed now, independent of when quantum computers arrive **[CITE-2]**.

In response, the US National Institute of Standards and Technology (NIST) ran a multi-year standardisation process for post-quantum algorithms and published the first standards in 2024, among them FIPS 203, the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM, derived from CRYSTALS-Kyber), and FIPS 204 (ML-DSA) for signatures **[CITE-3]**. Because these algorithms are comparatively young, deployments favour a **hybrid** approach: combine a classical key exchange (here X25519) with a post-quantum KEM (here ML-KEM-768) so that the session key stays secure if *either* component survives **[CITE-4]**.

Hybrid and post-quantum modes bring two practical issues that this project studies:

1. **Negotiation and downgrade.** When peers can support several algorithms, an active attacker may try to strip the strongest option from the negotiation so that both sides fall back to a classical one that can later be broken. Downgrade protection has long been a design concern in TLS **[CITE-5]**.
2. **Cost.** Post-quantum keys and ciphertexts are far larger than elliptic-curve ones (about 1 kB for ML-KEM-768 versus 32 B for X25519) and their computation differs, so the cost in handshake size, time, CPU and memory under realistic network conditions must be measured, not assumed.

## 1.2 PROBLEM STATEMENT

Existing secure channels that use only classical key exchange are vulnerable to harvest-now-decrypt-later attacks, and naive migration to post-quantum or hybrid mechanisms introduces a negotiation step that an active man-in-the-middle can attack by forcing a classical fallback. In addition, the performance cost of post-quantum and hybrid key exchange is often unclear to system designers.

The problem addressed here is therefore:

> *Design, implement and evaluate a secure channel that (a) derives session keys with a hybrid X25519 + ML-KEM-768 exchange, (b) detects and rejects downgrade, tampering, replay and record-dropping attacks, and (c) quantifies the cost of classical, post-quantum-only and hybrid modes under varying network conditions.*

**Scope.** A research prototype running on a single machine in an authorised local laboratory. Out of scope: production hardening, certificate infrastructure, denial of service, side-channel attacks, and post-quantum *authentication* (see 5.4 and the threat model).

## 1.3 OBJECTIVES

| # | Objective | How it is verified | Result location |
|---|---|---|---|
| O1 | Implement three negotiable modes: classical (X25519), PQC (ML-KEM-768), hybrid | Normal-operation tests T1 in all three modes | `docs/test_matrix.md` |
| O2 | Derive separate directional session keys with HKDF-SHA256 bound to the handshake transcript, and protect data with AES-256-GCM | Handshake and record-layer unit tests | `tests/test_handshake.py`, `tests/test_record_layer.py` |
| O3 | Authenticate the server with a pinned Ed25519 key over a signed transcript | Unpinned-key test (T2) | `docs/test_matrix.md` |
| O4 | Detect downgrade attacks by (a) a client minimum-mode policy and (b) transcript signature mismatch | Tests T6, T7, T8 | `docs/test_matrix.md` |
| O5 | Reject tampered, replayed and dropped records with distinct events (`BAD_TAG`, `REPLAY_DETECTED`, `SEQ_GAP`) | Tests T3-T5, T9-T12 | `docs/test_matrix.md` |
| O6 | Log every security event as JSON lines with colour-coded real-time alerts and a summary tool | Logger tests, demo output | `src/logger.py`, `results/demo_output.txt` |
| O7 | Measure handshake time (mean, std, p95, p99, n = 100), handshake bytes (raw and wire), CPU, memory and 10 MB throughput for the three modes under four network profiles plus a baseline | Benchmarks with raw CSVs and plots | `docs/results_interpretation.md`, `results/` |
| O8 | Provide a reproducible setup and a one-command demonstration | README, `demo.ps1` / `demo.sh` | Repository |
| O9 | State limitations honestly (pure-Python ML-KEM, localhost, approximate loss, classical authentication) | Limitations section | 5.4 |

**Organisation of the report.** Chapter 2 analyses existing systems and states the requirements and feasibility; Chapter 3 presents the design, topology and threat model; Chapter 4 describes the implementation; Chapter 5 gives test and benchmark results; Chapter 6 concludes.
