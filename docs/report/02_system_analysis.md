# CHAPTER 2: SYSTEM ANALYSIS

This chapter reviews existing systems and standards for post-quantum key exchange (2.1), lists the functional requirements of the proposed secure channel (2.2), describes the proposed system (2.3) and assesses feasibility and the execution plan (2.4).

---

## 2.1 EXISTING SYSTEM

> **How to use this section.** I did not search for or read any papers while building this project, so this section contains **structure, prompts and the claims to support**, not citations. Under each heading: read the listed source, replace each `[CITE-n: ...]` with the real reference in the numbering order of first appearance (Guidelines: `[n]` in text, numbered serially), and rewrite the "Points to verify" in your own words. The rubric rewards *critical analysis, limitations and research gaps*, so keep the "Limitation" lines and the gap table in 2.1.8. Remove all prompt text before submission.

### 2.1.1 The quantum threat to current key exchange
- **Cover:** RSA/ECDH security assumptions; Shor's algorithm; harvest-now-decrypt-later.
- **Points to verify:** which public-key primitives are affected and which symmetric primitives (AES-256, SHA-256) are only weakened by Grover's algorithm rather than broken.
- **Sources to find:** [CITE-1: Shor's algorithm paper], [CITE-2: a government or industry guidance document on HNDL, e.g. NIST or NSA/NCSC migration advice].
- **Limitation to state:** timeline of large quantum computers is uncertain; HNDL makes the risk present regardless.

### 2.1.2 NIST post-quantum standardisation
- **Cover:** the NIST PQC competition rounds; the 2024 standards FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).
- **Points to verify:** exact publication dates and document names; the security categories (ML-KEM-512/768/1024) and why this project chooses ML-KEM-768.
- **Sources:** [CITE-3: FIPS 203], [CITE-6: FIPS 204], [CITE-7: NIST PQC project/report].
- **Limitation to state:** the standards are new; implementations are less mature than classical ones.

### 2.1.3 ML-KEM / CRYSTALS-Kyber
- **Cover:** key encapsulation (KeyGen, Encaps, Decaps), the module-LWE basis, sizes of the ML-KEM-768 encapsulation key (1184 B), ciphertext (1088 B) and shared secret (32 B) (these sizes are verified by this project's tests), implicit rejection of invalid ciphertexts.
- **Sources:** [CITE-8: Kyber / CRYSTALS-Kyber submission or paper], [CITE-3: FIPS 203].
- **Limitation to state:** larger keys and ciphertexts than elliptic curves; implementation correctness and constant-time execution matter.

### 2.1.4 Hybrid key exchange (ECDH + Kyber / ML-KEM)
- **Cover:** why combine a classical and a post-quantum secret; combiner design (concatenate the secrets and feed a KDF bound to the transcript); early experiments with ECDH plus Kyber and the current X25519 + ML-KEM-768 combination.
- **Points to verify:** what security guarantee a concatenation combiner gives and under what assumptions; how the IETF hybrid design draft and any published hybrid-KEM constructions (e.g. X-Wing) handle it.
- **Sources:** [CITE-4: IETF hybrid key exchange design document for TLS 1.3], [CITE-9: hybrid KEM combiner security analysis paper(s)].
- **Limitation to state:** extra bytes and computation; a hybrid is only as good as its combiner and KDF binding.

### 2.1.5 Deployments and TLS 1.3 post-quantum extensions
- **Cover:** how TLS 1.3 negotiates key-exchange groups, how hybrid groups (X25519 with ML-KEM-768) are specified and deployed in browsers/CDNs, how TLS 1.3 protects against downgrade (transcript signing, downgrade sentinel values, Finished messages), and comparable work such as the Open Quantum Safe project and its OpenSSL provider.
- **Sources:** [CITE-5: TLS 1.3, RFC 8446], [CITE-10: IETF draft/RFC for X25519MLKEM768 in TLS], [CITE-11: Open Quantum Safe / liboqs documentation], [CITE-12: published measurements of PQC/hybrid TLS handshake cost].
- **Limitation to state:** TLS is large and complex; its authentication still relies on classical (or newly added post-quantum) certificates and a PKI, which this project replaces by key pinning for simplicity.

### 2.1.6 Authenticated record layers
- **Cover:** how existing protocols protect data after the handshake. Authenticated encryption with associated data (AEAD, here AES-256-GCM), per-record nonces built from a sequence number, replay protection by sequence numbers (TLS 1.3 record layer, SSH) or by sliding windows (DTLS, IPsec ESP), and the rule that any authentication failure closes the connection.
- **Points to verify:** how TLS 1.3 forms the per-record nonce, why nonce reuse under GCM is catastrophic, and what binding the sequence number into the AAD adds on top of the nonce. Compare with this project's design: an explicit 8-byte sequence number in every frame, separate keys per direction, and three distinct outcomes (`BAD_TAG`, `REPLAY_DETECTED`, `SEQ_GAP`).
- **Sources:** [CITE-13: NIST SP 800-38D, GCM], [CITE-14: AEAD interface, RFC 5116], [CITE-5: RFC 8446 section on record protection], [CITE-15: DTLS or IPsec ESP anti-replay description].
- **Limitation to state:** a stream protocol such as TCP needs only strict in-order sequence numbers, so this project does not implement a replay window; the 64-bit counter is not rekeyed within a session.

### 2.1.7 References to look up (standards; verify details before citing)
FIPS 203 (ML-KEM); FIPS 204 (ML-DSA); RFC 7748 (X25519); RFC 8032 (Ed25519); RFC 5869 (HKDF); RFC 5116 (AEAD); NIST SP 800-38D (GCM); RFC 8446 (TLS 1.3); the IETF TLS hybrid design draft; liboqs documentation; plus **at least 3 to 5 published papers** on PQC or hybrid handshake performance or downgrade attacks, chosen after you have read them.

### 2.1.8 Gap analysis (keep; fill the "Evidence" column with your citations)

| Existing approach | What it provides | Limitation relevant to this project | Gap addressed by this project |
|---|---|---|---|
| Classical-only key exchange (X25519/ECDH) | Fast, small messages | Vulnerable to harvest-now-decrypt-later | Hybrid mode adds ML-KEM-768 |
| PQC-only key exchange | Quantum-resistant | Relies solely on a young algorithm; no classical fallback if it is broken | Hybrid is secure if either component holds |
| Hybrid groups in TLS 1.3 deployments | Standardised, deployed | Full TLS stack is heavy; behaviour of downgrade and overhead is hard to study in isolation | A small, readable prototype with explicit attacks and measurements |
| Negotiation without downgrade protection | Flexible | Active attacker can force a weaker mode | Signed transcript + client `min_mode` policy; both cases tested |
| Performance claims in the literature | Typically native, optimised implementations | Not directly comparable to Python; network conditions vary | Measured cost of three modes under delay and loss, with limitations stated |

**Evidence:** [CITE: ...] in each row.

---

## 2.2 FUNCTIONAL REQUIREMENTS

| ID | Requirement | Implemented in | Verified by |
|---|---|---|---|
| FR1 | The server and client shall support the modes `classical`, `pqc` and `hybrid`, and the server shall select the strongest mode both support | `src/handshake.py`, `src/crypto_suite.py` | T1, `test_negotiates_strongest_mutual_mode` |
| FR2 | The handshake shall be ClientHello, ServerHello (with an Ed25519 signature over the transcript), ClientFinished, ServerFinished | `src/handshake.py`, `src/wire.py` | handshake tests |
| FR3 | The client shall verify the signature against a **pinned** server public key and abort otherwise | `src/handshake.py` | T2 |
| FR4 | Session keys shall be derived with HKDF-SHA256 over the concatenated shared secrets, with the transcript hash as salt, giving separate client-to-server and server-to-client keys | `src/crypto_suite.py` | `test_kdf_directional_and_transcript_bound` |
| FR5 | The client shall support a configurable minimum mode and abort with `DOWNGRADE_DETECTED` if the negotiated mode is weaker | `src/handshake.py`, `src/client.py` | T6, T8 |
| FR6 | A MITM that edits the ClientHello shall be detected through the signature check (`SIG_INVALID`) even without a policy | `src/handshake.py` | T7 |
| FR7 | Application data shall be protected as AES-256-GCM records `[4B len][8B seq][ciphertext+tag]` with the sequence number bound into the nonce and AAD | `src/record_layer.py` | record-layer tests |
| FR8 | The receiver shall reject a bad tag (`BAD_TAG`), an old sequence number (`REPLAY_DETECTED`) and a future sequence number (`SEQ_GAP`), and close the connection | `src/record_layer.py`, `src/server.py` | T3-T5, T9-T12 |
| FR9 | Security events shall be written as JSON lines (timestamp, event, peer, mode, backend, details) with real-time coloured alerts and a summary tool | `src/logger.py`, `src/log_summary.py` | logger tests |
| FR10 | The system shall provide attack tools (downgrade MITM, tamper, replay, drop) for use against the local server | `attacks/` | T7-T12 |
| FR11 | The system shall provide benchmarks for handshake time, bytes, CPU, memory and throughput under network profiles | `bench/` | `results/*.csv` |
| FR12 | The system shall run on Windows without root privileges and provide a one-command demonstration | `demo.ps1`, `demo.sh` | demo output |

**Non-functional requirements:** reproducibility (virtual environment, `requirements.txt`, fixed loss seed); explainability (docstrings explain *why*); honesty about limitations; no custom cryptographic primitives (all primitives come from the `cryptography` and `kyber-py` libraries).

---

## 2.3 PROPOSED SYSTEM

The proposed system is a client-server secure channel in which the client and server run a four-message handshake to agree on a mode and derive session keys, and then exchange AES-256-GCM-protected records.

- **Key exchange:** classical X25519, post-quantum ML-KEM-768, or both; in hybrid mode the two shared secrets are concatenated and passed to HKDF-SHA256 together with the transcript hash.
- **Authentication and downgrade protection:** the server signs the hash of (ClientHello exactly as received, ServerHello); the client verifies the signature under the pinned key against the ClientHello *it sent*. A modified ClientHello therefore yields a signature mismatch. Finished MACs over the transcript, under keys derived from it, give a second independent check, and a client policy `min_mode` rejects any weaker negotiated mode.
- **Record protection:** AES-256-GCM, separate directional keys, explicit 64-bit sequence numbers, a 16 KiB record size and fail-closed handling of every record error.
- **Observability:** JSON-lines security log, coloured alerts and a log summary tool.
- **Evaluation harness:** attack proxies and a delay/loss emulation proxy, automated tests, and benchmark scripts producing CSVs and charts.

The full design is in Chapter 3 and `docs/architecture.md`.

---

## 2.4 FEASIBILITY STUDY AND PROJECT PLAN

### 2.4.1 Technical feasibility
- **Required technology is available and mature enough:** Python 3.10+ (3.13.5 used), the `cryptography` package (X25519, Ed25519, HKDF, AES-GCM), `kyber-py` (pure-Python ML-KEM-768, FIPS 203), pytest and matplotlib.
- **Risk that materialised and its mitigation:** the native liboqs library could not be built on the development machine (no CMake or build toolchain, no prebuilt Windows wheel). The design therefore hides the KEM behind an interface and falls back to the pure-Python `kyber-py` backend. The backend used is recorded in every log line and CSV, and the consequences (slower PQC operations) are stated in the limitations rather than hidden. Verified by an actual ML-KEM-768 key exchange on the target machine before any protocol code was written.
- **Network emulation:** real `tc netem` needs Linux and root; WSL2 had no distribution installed. A pure-Python delay/loss proxy was built instead, so every benchmark runs without root. Its loss model is an approximation (5.4).
- **Conclusion:** technically feasible with the stated limitations.

### 2.4.2 Operational feasibility
- Runs on an ordinary Windows 11 laptop with a Python virtual environment; no root, no external services, no network access needed after installing dependencies.
- One-command demonstration (`demo.ps1` on Windows, `demo.sh` on Linux/WSL), automated test suite (46 tests, about 1 s) and documented benchmark commands.
- All attacks target only the project's own server on localhost in an authorised laboratory, as required by the course rubric.

### 2.4.3 Economic feasibility
- **Software cost:** none. All components are free and open source (Python, `cryptography`, `kyber-py`, pytest, matplotlib, Git).
- **Hardware cost:** none beyond an existing laptop (benchmarks were run on an Intel Core i7-6600U, 2.6 GHz, 32 GB RAM). No cloud resources, licences or specialised devices.
- **Effort:** one student team over the project window; the main cost is time.
- **Conclusion:** economically feasible at effectively zero direct cost.

### 2.4.4 Time/schedule feasibility and execution plan
The deadline is 2 November 2026. The work was organised as ordered milestones, each ending with passing tests before the next began.

| Milestone | Work | Output / acceptance check |
|---|---|---|
| M0 | Environment check; test whether liboqs builds and ML-KEM works | Environment report; fallback decision (`kyber-py`) |
| M1 | `crypto_suite` (modes, KEM backends, X25519, Ed25519, HKDF, AEAD) | 6 unit tests pass |
| M2 | Handshake state machines | 11 handshake tests pass |
| M3 | Record layer (framing, sequence numbers, replay checks) | 9 record-layer tests pass |
| M4 | Server, client, logger, log summary | End-to-end tests in all three modes |
| M5 | Attack tools and attack tests; demo scripts | T7-T12 pass; demo runs |
| M6 | Benchmarks (handshake, throughput, emulator), plots | CSVs and charts from real runs |
| M7 | Documentation, test matrix, results interpretation, report | `docs/`, final report |

**Risks and mitigations:** native liboqs unavailable (mitigated: fallback backend, disclosed); noisy test machine affecting timing (mitigated: warm-up runs, n = 100, percentiles and medians reported, outliers disclosed); limited time (mitigated: milestone order with a working demo early).
