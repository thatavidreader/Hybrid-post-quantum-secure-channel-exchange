# Threat model

## 1. Assets
| Asset | Why it matters |
|---|---|
| Application data in transit | Confidentiality + integrity |
| Session keys (`c2s`, `s2c`) | Compromise = full session compromise |
| Server Ed25519 private key | Lets an attacker impersonate the server |
| Client's pinned server public key | If an attacker can replace it, authentication is void |
| Security event log | Evidence for detection/response |

## 2. Attacker capabilities
Dolev-Yao network attacker **on the path** between client and server: can read, drop, delay, replay, reorder, modify and inject any TCP payload (our `attacks/` proxies implement this). Also a **harvest-now-decrypt-later (HNDL)** adversary who records traffic today and gets a quantum computer later.

Out of scope: compromise of either endpoint or of the server's private key, side channels, denial of service, traffic analysis (record lengths are visible), and a real-time quantum attacker (see 4).

## 3. Threats and mitigations
| # | Threat | Mitigation in this prototype | Detected as | Test |
|---|---|---|---|---|
| T-1 | **HNDL**: recorded traffic decrypted later by a quantum computer | Hybrid key exchange: session key depends on X25519 *and* ML-KEM-768; secure if either holds | n/a (preventive) | T1 |
| T-2 | **Downgrade**: MITM strips hybrid/PQC from ClientHello to force classical | Server signs the transcript including the exact ClientHello it received; client verifies against the one it sent. Client policy `min_mode` rejects any weaker selected mode. Finished MACs + transcript-salted HKDF are a third check | `SIG_INVALID` (no policy) / `DOWNGRADE_DETECTED` (policy) | T6, T7, T8 |
| T-3 | **Server impersonation / forged signature** | Ed25519 key pinned in the client (no CA) | `SIG_INVALID` | T2 |
| T-4 | **Ciphertext tampering** | AES-256-GCM tag; AAD binds direction + sequence number | `BAD_TAG` | T3, T9 |
| T-5 | **Replay** of captured records | Explicit 64-bit sequence number per direction, strictly increasing; seq in nonce and AAD | `REPLAY_DETECTED` | T4, T10, T12 |
| T-6 | **Drop / reorder** of records | Gap in sequence numbers is fatal | `SEQ_GAP` | T5, T11 |
| T-7 | **Reflection** (record echoed back at its sender) | Separate keys and AAD labels per direction | `BAD_TAG` | `test_wrong_direction_reflection_rejected` |
| T-8 | **Handshake message tampering** (e.g. change selected mode, swap keys) | Covered by the signature; Finished MACs under keys derived from the transcript | `SIG_INVALID` / `HANDSHAKE_FAIL` | `test_tampered_server_hello_rejected`, `test_bad_finished_rejected` |
| T-9 | Oversize/malformed frames | Frame and handshake size caps; strict base64/length/JSON validation; errors are fatal | `HANDSHAKE_FAIL` / `BAD_TAG` | `test_garbage_client_hello_rejected` |

All record-layer errors are **fail-closed**: the connection is closed immediately and the event is logged.

## 4. What this design does NOT protect against (read this before the viva)

**Ed25519 authentication is not post-quantum.** The hybrid KEM protects the *confidentiality* of recorded traffic against harvest-now-decrypt-later: an attacker who records a session today cannot recover the key later without breaking both X25519 and ML-KEM-768. But the *authentication* is classical. A quantum adversary who can break Ed25519 **in real time, during the handshake**, could forge the server's signature and run an active man-in-the-middle attack, defeating both the pinning and the downgrade protection described above. Moving the signature to a post-quantum scheme such as **ML-DSA (FIPS 204)**, or to a hybrid Ed25519 + ML-DSA signature, is **future scope**. Until then, the downgrade protection holds against today's attackers and against any attacker who cannot yet forge Ed25519, which is the realistic window the HNDL threat model assumes.

Other limitations:
* **No forward secrecy for the long-term key**: the KEM keys are ephemeral (good), but there is no rekeying within a session and the 64-bit sequence space is not rolled over.
* **Pinning is manual**: key distribution/rotation/revocation is out of scope.
* **Server private key is stored unencrypted** in `keys/` (prototype). Use an HSM/KMS in practice.
* **Information leaks**: JSON message sizes and record lengths are visible; no padding.
* **Research prototype, not production crypto**: Python, a pure-Python ML-KEM (`kyber-py`) with no constant-time guarantees (the timing side channels of a pure-Python implementation are unmitigated), no formal verification, no external audit.
* **The server sends a generic alert only** on handshake failure and logs details locally, to avoid giving an attacker a decryption/validation oracle.
* Without a client `min_mode` policy a *legitimately* classical-only server is accepted (by design: the policy is the client's choice). The signature check stops a *MITM* from forcing that outcome; it cannot stop a server that is actually weak.
