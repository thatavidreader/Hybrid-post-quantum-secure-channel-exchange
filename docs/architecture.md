# Architecture

## 1. Components
| Module | Responsibility | Key design point (say this in the viva) |
|---|---|---|
| `src/crypto_suite.py` | Mode enum, ML-KEM backend selection, X25519, Ed25519, HKDF key schedule, AES-GCM | No custom primitives; `get_kem()` uses liboqs if importable, else `kyber-py`; the backend name is stamped on every log line and CSV |
| `src/handshake.py` | Sans-IO client/server handshake state machines | No sockets inside, so they are unit-testable and the crypto-only benchmark can drive them directly |
| `src/wire.py` | `[1B type][4B len][payload]` framing for handshake messages, `recv_exact` | TCP is a stream, so reads must loop until n bytes arrive |
| `src/record_layer.py` | `[4B len][8B seq][ciphertext+tag]` records, AES-256-GCM, replay/gap checks | Authenticate first, then classify (BAD_TAG vs REPLAY vs SEQ_GAP) |
| `src/server.py`, `src/client.py` | Threaded TCP server; client with `min_mode` policy; tiny echo/sink application protocol | Any integrity error closes the connection (fail closed) |
| `src/logger.py`, `src/log_summary.py` | JSON-lines events + coloured console alerts; summary counts | Backend recorded in every line |
| `attacks/relay.py` | Frame-aware MITM relay with per-frame hooks | One engine, two attack modules |
| `attacks/mitm_downgrade.py`, `attacks/tamper_replay.py` | The attacks | Used by both tests and demo |
| `bench/` | Handshake + throughput benchmarks, delay/loss emulation, plots | Crypto-only vs end-to-end vs proxy-overhead measured separately |

## 2. Message flow
```
Client                                                   Server
  | ClientHello {modes, nonce_c, x25519_pub?, mlkem_ek?}   |
  |------------------------------------------------------->|  pick strongest mutual mode
  |                                                        |  X25519 DH and/or ML-KEM encaps
  |                                                        |  th = SHA256(CH_bytes || SH_body)
  |                                                        |  sig = Ed25519(th)   keys = HKDF(secrets, salt=th)
  |<-------------------------------------------------------|
  |  ServerHello {mode, nonce_s, x25519_pub?, mlkem_ct?, sig}
  | policy check (min_mode) -> verify sig vs PINNED key    |
  | derive same keys; MAC_c = HMAC(fin_c, H(CH||SH))       |
  | ClientFinished {mac}                                   |
  |------------------------------------------------------->|  verify MAC_c
  |<-------------------------------------------------------|
  |  ServerFinished {mac}                                  |
  | verify MAC_s                                           |
  |================ encrypted records (AES-256-GCM) =======|
```
Client checks, in order: structure -> mode was offered -> **policy** -> **signature** -> key agreement -> Finished.

## 3. Key schedule
```
IKM  = ss_x25519 || ss_mlkem        (only the secrets of the chosen mode, in this order)
salt = th = SHA256(ClientHello || ServerHello-without-sig)
OKM  = HKDF-SHA256(IKM, salt, info="PQSC1 key schedule|<mode>", L=136)
       -> c2s_key(32) s2c_key(32) c2s_iv(4) s2c_iv(4) finished_c(32) finished_s(32)
```
Hybrid: the shared secrets are concatenated (the KEM public key, ciphertext, and X25519 shares are all in the hashed transcript, so the concatenation combiner is sound). The result is secure if *either* X25519 or ML-KEM remains unbroken.

## 4. Record layer
`nonce = iv(4B per direction) || seq(8B)`; `AAD = "PQSC1 record" || "c2s"|"s2c" || seq`.
Receiver: authenticate under claimed seq (fail → `BAD_TAG`), then `seq < expected` → `REPLAY_DETECTED`, `seq > expected` → `SEQ_GAP`, else accept.

## 5. Protocol refinements vs. the original brief (and why)
1. **Authenticate-then-classify** in the receiver, so tampering with the visible `seq` field yields BAD_TAG, not a bogus "replay".
2. **Policy check before signature check** in the client: for a MITM-stripped hello with `min_mode` set the client reports `DOWNGRADE_DETECTED`; without a policy it reports `SIG_INVALID`. Both abort. (Both documented cases are tested: T7, T8.)
3. **Finished MAC covers the full ServerHello (incl. signature)**; the signature covers the ServerHello without itself.
4. **Server alert is generic** (`handshake_failure`); details only in the local log.
5. **JSON/base64 encoding** was chosen for readability; the benchmark reports raw and wire bytes so the overhead is explicit.
6. Extra module `src/wire.py` (framing helpers) and `bench/common.py` (stats/CSV/lab) were added to avoid duplication.
7. ML-KEM backend: `kyber-py` (pure Python) is the default on this machine because liboqs could not be built (no CMake); see README.
