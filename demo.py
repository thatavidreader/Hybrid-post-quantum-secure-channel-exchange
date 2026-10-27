"""Scripted live demo: normal session -> downgrade caught -> tamper caught -> replay caught.

Run via demo.sh (Linux/WSL/Git-Bash) or demo.ps1 (Windows PowerShell), or directly:
    python demo.py
Everything runs on localhost against our own server; logs go to results/demo_*.jsonl.
"""
from __future__ import annotations

import time
from pathlib import Path

from attacks.mitm_downgrade import DowngradeProxy
from attacks.tamper_replay import RecordAttackProxy
from src import crypto_suite as cs
from src.client import SecureClient
from src.crypto_suite import Mode
from src.handshake import HandshakeError
from src.log_summary import summarize
from src.logger import SecurityLogger
from src.record_layer import RecordError
from src.server import SecureServer
from src.wire import ConnectionClosed

BOLD, CYN, GRN, RST = "\033[1m", "\033[96m", "\033[92m", "\033[0m"
RES = Path("results")


def banner(title: str) -> None:
    print(f"\n{BOLD}{CYN}{'=' * 78}\n {title}\n{'=' * 78}{RST}", flush=True)


def settle() -> None:
    time.sleep(0.4)  # let the server thread print its alert before the next banner


def main() -> None:
    RES.mkdir(exist_ok=True)
    slog, clog = RES / "demo_server.log.jsonl", RES / "demo_client.log.jsonl"
    for p in (slog, clog):
        p.unlink(missing_ok=True)

    ident = cs.ServerIdentity.generate()
    server = SecureServer(ident, logger=SecurityLogger("server", slog))
    server.start()
    pin = ident.public_raw
    print(f"{BOLD}Server up on 127.0.0.1:{server.port}; ML-KEM backend = {cs.backend_name()}{RST}")

    def client(**kw) -> SecureClient:
        return SecureClient(pin, logger=SecurityLogger("client", clog), **kw)

    banner("1. NORMAL SESSION (client requires >= hybrid)")
    s = client(min_mode=Mode.HYBRID).connect("127.0.0.1", server.port)
    msg = b"hello over a hybrid X25519+ML-KEM-768 channel"
    reply = s.echo(msg)
    print(f"{GRN}negotiated mode={s.mode.value}, handshake={s.handshake_seconds*1e3:.1f} ms, "
          f"handshake wire bytes={s.wire_bytes_sent + s.wire_bytes_recv}, echo ok={reply == msg}{RST}")
    s.close(); settle()

    banner("2a. DOWNGRADE ATTACK, client policy min_mode=hybrid  -> expect DOWNGRADE_DETECTED")
    mitm = DowngradeProxy(("127.0.0.1", server.port)); mitm.start()
    try:
        client(min_mode=Mode.HYBRID).connect("127.0.0.1", mitm.port)
    except HandshakeError as e:
        print(f"attacker did: {mitm.trace[0]}\nclient aborted -> {type(e).__name__}")
    mitm.stop(); settle()

    banner("2b. DOWNGRADE ATTACK, NO client policy  -> expect SIG_INVALID (signed transcript mismatch)")
    mitm = DowngradeProxy(("127.0.0.1", server.port)); mitm.start()
    try:
        client().connect("127.0.0.1", mitm.port)
    except HandshakeError as e:
        print(f"attacker did: {mitm.trace[0]}\nclient aborted -> {type(e).__name__}")
    mitm.stop(); settle()

    banner("3. TAMPERED CIPHERTEXT (bit flip in record #1)  -> expect BAD_TAG at server")
    mitm = RecordAttackProxy(("127.0.0.1", server.port), "tamper", 1, "c2s"); mitm.start()
    s = client().connect("127.0.0.1", mitm.port)
    s.echo(b"first record is fine")
    try:
        s.echo(b"second record gets corrupted in flight")
    except (RecordError, ConnectionClosed, OSError):
        pass
    print(f"attacker did: {mitm.trace[0]}")
    mitm.stop(); settle()

    banner("4. REPLAYED RECORD (record #1 delivered twice)  -> expect REPLAY_DETECTED at server")
    mitm = RecordAttackProxy(("127.0.0.1", server.port), "replay", 1, "c2s"); mitm.start()
    s = client().connect("127.0.0.1", mitm.port)
    s.echo(b"first record"); s.echo(b"transfer 100 EUR to Mallory")
    print(f"attacker did: {mitm.trace[0]}")
    mitm.stop(); settle()

    banner("5. SECURITY LOG SUMMARY (log_summary)")
    for p in (slog, clog):
        print(f"{p}:")
        for ev, n in sorted(summarize([str(p)]).items()):
            print(f"   {ev:<20} {n}")
    server.stop()
    print(f"\n{BOLD}Demo complete.{RST} Raw logs: {slog}, {clog}")


if __name__ == "__main__":
    main()
