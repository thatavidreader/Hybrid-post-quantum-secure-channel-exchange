"""JSON-lines security event logger + coloured console alerts.

One line per event:
  {"ts": "...Z", "event": "BAD_TAG", "role": "server", "peer": "127.0.0.1:5000",
   "mode": "hybrid", "backend": "kyber-py", "details": {...}}

WHY JSON lines: append-only, greppable, trivially parsed by log_summary.py and
by the tests (which read the in-memory copy instead of the file).
"""
from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .crypto_suite import backend_name

EVENTS = (
    "HANDSHAKE_OK", "HANDSHAKE_FAIL", "DOWNGRADE_DETECTED", "BAD_TAG",
    "REPLAY_DETECTED", "SIG_INVALID", "SEQ_GAP",
)

_RED, _YEL, _GRN, _CYN, _RST, _BOLD = "\033[91m", "\033[93m", "\033[92m", "\033[96m", "\033[0m", "\033[1m"
_COLOR = {
    "HANDSHAKE_OK": _GRN,
    "HANDSHAKE_FAIL": _YEL,
    "SEQ_GAP": _YEL,
    "DOWNGRADE_DETECTED": _RED,
    "BAD_TAG": _RED,
    "REPLAY_DETECTED": _RED,
    "SIG_INVALID": _RED,
}
_ATTACK_EVENTS = {"DOWNGRADE_DETECTED", "BAD_TAG", "REPLAY_DETECTED", "SIG_INVALID", "SEQ_GAP"}

if os.name == "nt":
    os.system("")  # enables ANSI escape processing in the Windows console


class SecurityLogger:
    def __init__(self, role: str, path: str | Path | None = None, console: bool = True) -> None:
        self.role = role
        self.path = Path(path) if path else None
        self.console = console
        self.events: list[dict[str, Any]] = []   # in-memory copy (used by tests)
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, peer: str = "-", mode: str | None = None, **details: Any) -> dict:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "event": event,
            "role": self.role,
            "peer": peer,
            "mode": mode,
            "backend": backend_name(),
            "details": details,
        }
        with self._lock:
            self.events.append(rec)
            if self.path:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            if self.console:
                self._print(rec)
        return rec

    def _print(self, rec: dict) -> None:
        color = _COLOR.get(rec["event"], _CYN)
        tag = "ALERT" if rec["event"] in _ATTACK_EVENTS else "info "
        reason = rec["details"].get("reason", "")
        extra = f" mode={rec['mode']}" if rec["mode"] else ""
        print(f"{color}{_BOLD}[{self.role.upper()} {tag}] {rec['event']}{_RST}{color} "
              f"peer={rec['peer']}{extra} {reason}{_RST}", flush=True)  # stdout: keeps ordering with demo text

    def count(self, event: str) -> int:
        with self._lock:
            return sum(1 for e in self.events if e["event"] == event)

    def event_names(self) -> list[str]:
        with self._lock:
            return [e["event"] for e in self.events]
