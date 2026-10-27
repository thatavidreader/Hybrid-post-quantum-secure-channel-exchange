"""Record-level attacks on an established session: tamper, replay, drop.

    tamper : flip one bit in the ciphertext of record N      -> expect BAD_TAG
    replay : deliver record N twice                           -> expect REPLAY_DETECTED
    drop   : silently delete record N                         -> expect SEQ_GAP

`direction` selects which way the attacked record travels ("c2s" attacks what the
server receives, "s2c" what the client receives). The attacker sees only
ciphertext; these attacks need no key, which is the point: AES-GCM + the explicit
sequence number make each one detectable.

Usage (own lab only):
    python -m attacks.tamper_replay --action replay --index 1 --listen 9445 --upstream 127.0.0.1:9443
"""
from __future__ import annotations

import argparse
import threading

from .relay import Frame, Hook, MitmProxy, passthrough


def make_hook(action: str, index: int, trace: list[str], direction: str) -> Hook:
    def hook(frame: Frame) -> list[Frame]:
        if frame.kind != "rec" or frame.index != index:
            return [frame]
        if action == "tamper":
            mutated = bytearray(frame.data)
            mutated[8] ^= 0x01  # first ciphertext byte (bytes 0-7 are the seq field)
            trace.append(f"{direction}: flipped 1 bit in ciphertext of record #{index}")
            return [Frame("rec", bytes(mutated), 0, frame.index)]
        if action == "replay":
            trace.append(f"{direction}: record #{index} delivered twice")
            return [frame, Frame("rec", frame.data, 0, frame.index)]
        if action == "drop":
            trace.append(f"{direction}: record #{index} dropped")
            return []
        return [frame]

    return hook


class RecordAttackProxy(MitmProxy):
    def __init__(self, upstream: tuple[str, int], action: str = "tamper", index: int = 1,
                 direction: str = "c2s", **kw) -> None:
        if action not in ("tamper", "replay", "drop") or direction not in ("c2s", "s2c"):
            raise ValueError("action in tamper|replay|drop, direction in c2s|s2c")
        super().__init__(upstream, **kw)
        hook = make_hook(action, index, self.trace, direction)
        self.c2s, self.s2c = (hook, passthrough) if direction == "c2s" else (passthrough, hook)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--action", choices=["tamper", "replay", "drop"], required=True)
    ap.add_argument("--index", type=int, default=1, help="0-based record index to attack")
    ap.add_argument("--direction", choices=["c2s", "s2c"], default="c2s")
    ap.add_argument("--listen", type=int, default=9445)
    ap.add_argument("--upstream", default="127.0.0.1:9443")
    a = ap.parse_args()
    host, port = a.upstream.rsplit(":", 1)
    p = RecordAttackProxy((host, int(port)), a.action, a.index, a.direction, port=a.listen)
    p.start()
    print(f"{a.action} MITM listening on 127.0.0.1:{p.port} -> {a.upstream}")
    threading.Event().wait()


if __name__ == "__main__":
    main()
