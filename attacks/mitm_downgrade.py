"""MITM downgrade attack: strip hybrid/PQC from the ClientHello.

Goal of the attacker: make both ends settle on classical-only so a future quantum
computer (or a harvested recording) can break the session.

Why it fails here:
  * The server signs H(ClientHello_as_received || ServerHello). The client checks
    that signature against the ClientHello it ACTUALLY SENT. The proxy changed the
    ClientHello, so the two hashes differ -> SIG_INVALID (client has no policy), or
    DOWNGRADE_DETECTED first if the client has min_mode set.
  * The attacker cannot re-sign: it lacks the server's Ed25519 private key.

Usage (own lab only):
    python -m attacks.mitm_downgrade --listen 9444 --upstream 127.0.0.1:9443
then point a client at port 9444 instead of 9443.
"""
from __future__ import annotations

import argparse
import json
import threading

from src.handshake import canonical
from src.wire import CLIENT_HELLO

from .relay import Frame, MitmProxy


class DowngradeProxy(MitmProxy):
    """Relay that rewrites ClientHello to offer only 'classical' and drops the ML-KEM key."""

    def __init__(self, upstream: tuple[str, int], **kw) -> None:
        super().__init__(upstream, c2s=self._strip, **kw)

    def _strip(self, frame: Frame) -> list[Frame]:
        if frame.kind == "hs" and frame.msg_type == CLIENT_HELLO:
            hello = json.loads(frame.data)
            before = list(hello["modes"])
            hello["modes"] = ["classical"]
            hello.pop("mlkem", None)
            self.trace.append(f"ClientHello rewritten: modes {before} -> ['classical'], ML-KEM key removed")
            return [Frame("hs", canonical(hello), frame.msg_type, frame.index)]
        return [frame]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--listen", type=int, default=9444)
    ap.add_argument("--upstream", default="127.0.0.1:9443")
    a = ap.parse_args()
    host, port = a.upstream.rsplit(":", 1)
    p = DowngradeProxy((host, int(port)), port=a.listen)
    p.start()
    print(f"downgrade MITM listening on 127.0.0.1:{p.port} -> {a.upstream}")
    threading.Event().wait()


if __name__ == "__main__":
    main()
