"""Network-condition emulation: pure-Python TCP proxy (default) + `tc netem` wrappers.

IMPORTANT - what the pure-Python proxy does and does NOT model
---------------------------------------------------------------
* DELAY: every chunk read from one side is released to the other side after a
  fixed ONE-WAY delay. Chunks stay in order. A profile with delay_ms=50 therefore
  gives an RTT of ~100 ms (same as `tc netem delay 50ms` on a loopback device,
  where both directions cross the qdisc). The TCP three-way handshake with the
  proxy itself is not delayed (only payload is).
* LOSS is an **RTO-stall approximation, not real packet loss.** Bytes are never
  dropped (the kernel's TCP between proxy and endpoints is lossless). Instead each
  1460-byte segment-equivalent of a chunk is "lost" with probability p, and every
  lost segment stalls delivery of that chunk by one retransmission timeout
  (RTO = 200 ms, Linux's minimum), and because TCP is in-order it also stalls
  everything behind it (head-of-line blocking). Stalls are computed from each chunk's READ time,
  so chunks that the proxy reads back-to-back have overlapping (not serially
  accumulating) stalls: a bulk transfer therefore pays roughly the largest stall,
  not the sum. (Measured: 10 MB at 5 % loss finished in ~0.9 s, whereas ~340
  serial 200 ms stalls would take ~68 s.) It also ignores congestion-window
  collapse, fast retransmit, SACK and repeated losses of the same segment, so
  it is a qualitative, probably optimistic model of loss cost for bulk data, not
  a replacement for a real netem run.
* No bandwidth limit and no queue limit (infinite pipe with latency).
* Loss draws use a seeded RNG, so a given (seed, traffic pattern) is reproducible.

`tc netem` (real kernel emulation) needs Linux + root, i.e. WSL2 with a distro
installed. `tc_commands()` prints the exact commands; `apply_tc()` runs them.
"""
from __future__ import annotations

import queue
import random
import socket
import subprocess
import threading
import time
from dataclasses import dataclass

MSS = 1460
RTO_S = 0.200


@dataclass(frozen=True)
class Profile:
    name: str
    delay_ms: float = 0.0      # one-way delay
    loss_pct: float = 0.0
    use_proxy: bool = True     # False = connect directly (no proxy at all)
    description: str = ""

    @property
    def rtt_ms(self) -> float:
        return 2 * self.delay_ms


PROFILES: tuple[Profile, ...] = (
    Profile("baseline", use_proxy=False, description="direct localhost TCP, no proxy"),
    Profile("proxy_0ms", description="through the emulator, zero delay/loss (isolates proxy overhead)"),
    Profile("delay_50ms", delay_ms=50, description="50 ms one-way delay (RTT ~100 ms)"),
    Profile("delay_100ms_loss_1pct", delay_ms=100, loss_pct=1.0,
            description="100 ms one-way delay (RTT ~200 ms) + 1 % loss (RTO-stall model)"),
    Profile("loss_5pct", loss_pct=5.0, description="5 % loss (RTO-stall model), no extra delay"),
)
PROFILE_BY_NAME = {p.name: p for p in PROFILES}


class _Pipe:
    """One direction: a reader (recv -> compute release time -> queue) and a writer thread."""

    def __init__(self, src: socket.socket, dst: socket.socket, profile: Profile, rng: random.Random,
                 stats: dict) -> None:
        self.src, self.dst, self.p, self.rng, self.stats = src, dst, profile, rng, stats
        self.q: queue.Queue = queue.Queue()
        self._last_release = 0.0

    def _release_time(self, nbytes: int) -> float:
        now = time.perf_counter()
        stall = 0.0
        if self.p.loss_pct > 0:
            for _ in range((nbytes + MSS - 1) // MSS):
                if self.rng.random() * 100 < self.p.loss_pct:
                    stall += RTO_S
                    self.stats["loss_events"] += 1
        # max(): in-order delivery - a stalled chunk blocks everything queued behind it
        self._last_release = max(self._last_release, now + self.p.delay_ms / 1000 + stall)
        return self._last_release

    def _writer(self) -> None:
        try:
            while True:
                item = self.q.get()
                if item is None:
                    break
                release, data = item
                wait = release - time.perf_counter()
                if wait > 0:
                    time.sleep(wait)
                self.dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                self.dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def run(self) -> None:
        w = threading.Thread(target=self._writer, daemon=True)
        w.start()
        try:
            while True:
                data = self.src.recv(65536)
                if not data:
                    break
                self.stats["bytes"] += len(data)
                self.q.put((self._release_time(len(data)), data))
        except OSError:
            pass
        finally:
            self.q.put(None)
            w.join()


class NetemProxy:
    """Delay/loss TCP proxy in front of `upstream`; one instance serves many connections."""

    def __init__(self, upstream: tuple[str, int], profile: Profile, seed: int = 1234) -> None:
        self.upstream, self.profile, self.seed = upstream, profile, seed
        self.port = 0
        self.stats = {"bytes": 0, "loss_events": 0}
        self._sock: socket.socket | None = None
        self._n = 0
        self._stop = threading.Event()

    def start(self) -> None:
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(64)
        self.port = s.getsockname()[1]
        self._sock = s
        threading.Thread(target=self._accept, daemon=True, name="netem-accept").start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()

    def _accept(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
                server = socket.create_connection(self.upstream)
            except OSError:
                return
            for s in (client, server):
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._n += 1
            # distinct but reproducible RNG stream per connection and direction
            shared = {"done": 0, "lock": threading.Lock()}
            for i, (a, b) in enumerate(((client, server), (server, client))):
                rng = random.Random(self.seed * 1_000_003 + self._n * 2 + i)
                threading.Thread(target=self._run_pipe,
                                 args=(_Pipe(a, b, self.profile, rng, self.stats), client, server, shared),
                                 daemon=True).start()

    @staticmethod
    def _run_pipe(pipe: _Pipe, client: socket.socket, server: socket.socket, shared: dict) -> None:
        pipe.run()  # returns after this direction hit EOF and flushed (it half-closes its destination)
        with shared["lock"]:
            shared["done"] += 1
            if shared["done"] == 2:  # both directions finished -> release the file descriptors
                for s in (client, server):
                    try:
                        s.close()
                    except OSError:
                        pass


# --------------------------------------------------------------------------- real netem (Linux only)
def tc_commands(profile: Profile, iface: str = "lo") -> list[str]:
    """Shell commands for a real `tc netem` qdisc equivalent to `profile` (needs root on Linux/WSL2)."""
    opts = []
    if profile.delay_ms:
        opts.append(f"delay {profile.delay_ms:g}ms")
    if profile.loss_pct:
        opts.append(f"loss {profile.loss_pct:g}%")
    if not opts:
        return [f"tc qdisc del dev {iface} root 2>/dev/null || true"]
    return [f"tc qdisc del dev {iface} root 2>/dev/null || true",
            f"tc qdisc add dev {iface} root netem {' '.join(opts)}"]


def apply_tc(profile: Profile, iface: str = "lo") -> None:
    for cmd in tc_commands(profile, iface):
        subprocess.run(["sudo", "sh", "-c", cmd], check=True)


def clear_tc(iface: str = "lo") -> None:
    subprocess.run(["sudo", "sh", "-c", f"tc qdisc del dev {iface} root 2>/dev/null || true"], check=False)


if __name__ == "__main__":
    for p in PROFILES:
        print(f"# {p.name}: {p.description}")
        for c in tc_commands(p):
            print("  " + c)
