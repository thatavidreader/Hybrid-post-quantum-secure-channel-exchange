"""Print counts per event type from one or more JSON-lines security logs.

Usage:  python -m src.log_summary results/server.log.jsonl [more.jsonl ...]
"""
from __future__ import annotations

import argparse
import collections
import json
import sys


def summarize(paths: list[str]) -> collections.Counter:
    counts: collections.Counter = collections.Counter()
    for p in paths:
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    counts[json.loads(line)["event"]] += 1
                except (ValueError, KeyError):
                    counts["MALFORMED_LINE"] += 1
    return counts


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logs", nargs="+")
    args = ap.parse_args(argv)
    counts = summarize(args.logs)
    if not counts:
        print("no events")
        return 0
    width = max(len(k) for k in counts)
    print(f"{'EVENT':<{width}}  COUNT")
    for ev, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        print(f"{ev:<{width}}  {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
