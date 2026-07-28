#!/usr/bin/env python3
"""Regenerate the decision-ceiling table in the README.

Every number in that table comes from this script. Run it and compare:

    python benchmarks/ceiling.py

The point of the table is that the ceiling applies to the *enumerated product*,
not the box volume -- the counter solves the widest variable in closed form, so
a two-variable box spanning 2^32 points costs only 2^16 enumerations.

Timings are machine-dependent; the verdicts and the enumerated counts are not.
"""

from __future__ import annotations

import time

from exploit_counter import enumeration_cost

from crs_mcp.tools import AGENT_EXACT_CAP, certify_guard

DOMAIN = [{"coeff": {"payload": -1}}]
GUARD = [{"coeff": {"payload": 1, "record_len": -1}, "const": 19}]
SAFETY = [{"coeff": {"payload": 1, "record_len": -1}, "const": 3}]

CASES = [
    ("payload=0:255, record_len=0:255", {"payload": [0, 255], "record_len": [0, 255]}),
    ("payload=0:65535, record_len=0:65535", {"payload": [0, 65535], "record_len": [0, 65535]}),
    ("payload=0:499999, record_len=0:10^9", {"payload": [0, 499999], "record_len": [0, 10**9]}),
    ("payload=0:500000, record_len=0:10^9", {"payload": [0, 500000], "record_len": [0, 10**9]}),
    (
        "three variables, 0:699 each",
        {"payload": [0, 699], "record_len": [0, 699], "extra": [0, 699]},
    ),
    (
        "three variables, 0:800 each",
        {"payload": [0, 800], "record_len": [0, 800], "extra": [0, 800]},
    ),
]


def main() -> int:
    print(f"cap = {AGENT_EXACT_CAP:,} enumerated points\n")
    print(f"{'box':38s} {'volume':>22s} {'enumerated':>12s} {'verdict':>14s} {'ms':>7s}")
    print("-" * 98)
    for label, box in CASES:
        volume = 1
        for lo, hi in box.values():
            volume *= hi - lo + 1
        enumerated, _ = enumeration_cost({k: tuple(v) for k, v in box.items()})
        start = time.perf_counter()
        verdict = certify_guard(DOMAIN, GUARD, SAFETY, box).verdict
        elapsed = (time.perf_counter() - start) * 1000
        print(f"{label:38s} {volume:>22,} {enumerated:>12,} {verdict:>14s} {elapsed:>7.0f}")
    print(
        "\nNote the fourth row: one more point in the *narrow* variable crosses the cap, "
        "\nwhile the box volume is unchanged. The volume is not what is being limited."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
