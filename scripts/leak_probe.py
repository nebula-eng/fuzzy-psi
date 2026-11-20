"""Measure the leakage that the consistency proof introduces.

The proof needs the client's unblinded band-key bases `B_i = H(key_i)` to be
verifier-evaluable, so the server can enumerate the whole band-key space and
match each base. This script measures the two costs that bound the resulting
attack, and writes `results/leakage.json`.

    python scripts/leak_probe.py            # write results/leakage.json
    python scripts/leak_probe.py --repeat 50

Caveat: this measures the *primitive* costs (hash-to-group sweep, simhash per
candidate). It does not implement the full attack, so it is an upper bound on
attacker cost, not a demonstration that a specific indicator set is recovered.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from fuzzy_psi import group, lsh  # noqa: E402

BANDS = 5
BAND_BITS = 12


def bench_enumeration(repeat: int) -> dict:
    """Time a full 5 x 4096 hash-to-group sweep, i.e. one recovery table."""
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        table = {}
        for band in range(BANDS):
            for value in range(1 << BAND_BITS):
                token = bytes([band]) + value.to_bytes(2, "big")
                table[(band, value)] = group.hash_to_group(token)
        samples.append(time.perf_counter() - start)
    return {
        "table_entries": BANDS * (1 << BAND_BITS),
        "median_ms": round(statistics.median(samples) * 1e3, 3),
        "min_ms": round(min(samples) * 1e3, 3),
        "max_ms": round(max(samples) * 1e3, 3),
        "repeat": repeat,
        "note": "one table covers a whole submission; lookup per item is O(1)",
    }


def bench_simhash(count: int = 500) -> dict:
    """Per-candidate cost of the offline dictionary step."""
    items = [f"malware-{i}.example.com/drop?id={i}" for i in range(count)]
    start = time.perf_counter()
    for item in items:
        sketch = lsh.simhash(lsh.shingles(item))
        lsh.band_keys(sketch)
    elapsed = time.perf_counter() - start
    return {
        "candidates": count,
        "median_us_per_candidate": round(elapsed / count * 1e6, 3),
        "total_ms": round(elapsed * 1e3, 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repeat", type=int, default=20)
    parser.add_argument("--out", default="results/leakage.json")
    args = parser.parse_args()

    payload = {
        "machine": {
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "enumeration": bench_enumeration(args.repeat),
        "dictionary": bench_simhash(),
        "params": {"bands": BANDS, "band_bits": BAND_BITS},
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
