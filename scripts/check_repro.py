"""Regenerate `results/results.json` and fail if it no longer matches the commit.

The committed table is the evidence behind every number in the README. If the
documented command no longer produces it, the document is wrong. The result file contains wall-clock measurements, so the comparison runs on
a projection with those fields removed. They are listed in TIMING_KEYS.

The working tree is restored before exiting, so a failed run leaves no diff.

    PYTHONPATH=src python scripts/check_repro.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "results" / "results.json"
COMMAND = ["-m", "fuzzy_psi.cli"] + "eval --out results/results.json".split()
TIMING_KEYS = ["wall_time_s", "phases_s", "total_wall_s",
                "generated_utc", "machine"]


def project(value, path="$"):
    """Drop wall-clock and host fields so two runs can be compared."""
    if isinstance(value, dict):
        return {k: project(v, f"{path}.{k}") for k, v in value.items() if k not in TIMING_KEYS}
    if isinstance(value, list):
        return [project(item, f"{path}[]") for item in value]
    return value


def main() -> int:
    if not RESULT.exists():
        print(f"missing {RESULT.relative_to(ROOT)}")
        return 1
    committed = RESULT.read_bytes()

    env = {**os.environ, "PYTHONPATH": "src", "MPLBACKEND": "Agg"}
    proc = subprocess.run([sys.executable, *COMMAND], cwd=ROOT, env=env,
                          capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout[-2000:])
        print(proc.stderr[-2000:])
        print("the documented evaluation command failed")
        return 1

    produced = RESULT.read_bytes()
    if project(json.loads(produced)) == project(json.loads(committed)):
        print(f"reproduced {len(committed)} bytes")
        return 0

    RESULT.write_bytes(committed)
    print("results.json does not match the committed file")
    if TIMING_KEYS:
        print("(timing fields excluded from the comparison: "
              + ", ".join(TIMING_KEYS) + ")")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
