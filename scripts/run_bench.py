"""Benchmark driver, equivalent to `python -m fuzzy_psi.cli eval`.

Kept as a separate script so the numbers can be regenerated without the CLI
entry point (which may not be on PATH in a checkout).  All timing and byte
counts come from `fuzzy_psi.metrics.run_evaluation`; nothing is estimated.
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from fuzzy_psi import metrics  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default="64,256,512")
    parser.add_argument("--radii", default="2,4,6,8")
    parser.add_argument("--fuzzy-size", type=int, default=48)
    parser.add_argument("--seed", type=int, default=metrics.DEFAULT_SEED)
    parser.add_argument("--bands", type=int, default=5)
    parser.add_argument("--band-bits", type=int, default=12)
    parser.add_argument(
        "--out",
        default=os.path.join(ROOT, "results", "results.json"),
    )
    args = parser.parse_args(argv)

    sizes = [int(part) for part in args.sizes.split(",") if part.strip()]
    radii = [int(part) for part in args.radii.split(",") if part.strip()]
    print(f"fuzzy-psi benchmark: sizes={sizes} radii={radii} fuzzy_n={args.fuzzy_size}")
    report = metrics.run_evaluation(
        sizes=sizes,
        fuzzy_radii=radii,
        fuzzy_size=args.fuzzy_size,
        seed=args.seed,
        lsh_bands=args.bands,
        lsh_bits=args.band_bits,
    )
    metrics.write_json(report, args.out)
    print()
    print(metrics.markdown_scaling(report))
    print()
    print(metrics.markdown_fuzzy(report))
    print()
    print(metrics.markdown_baselines(report))
    print()
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
