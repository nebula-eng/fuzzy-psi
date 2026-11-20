"""Render the three figures from results/results.json.

Output: results/fig_scaling.png, results/fig_fuzzy.png,
results/fig_phase_breakdown.png.  All figures are 1600x1000 pixels at
dpi=200 (8.0 x 5.0 inches) with a serif academic style.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))

from fuzzy_psi import lsh  # noqa: E402

FIG_SIZE = (8.0, 5.0)
DPI = 200
COLORS = ["#1f4e79", "#c05621", "#2f6f4e", "#6b46c1", "#8a8a8a"]
PHASES = ["lsh", "psi1", "psi2", "stage3", "other"]
PHASE_LABELS = ["LSH sketching", "PSI-1 band keys", "PSI-2 verification", "distance step", "other"]


def _style() -> None:
    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["DejaVu Serif"],
            "font.size": 9,
            "axes.titlesize": 10,
            "axes.labelsize": 9,
            "legend.fontsize": 8,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "grid.linewidth": 0.5,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.axisbelow": True,
            "lines.linewidth": 1.4,
            "lines.markersize": 4.5,
            "figure.dpi": DPI,
            "savefig.dpi": DPI,
            "savefig.bbox": "standard",
        }
    )


def fig_scaling(report: dict, outdir: str) -> str:
    rows = report["scaling"]
    sizes = [row["n"] for row in rows]
    times = [row["wall_time_s"] for row in rows]
    total_bytes = [row["total_bytes"] for row in rows]
    hash_bytes = [row["baselines"]["hash-psi"]["total_bytes"] for row in rows]
    plain_bytes = [row["baselines"]["plaintext"]["total_bytes"] for row in rows]

    figure, (left, right) = plt.subplots(1, 2, figsize=FIG_SIZE)
    left.plot(sizes, times, "o-", color=COLORS[0], label="fuzzy-psi (measured)")
    left.set_xscale("log", base=2)
    left.set_yscale("log")
    left.set_yticks([10, 20, 30, 60])
    left.set_yticklabels(["10", "20", "30", "60"])
    left.minorticks_off()
    left.set_xlabel("set size per party (n)")
    left.set_ylabel("wall time (s)")
    left.set_title("Runtime (log-log)")
    for n, value in zip(sizes, times):
        left.annotate(f"{value:.1f}s", (n, value), textcoords="offset points",
                      xytext=(0, 7), ha="center", fontsize=7)
    left.legend(frameon=False, loc="upper left")

    right.plot(sizes, total_bytes, "o-", color=COLORS[0], label="fuzzy-psi")
    right.plot(sizes, hash_bytes, "s--", color=COLORS[1], label="hash-psi baseline")
    right.plot(sizes, plain_bytes, "^:", color=COLORS[2], label="plaintext baseline")
    right.set_xscale("log", base=2)
    right.set_yscale("log")
    right.set_xlabel("set size per party (n)")
    right.set_ylabel("total wire bytes")
    right.set_title("Communication (log-log)")
    right.legend(frameon=False, loc="upper left")

    path = os.path.join(outdir, "fig_scaling.png")
    figure.tight_layout()
    figure.savefig(path)
    plt.close(figure)
    return path


def fig_fuzzy(report: dict, outdir: str) -> str:
    rows = sorted(report["fuzzy"], key=lambda row: row["radius"])
    radii = [row["radius"] for row in rows]
    recall = [row["recall"] for row in rows]
    cand_precision = [row["candidate_precision"] for row in rows]
    precision = [row["precision"] for row in rows]

    grid = [index / 10.0 for index in range(0, 161)]
    analytic = [lsh.expected_recall(int(round(d))) for d in grid]

    figure, (left, right) = plt.subplots(1, 2, figsize=FIG_SIZE)
    left.plot(grid, analytic, "--", color=COLORS[4], linewidth=1.2,
              label="analytic (uniform-bit model)")
    left.plot(radii, recall, "o-", color=COLORS[0], label="measured (end to end)")
    left.set_xlabel("Hamming radius t")
    left.set_ylabel("candidate recall")
    left.set_title("Recall: model vs measurement")
    left.set_xlim(0, 16)
    left.set_ylim(0.0, 1.05)
    left.legend(frameon=False, loc="lower left")
    for radius, value in zip(radii, recall):
        offset = (0, 9) if value > 0.985 else (6, 6)
        left.annotate(f"{value:.2f}", (radius, value), textcoords="offset points",
                      xytext=offset, ha="center", fontsize=7)

    right.plot(radii, cand_precision, "s--", color=COLORS[1], label="candidate precision")
    right.plot(radii, precision, "^:", color=COLORS[2], label="final precision (verified)")
    right.set_xlabel("Hamming radius t")
    right.set_ylabel("precision")
    right.set_title("Precision: candidates vs verified output")
    right.set_ylim(0.0, 1.05)
    right.set_xlim(min(radii) - 1, max(radii) + 1)
    right.legend(frameon=False, loc="lower right")
    for radius, value in zip(radii, cand_precision):
        right.annotate(f"{value:.2f}", (radius, value), textcoords="offset points",
                       xytext=(0, -13), ha="center", fontsize=7)

    path = os.path.join(outdir, "fig_fuzzy.png")
    figure.tight_layout()
    figure.savefig(path)
    plt.close(figure)
    return path


def fig_phase_breakdown(report: dict, outdir: str) -> str:
    rows = report["scaling"]
    labels = [str(row["n"]) for row in rows]
    positions = range(len(rows))
    figure, axis = plt.subplots(figsize=FIG_SIZE)
    bottom = [0.0] * len(rows)
    for phase, label, color in zip(PHASES, PHASE_LABELS, COLORS):
        values = [row["phases_s"].get(phase, 0.0) for row in rows]
        axis.bar(positions, values, bottom=bottom, color=color, label=label,
                 width=0.6, edgecolor="white", linewidth=0.5)
        bottom = [acc + value for acc, value in zip(bottom, values)]
    for index, row in enumerate(rows):
        axis.annotate(f"total {row['wall_time_s']:.1f}s", (index, bottom[index]),
                      textcoords="offset points", xytext=(0, 4), ha="center", fontsize=7)
    axis.set_xticks(list(positions))
    axis.set_xticklabels([f"n={label}" for label in labels])
    axis.set_ylabel("compute time (s, both parties)")
    axis.set_title("Phase breakdown (waiting excluded)")
    axis.legend(frameon=False, loc="upper left")
    if bottom:
        axis.set_ylim(0, max(bottom) * 1.15)

    path = os.path.join(outdir, "fig_phase_breakdown.png")
    figure.tight_layout()
    figure.savefig(path)
    plt.close(figure)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="?", default=os.path.join(ROOT, "results", "results.json"))
    parser.add_argument("--outdir", default=os.path.join(ROOT, "results"))
    args = parser.parse_args(argv)

    with open(args.results, "r", encoding="ascii") as handle:
        report = json.load(handle)
    _style()
    os.makedirs(args.outdir, exist_ok=True)
    for builder in (fig_scaling, fig_fuzzy, fig_phase_breakdown):
        path = builder(report, args.outdir)
        print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
