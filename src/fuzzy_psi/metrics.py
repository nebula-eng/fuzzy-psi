"""Datasets, ground truth, precision/recall and the evaluation harness.

The evaluation is deliberately single-run per configuration and reports the
numbers it measured; nothing here interpolates or estimates.  Ground truth is
computed from the 64-bit simhashes of the actual strings, so "recall" always
means recall against exact Hamming distance, not against an LSH heuristic.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import sys
import time
from dataclasses import dataclass

import numpy as np

from . import lsh, protocol

DEFAULT_SEED = 20241114
PHASE_GROUPS = ("lsh", "psi1", "psi2", "stage3")


# ---------------------------------------------------------------------------
# Dataset construction
# ---------------------------------------------------------------------------
_KINDS = ("domain", "url", "ipv4", "sha256", "email")


def _indicator(rng: random.Random, number: int, kinds: tuple[str, ...] | None = None) -> str:
    """Synthetic indicator with enough length that a typo moves few shingles."""
    pool = kinds or _KINDS
    kind = pool[number % len(pool)]
    token = "%08x" % rng.randrange(1 << 32)
    if kind == "domain":
        return f"http://{token}.cdn{number:05d}.malware-delivery.example/gate.php"
    if kind == "url":
        return (
            f"http://cdn{number:05d}.malware.example/assets/{token}/payload.bin"
            f"?sig={rng.randrange(1 << 32):08x}"
        )
    if kind == "ipv4":
        return f"netblock:10.{rng.randrange(1, 255)}.{rng.randrange(1, 255)}.0/24"
    if kind == "sha256":
        return "sha256:" + hashlib.sha256(f"sample-{number}-{token}".encode()).hexdigest()
    return f"actor-{token}-{number:05d}@drop.malware-exfil.example"


def mutate(text: str, rng: random.Random, edits: int = 1) -> str:
    """Introduce character-level typos: substitution, insertion, deletion, swap."""
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789.-/"
    chars = list(text)
    for _ in range(edits):
        if not chars:
            chars = list("x")
        op = rng.choice(("sub", "ins", "del", "swap"))
        pos = rng.randrange(len(chars))
        if op == "sub":
            chars[pos] = rng.choice(alphabet)
        elif op == "ins":
            chars.insert(pos, rng.choice(alphabet))
        elif op == "del" and len(chars) > 4:
            del chars[pos]
        elif op == "swap" and pos + 1 < len(chars):
            chars[pos], chars[pos + 1] = chars[pos + 1], chars[pos]
    return "".join(chars)


@dataclass
class Dataset:
    client: list[str]
    server: list[str]
    client_sketches: list[int]
    server_sketches: list[int]
    min_distance: list[int]

    def truth(self, radius: int) -> set[str]:
        return {
            item for item, distance in zip(self.client, self.min_distance) if distance <= radius
        }


def build_dataset(
    size: int,
    seed: int,
    overlap_ratio: float = 0.2,
    variant_ratio: float = 0.3,
    edits: int = 1,
    kinds: tuple[str, ...] | None = None,
) -> Dataset:
    """Client and server sets of the same size with exact and fuzzy overlap."""
    rng = random.Random(seed)
    server = [_indicator(rng, i, kinds) for i in range(size)]
    overlap = int(round(size * overlap_ratio))
    variants = int(round(size * variant_ratio))

    client: list[str] = []
    client.extend(server[:overlap])
    for item in server[overlap : overlap + variants]:
        client.append(mutate(item, rng, edits=max(1, edits)))
    filler = 0
    while len(client) < size:
        client.append(_indicator(rng, 100000 + filler, kinds))
        filler += 1
    client = client[:size]
    rng.shuffle(client)

    client_sketches = [lsh.simhash(lsh.shingles(item)) for item in client]
    server_sketches = [lsh.simhash(lsh.shingles(item)) for item in server]

    left = np.asarray(client_sketches, dtype=np.uint64)[:, None]
    right = np.asarray(server_sketches, dtype=np.uint64)[None, :]
    distances = np.bitwise_count(left ^ right)
    min_distance = [int(value) for value in distances.min(axis=1)]
    return Dataset(client, server, client_sketches, server_sketches, min_distance)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def precision_recall(predicted: set[str], truth: set[str]) -> tuple[float, float]:
    if truth:
        recall = len(predicted & truth) / len(truth)
    else:
        recall = 1.0
    if predicted:
        precision = len(predicted & truth) / len(predicted)
    else:
        precision = 1.0
    return recall, precision


def phase_breakdown(result: protocol.ProtocolResult) -> dict[str, float]:
    groups = {name: 0.0 for name in PHASE_GROUPS}
    for recorder in (result.client_recorder, result.server_recorder):
        for name, seconds in recorder.time.items():
            if name.endswith("_wait"):
                continue  # blocking on the peer is not compute cost
            for group in PHASE_GROUPS:
                if name == group or name.startswith(group + "_"):
                    groups[group] += seconds
    total = sum(groups.values())
    groups["other"] = max(0.0, result.wall_time - total)
    return groups


def phase_bytes(result: protocol.ProtocolResult) -> dict[str, int]:
    out = {name: 0 for name in PHASE_GROUPS}
    for recorder in (result.client_recorder, result.server_recorder):
        for name, count in recorder.bytes.items():
            if name in out:
                out[name] += count
    return out


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------
def machine_info() -> dict[str, object]:
    return {
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "numpy": np.__version__,
    }


def _summarise(
    result: protocol.ProtocolResult,
    dataset: Dataset,
    radius: int,
    size: int,
) -> dict[str, object]:
    truth = dataset.truth(radius)
    recall, precision = precision_recall(result.client.matches, truth)
    cand_recall, cand_precision = precision_recall(result.client.candidates, truth)
    phases = phase_breakdown(result)
    return {
        "n": size,
        "radius": radius,
        "wall_time_s": round(result.wall_time, 4),
        "total_bytes": result.total_bytes,
        "bytes_per_item": round(result.total_bytes / max(1, size), 2),
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "candidate_recall": round(cand_recall, 4),
        "candidate_precision": round(cand_precision, 4),
        "true_matches": len(truth),
        "reported_matches": len(result.client.matches),
        "candidates": len(result.client.candidates),
        "phases_s": {key: round(value, 4) for key, value in phases.items()},
        "phase_bytes": phase_bytes(result),
        "counters": {
            "client_band_keys": result.client.band_keys,
            "server_band_keys": result.server.band_keys,
            "matched_band_keys": result.client_recorder.counters.get("matched_band_keys", 0),
            "candidate_sketches": result.client.candidate_tokens,
            "exact_sketches": result.client.exact_tokens,
            "pending_probes": result.client.pending_tokens,
            "confirmed_sketches": result.client_recorder.counters.get("confirmed_sketches", 0),
            "confirmations": result.server_recorder.counters.get("confirmations", 0),
        },
        "proof_bytes": protocol.schnorr.PROOF_BYTES,
    }


def run_evaluation(
    sizes: list[int] | None = None,
    fuzzy_radii: list[int] | None = None,
    fuzzy_size: int = 48,
    seed: int = DEFAULT_SEED,
    lsh_bands: int = lsh.BANDS,
    lsh_bits: int = lsh.BAND_BITS,
) -> dict[str, object]:
    sizes = sizes or [64, 256, 512]
    fuzzy_radii = fuzzy_radii or [2, 4, 6, 8]
    started = time.perf_counter()
    params = protocol.Params(bands=lsh_bands, band_bits=lsh_bits, radius=4)

    report: dict[str, object] = {
        "meta": {
            "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "machine": machine_info(),
            "seed": seed,
            "group_bits": protocol.group.P.bit_length(),
            "element_bytes": protocol.group.ELEMENT_BYTES,
            "exponent_bits": params.exponent_bits,
            "lsh": {
                "bands": lsh_bands,
                "band_bits": lsh_bits,
                "analytic_recall": {
                    str(t): round(lsh.expected_recall(t, params.lsh_params), 4)
                    for t in (0, 1, 2, 4, 6, 8)
                },
            },
        },
        "scaling": [],
        "fuzzy": [],
        "baselines": [],
    }

    for size in sizes:
        dataset = build_dataset(size, seed)
        result = protocol.run(dataset.client, dataset.server, params)
        entry = _summarise(result, dataset, params.radius, size)
        plain = protocol.run_plaintext(dataset.client, dataset.server)
        hashed = protocol.run_hash_psi(dataset.client, dataset.server)
        truth = dataset.truth(params.radius)
        entry["baselines"] = {
            "plaintext": {
                "total_bytes": plain.total_bytes,
                "wall_time_s": round(plain.wall_time, 6),
                "recall_at_radius": round(len(plain.matches & truth) / len(truth), 4) if truth else 1.0,
                "matches": len(plain.matches),
            },
            "hash-psi": {
                "total_bytes": hashed.total_bytes,
                "wall_time_s": round(hashed.wall_time, 6),
                "recall_at_radius": round(len(hashed.matches & truth) / len(truth), 4) if truth else 1.0,
                "matches": len(hashed.matches),
            },
        }
        report["scaling"].append(entry)
        print(
            f"  n={size:<5} wall={entry['wall_time_s']:8.2f}s bytes={entry['total_bytes']:<9}"
            f" recall={entry['recall']:.3f} precision={entry['precision']:.3f}",
            flush=True,
        )

    fuzzy_dataset = build_dataset(fuzzy_size, seed + 1, overlap_ratio=0.5, variant_ratio=0.5, edits=2)
    for radius in fuzzy_radii:
        params_r = protocol.Params(bands=lsh_bands, band_bits=lsh_bits, radius=radius)
        result = protocol.run(fuzzy_dataset.client, fuzzy_dataset.server, params_r)
        entry = _summarise(result, fuzzy_dataset, radius, fuzzy_size)
        report["fuzzy"].append(entry)
        print(
            f"  t={radius:<2} n={fuzzy_size:<4} wall={entry['wall_time_s']:7.2f}s"
            f" recall={entry['recall']:.3f} cand_precision={entry['candidate_precision']:.3f}",
            flush=True,
        )

    report["meta"]["total_wall_s"] = round(time.perf_counter() - started, 3)
    return report


def write_json(report: dict[str, object], path: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="ascii", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, ensure_ascii=True)
        handle.write("\n")


def load_json(path: str) -> dict[str, object]:
    with open(path, "r", encoding="ascii") as handle:
        return json.load(handle)


def markdown_scaling(report: dict[str, object]) -> str:
    lines = [
        "| n (client x server) | wall time (s) | total bytes | bytes/item | recall@t=4 | precision | candidate recall |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in report["scaling"]:
        lines.append(
            f"| {row['n']} x {row['n']} | {row['wall_time_s']:.2f} | {row['total_bytes']:,} | "
            f"{row['bytes_per_item']:.1f} | {row['recall']:.3f} | {row['precision']:.3f} | "
            f"{row['candidate_recall']:.3f} |"
        )
    return "\n".join(lines)


def markdown_fuzzy(report: dict[str, object]) -> str:
    lines = [
        "| radius t | true matches | reported | recall | precision | candidate precision | wall time (s) | bytes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in report["fuzzy"]:
        lines.append(
            f"| {row['radius']} | {row['true_matches']} | {row['reported_matches']} | "
            f"{row['recall']:.3f} | {row['precision']:.3f} | {row['candidate_precision']:.3f} | "
            f"{row['wall_time_s']:.2f} | {row['total_bytes']:,} |"
        )
    return "\n".join(lines)


def markdown_baselines(report: dict[str, object]) -> str:
    lines = [
        "| n | plaintext bytes | plaintext recall@t=4 | hash-psi bytes | hash-psi recall@t=4 | protocol bytes |",
        "|---|---|---|---|---|---|",
    ]
    for row in report["scaling"]:
        base = row["baselines"]
        lines.append(
            f"| {row['n']} | {base['plaintext']['total_bytes']:,} | "
            f"{base['plaintext']['recall_at_radius']:.3f} | {base['hash-psi']['total_bytes']:,} | "
            f"{base['hash-psi']['recall_at_radius']:.3f} | {row['total_bytes']:,} |"
        )
    return "\n".join(lines)
