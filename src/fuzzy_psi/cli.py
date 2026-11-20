"""Command line interface: `eval`, `demo`, `bench`, `info`."""

from __future__ import annotations

import argparse
import secrets
import sys
import time

from . import group, lsh, metrics, protocol


def _parse_int_list(text: str) -> list[int]:
    return [int(part) for part in text.split(",") if part.strip()]


def cmd_eval(args: argparse.Namespace) -> int:
    sizes = _parse_int_list(args.sizes)
    radii = _parse_int_list(args.radii)
    print(f"evaluating sizes={sizes} fuzzy radii={radii} (seed={args.seed})")
    started = time.perf_counter()
    report = metrics.run_evaluation(
        sizes=sizes,
        fuzzy_radii=radii,
        fuzzy_size=args.fuzzy_size,
        seed=args.seed,
        lsh_bands=args.bands,
        lsh_bits=args.band_bits,
    )
    metrics.write_json(report, args.out)
    elapsed = time.perf_counter() - started
    print()
    print(metrics.markdown_scaling(report))
    print()
    print(metrics.markdown_fuzzy(report))
    print()
    print(metrics.markdown_baselines(report))
    print()
    print(f"wrote {args.out} in {elapsed:.1f}s")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    dataset = metrics.build_dataset(args.n, args.seed)
    params = protocol.Params(radius=args.radius)
    print(f"running protocol over 127.0.0.1 with n={args.n}, t={args.radius}")
    result = protocol.run_tcp(dataset.client, dataset.server, params)
    truth = dataset.truth(args.radius)
    recall, precision = metrics.precision_recall(result.client.matches, truth)
    print(f"  wall time       : {result.wall_time:.2f} s")
    print(f"  client -> server : {result.client_channel_bytes} bytes")
    print(f"  server -> client : {result.server_channel_bytes} bytes")
    print(f"  total            : {result.total_bytes} bytes")
    print(f"  bytes/item       : {result.total_bytes / max(1, args.n):.1f}")
    print(f"  true matches     : {len(truth)}")
    print(f"  reported matches : {len(result.client.matches)}")
    print(f"  recall           : {recall:.3f}")
    print(f"  precision        : {precision:.3f}")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """Microbenchmarks for the primitives; used when tuning parameters."""
    print(f"group: RFC 3526 MODP, {group.P.bit_length()} bits, element {group.ELEMENT_BYTES} bytes")
    base = group.hash_to_group(b"benchmark")
    for bits in (group.DEFAULT_EXPONENT_BITS, 512, group.P.bit_length()):
        exponent = group.rand_exponent(bits=bits)
        rounds = args.rounds
        started = time.perf_counter()
        for _ in range(rounds):
            pow(base, exponent, group.P)
        per_op = (time.perf_counter() - started) / rounds
        print(f"  modexp, {bits:>4}-bit exponent : {per_op * 1000:7.3f} ms")
    text = "http://cdn7.malware.example/0a1b2c/payload.bin"
    rounds = 2000
    started = time.perf_counter()
    for _ in range(rounds):
        lsh.simhash(lsh.shingles(text))
    print(f"  simhash per item         : {(time.perf_counter() - started) / rounds * 1e6:7.1f} us")
    started = time.perf_counter()
    for _ in range(200):
        group.hash_to_group(secrets.token_bytes(16))
    print(f"  hash_to_group            : {(time.perf_counter() - started) / 200 * 1000:7.3f} ms")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    params = protocol.Params()
    print(f"fuzzy-psi parameters")
    print(f"  group            : RFC 3526 2048-bit MODP, g=2, q=(p-1)/2")
    print(f"  element size     : {group.ELEMENT_BYTES} bytes")
    print(f"  exponent size    : {params.exponent_bits} bits")
    print(f"  LSH bands        : {params.bands} x {params.band_bits} bits")
    for distance in (2, 4, 6, 8):
        print(f"  analytic recall at d={distance}: {lsh.expected_recall(distance, params.lsh_params):.3f}")
    print(f"  consistency proof: batch Chaum-Pedersen, {protocol.schnorr.PROOF_BYTES} bytes")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fuzzy-psi", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    ev = sub.add_parser("eval", help="run the benchmark and write results.json")
    ev.add_argument("--sizes", default="64,256,512", help="comma separated client set sizes")
    ev.add_argument("--radii", default="2,4,6,8", help="fuzzy radii to sweep")
    ev.add_argument("--fuzzy-size", type=int, default=48)
    ev.add_argument("--seed", type=int, default=metrics.DEFAULT_SEED)
    ev.add_argument("--bands", type=int, default=lsh.BANDS)
    ev.add_argument("--band-bits", type=int, default=lsh.BAND_BITS)
    ev.add_argument("--out", default="results/results.json")
    ev.set_defaults(func=cmd_eval)

    demo = sub.add_parser("demo", help="run the protocol over loopback TCP")
    demo.add_argument("--n", type=int, default=64)
    demo.add_argument("--radius", type=int, default=4)
    demo.add_argument("--seed", type=int, default=metrics.DEFAULT_SEED)
    demo.set_defaults(func=cmd_demo)

    bench = sub.add_parser("bench", help="primitive microbenchmarks")
    bench.add_argument("--rounds", type=int, default=20)
    bench.set_defaults(func=cmd_bench)

    info = sub.add_parser("info", help="print parameters and analytic recall")
    info.set_defaults(func=cmd_info)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
