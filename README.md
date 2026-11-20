# fuzzy-psi

Fuzzy private set intersection with a consistency proof.

[![CI](https://github.com/nebula-eng/fuzzy-psi/actions/workflows/ci.yml/badge.svg)](https://github.com/nebula-eng/fuzzy-psi/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776ab.svg)](pyproject.toml)

Fuzzy private set intersection with a batch malicious-consistency proof.

Two parties each hold a set of threat-intelligence indicators (domains, URLs,
hashes, actor handles). They want to know which indicators the other side also
knows, without revealing anything about the indicators that do not match.
Exact PSI is too brittle for this: the same indicator often appears with a typo,
a different URL path or a rotation suffix. Naive fuzzy matching leaks the whole
set. This project builds a two-party protocol that

1. turns each indicator into a 64-bit simhash over character 3-grams and cuts
   it into 5 banded keys (locality-sensitive hashing, candidate generation),
2. runs Diffie-Hellman PSI over the band keys so the client learns only which
   of its bands collide,
3. runs a second DH-PSI over exact sketches to confirm distance-0 duplicates
   without revealing non-matching hashes,
4. verifies the remaining candidates at exact Hamming distance `t`, and
5. forces the client to prove, in zero knowledge of its exponent, that its
   whole submission used one exponent (batched Chaum-Pedersen), so it cannot
   swap exponents between items.

Everything is implemented on the Python standard library: RFC 3526 2048-bit
MODP group, `hashlib`, `hmac`, `secrets`, `pow`. No third-party crypto, no
network access, no build step.

## Protocol sketch

```
 client (X)                                                     server (Y)
 ----------                                                     ----------
 [local] 3-grams -> 64-bit simhash -> 5 bands x 12 bits        [local] same
    |                                                              |
    |  round 1:  U = shuffle{ H(band)^a }, bases B, proof1         |
    |------------------------------------------------------------->|
    |                                                              | verify proof1
    |                                                              | V = shuffle{ H(band)^b }
    |                                                              | W = { u^b }
    |<-------------------------------------------------------------|
    | Z = { v^a };  matching bands = { own keys with W_i in Z }     |
    |                                                              |
    |  round 2:  T = shuffle{ H(sketch)^a2 }, proof2                |
    |------------------------------------------------------------->|
    |                                                              | PSI over its n sketches
    |<-------------------------------------------------------------|
    | exact duplicates (d = 0) confirmed                            |
    |                                                              |
    |  round 3:  pending candidate tokens (band key || sketch)      |
    |------------------------------------------------------------->|
    |                                                              | Hamming(s, s') <= t ?
    |<-------------------------------------------------------------|
    | 32-byte confirmations; client names its own matching items    |
```

The client is the only party that gets an item-level answer. The server still
learns the size of the client submission, the client's band-key bases (a
checkable consistency proof must expose its inputs) and, because it evaluates
the round-3 probes, which of its own items had a near match; see the security
notes below and `docs/THREAT_MODEL.md`.

## Install

Not on PyPI. Install from a clone:

```bash
git clone https://github.com/nebula-eng/fuzzy-psi.git
cd fuzzy-psi
python -m pip install -e ".[plots]"
```

`numpy` is used for one operation that carries real weight: the batched Hamming
distance over candidate pairs. `matplotlib` sits behind the `plots` extra. No
cryptography library is involved at any point. Python 3.11 or newer.

## Quickstart

```bash
export PYTHONPATH=src

# unit tests: 75 tests (unittest, no pytest needed)
python -m unittest discover -s tests -v

# full benchmark -> results/results.json (2-3 minutes, see EVALUATION.md)
python -m fuzzy_psi.cli eval --out results/results.json

# figures from the benchmark output
python scripts/make_figures.py results/results.json

# protocol over a real loopback TCP connection
python -m fuzzy_psi.cli demo --n 64 --radius 4

# primitive microbenchmarks / parameter summary
python -m fuzzy_psi.cli bench
python -m fuzzy_psi.cli info

# leakage microbenchmark (enumeration + dictionary cost) -> results/leakage.json
python scripts/leak_probe.py
```

`make test`, `make eval`, `make figures` and `make demo` run exactly these
commands and nothing else. The evaluation was produced with the direct commands
above, so a reader without `make` loses no functionality.

## Measured results

Byte counts, match counts and recall are deterministic. Wall-clock numbers are
measurements from the reference run committed in `results/results.json` and will differ
on other machines. All numbers are produced by `python -m fuzzy_psi.cli eval` on the machine
described in `EVALUATION.md` (2026-11-14, Windows 11, CPython 3.13.14) and are
copied verbatim from `results/results.json`. Set sizes are per party, with 20%
exact overlap and 30% typo variants; `t = 4`.

| n (client x server) | wall time (s) | total bytes | bytes/item | recall@t=4 | precision |
|---|---|---|---|---|---|
| 64 x 64 | 11.10 | 342,158 | 5346.2 | 1.000 | 1.000 |
| 256 x 256 | 32.62 | 1,178,442 | 4603.3 | 1.000 | 1.000 |
| 512 x 512 | 57.97 | 2,059,862 | 4023.2 | 1.000 | 1.000 |

Fuzzy quality, `n = 48`, half of the server set duplicated exactly and half
mutated with two edits:

| radius t | true matches | reported | recall | precision | candidate precision |
|---|---|---|---|---|---|
| 2 | 26 | 26 | 1.000 | 1.000 | 0.591 |
| 4 | 27 | 27 | 1.000 | 1.000 | 0.614 |
| 6 | 33 | 33 | 1.000 | 1.000 | 0.750 |
| 8 | 38 | 36 | 0.947 | 1.000 | 0.841 |

Insecure baselines on the same data. `plaintext` ships the indicators in the
clear; `hash-psi` ships `sha256(indicator)` and returns a membership bitmap.
Both are exact-match only, so they cannot find the typo variants:

| n | plaintext bytes | recall@t=4 | hash-psi bytes | recall@t=4 | fuzzy-psi bytes |
|---|---|---|---|---|---|
| 64 | 4,315 | 0.722 | 2,064 | 0.722 | 342,158 |
| 256 | 17,072 | 0.812 | 8,232 | 0.812 | 1,178,442 |
| 512 | 34,391 | 0.752 | 16,456 | 0.752 | 2,059,862 |

The baselines are 60-166x cheaper in bytes (plaintext at 512: 34,391 B against
2,059,862 B; hash-psi at 512: 16,456 B), which is the honest headline: fuzzy PSI
over a 2048-bit MODP group costs kilobytes per item. Figures `fig_scaling.png`,
`fig_fuzzy.png` and `fig_phase_breakdown.png` visualise time, bytes, quality and
the phase split.

Phase split at `n = 512` (compute time, both parties, waiting excluded):
PSI-1 43.57 s, PSI-2 13.80 s, sketching 1.14 s, distance step 0.01 s. The two
Diffie-Hellman rounds dominate; the round-1 exponentiation count is
`3 n_k + n_s` per side, see `docs/DESIGN.md`.

## Security notes

* Threat model. Semi-honest server and malicious client for the
  consistency property; a malicious server is out of scope and explicitly
  discussed in `docs/THREAT_MODEL.md`.
* Server privacy. Band keys and sketches travel blinded under DDH in the
  order-q subgroup. The client learns `H(y)^b` only for the elements it
  submitted (one-more-DH caveat), so the submission size is what bounds probing.
* Consistency proof. A client that deviates on one item is rejected with
  probability at least `1 - 2^-128` (Fiat-Shamir, 128-bit per-item scalars,
  challenge binding the whole transcript). Tests cover tampering, swapping,
  per-item exponents and replayed challenges.
* The proof leaks the bases. A verifier-evaluable proof over
  `prod B_i^{rho_i}` needs the bases. With 12-bit band keys the server can build
  a recovery table over the whole `5 x 4096` key space in 53.0 ms per
  submission (`results/leakage.json`, median of 20 runs; lookup per item is then
  O(1)), and the recovered 60-bit sketch prefix supports an offline dictionary
  attack at 354 us per candidate simhash. This is the main limitation of the
  construction and the reason `docs/THREAT_MODEL.md` calls the proof an
  accountability mechanism rather than a privacy amplifier.
* Fuzzy matching leaks more than exact PSI by design. A band collision tells
  the client that *something* similar exists; candidate precision is 0.59-0.84
  in the measurements above, i.e. many candidates are near misses rather than
  true matches. Only the final answer is exact.
* No padding by default. `Params(pad_client_keys=N)` submits a fixed-size
  band-key set with random dummies, which hides the true size at linear cost.
  Not enabled in the benchmark.

## Documentation

- [`docs/DESIGN.md`](docs/DESIGN.md) -- group choice, protocol rounds, proof
  construction, LSH parameter selection, byte accounting.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) -- semi-honest vs malicious client,
  leakage, out-of-scope, ethics.
- [`docs/EVALUATION.md`](docs/EVALUATION.md) -- benchmark methodology, baselines, full
  tables, and the leakage measurement.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): the design rules a patch has to keep.
- [`SECURITY.md`](SECURITY.md): what counts as a vulnerability here, and how to report.
- [`CHANGELOG.md`](CHANGELOG.md): release notes.


## Layout

```
src/fuzzy_psi/   group.py dhpsi.py schnorr.py lsh.py protocol.py net.py metrics.py cli.py
tests/           test_group.py test_dhpsi.py test_schnorr.py test_lsh.py test_protocol.py
scripts/         run_bench.py make_figures.py leak_probe.py check_repro.py
docs/            DESIGN.md THREAT_MODEL.md EVALUATION.md
results/         results.json (contains measured wall times), leakage.json,
                 fig_scaling.png fig_fuzzy.png fig_phase_breakdown.png
```

## Limitations

* 2048-bit MODP with 256-byte elements: correct and library-free, but 6-8x
  larger and 10-50x slower than an elliptic-curve instantiation. A real
  deployment should use X25519 / ristretto255 and RFC 9380 hash-to-curve.
* The batch proof requires publishing the bases (see above). A production system
  needs a zk proof over a Merkle-committed input, which is out of scope here.
* Round 3 is evaluated by the server, so the output is only as trustworthy as
  the server (fine under the semi-honest assumption, not against a malicious
  one).
* The benchmark caps set sizes at 512. A 1024-item run at the measured
  0.113 s/item would take about 116 s, which together with the other
  configurations exceeds the 240 s budget on this machine; the rate is
  measured, the 116 s is arithmetic. Use `--sizes 64,256,1024` on a faster
  machine.
* Simhash is a coarse similarity sketch: recall is measured against Hamming
  distance on the sketch, not semantic similarity, and the uniform-bit model
  used for the analytic curve is pessimistic compared to real typo variants.

## License

MIT, see [`LICENSE`](LICENSE).
