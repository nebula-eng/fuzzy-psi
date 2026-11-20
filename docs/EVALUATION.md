# Evaluation

## 1. What is measured

| quantity | how |
|---|---|
| wall time | `time.perf_counter()` around the whole protocol run, both parties on one machine |
| phase time | per-phase perf counters inside each party; `*_wait` phases (blocking on the peer) are excluded from the breakdown |
| bytes | the channel's framed byte counter (4-byte length prefix + payload), counted on both directions |
| recall / precision | item level, against ground truth Hamming distance of the actual simhash values, not against the LSH heuristic |
| candidate precision | fraction of the client's candidate items (before verification) that have a true match within `t` |

Ground truth is computed with `numpy.bitwise_count` over the full
client x server sketch matrix, so recall is measured against every pair, not
against a sample.

Run command:

```
PYTHONPATH=src python -m fuzzy_psi.cli eval --out results/results.json
```

The benchmark is single-run per configuration; no repetitions, no warm-up, no
filters. `results/results.json` is the machine-readable record; the tables below
are copied from it unchanged.

Byte counts, match counts and recall are deterministic. Wall times and the `meta`
block (host, timestamps) are measurements, so `scripts/check_repro.py` compares a
projection with those fields removed. A run on another machine reproduces every
count and differs only in seconds.

## 2. Machine

| field | value |
|---|---|
| platform | Windows-11-10.0.26200-SP0 |
| processor | Intel64 Family 6 Model 170 Stepping 4, GenuineIntel |
| logical CPUs | 18 |
| Python | 3.13.14 (CPython) |
| numpy | 2.5.4 |
| group | RFC 3526 2048-bit MODP, 256-byte elements |
| exponents | 256-bit |
| LSH | 5 bands x 12 bits, 3-gram shingles, blake2b-64 |
| seed | 20241114 |

Primitive cost on this machine, measured with `python -m fuzzy_psi.cli bench`
during the same session: 4.5 ms per 2048-bit modular exponentiation with a
256-bit exponent, 0.50 ms per simhash of a 60-character indicator. The same
microbenchmark measured 2.2 ms and 6.8 ms at other points of the session on the
same machine; see section 8.

## 3. Scaling (20% exact overlap, 30% typo variants, t = 4)

| n (client x server) | wall time (s) | total bytes | bytes/item | recall@t=4 | precision | candidate recall |
|---|---|---|---|---|---|---|
| 64 x 64 | 11.10 | 342,158 | 5346.2 | 1.000 | 1.000 | 1.000 |
| 256 x 256 | 32.62 | 1,178,442 | 4603.3 | 1.000 | 1.000 | 1.000 |
| 512 x 512 | 57.97 | 2,059,862 | 4023.2 | 1.000 | 1.000 | 1.000 |

Bytes per item falls with `n` because the 1056-byte proof is amortised over the
batch and because the number of distinct band keys grows sublinearly
(278 / 907 / 1520 for 64 / 256 / 512 items).

Phase breakdown (compute time, both parties, seconds):

| n | LSH sketching | PSI-1 band keys | PSI-2 verification | distance step |
|---|---|---|---|---|
| 64 | 0.23 | 9.49 | 1.49 | 0.0005 |
| 256 | 0.56 | 25.52 | 6.80 | 0.0025 |
| 512 | 1.14 | 43.57 | 13.80 | 0.0057 |

Payload bytes per phase (both directions, headers excluded):

| n | PSI-1 | PSI-2 | distance step |
|---|---|---|---|
| 64 | 284,994 | 55,874 | 1,266 |
| 256 | 925,506 | 246,338 | 6,574 |
| 512 | 1,545,538 | 497,730 | 16,570 |

Internal counts at `n = 512`: 1520 distinct client band keys, 1473 distinct
server band keys, 764 colliding band keys, 476 distinct candidate sketches, 106
exact duplicates confirmed in round 2, 1149 round-3 probes, 141 confirmed
sketches via 86 returned confirmations (several probes can point at the same
sketch).

## 4. Fuzzy quality (n = 48, 50% exact duplicates, 50% two-edit variants)

| radius t | true matches | reported | recall | precision | candidate precision |
|---|---|---|---|---|---|
| 2 | 26 | 26 | 1.000 | 1.000 | 0.591 |
| 4 | 27 | 27 | 1.000 | 1.000 | 0.614 |
| 6 | 33 | 33 | 1.000 | 1.000 | 0.750 |
| 8 | 38 | 36 | 0.947 | 1.000 | 0.841 |

Interpretation:

* Final precision is exactly 1.000 at every radius because round 3 recomputes the
  true Hamming distance; a confirmed pair cannot be a false positive.
* Recall at `t <= 6` is 1.000, above the uniform-bit model (1.000 at 4, 0.896 at
  6). At `t = 8` the measured 0.947 (2 misses out of 38, Wilson 95% interval
  [0.827, 0.985]) is well above the model's 0.683. Real typo variants cluster
  their differing bits in a few bands, which the uniform model treats as
  unlikely; the model is therefore a conservative reference, not a prediction.
* Candidate precision rises with `t` because more of the near misses become
  true matches. At `t = 2`, 59% of candidates are real; the rest are pairs at
  distance 3-8 that share a band.

## 5. Insecure baselines

| n | plaintext bytes | recall@t=4 | hash-psi bytes | recall@t=4 | fuzzy-psi bytes |
|---|---|---|---|---|---|
| 64 | 4,315 | 0.722 | 2,064 | 0.722 | 342,158 |
| 256 | 17,072 | 0.812 | 8,232 | 0.812 | 1,178,442 |
| 512 | 34,391 | 0.752 | 16,456 | 0.752 | 2,059,862 |

`plaintext` sends the indicators in the clear. `hash-psi` sends
`sha256(indicator)` (32 bytes) and receives one bit per item. Both recall only
the exact-overlap items (21.5% of these mixed sets at `t = 4`), which is the
point: exact PSI is brittler than the fuzzy variant. `hash-psi` is also
insecure in a specific way - the client sends an *unsalted* hash of a
low-entropy string, so the server can hash its own candidate universe and match
it offline; a dictionary of domains or URL prefixes breaks it. The protocol
here does not have that property because band keys are blinded, but section 5
of `THREAT_MODEL.md` explains the leak it does have.

Cost ratio: fuzzy-psi uses 125-166x the bytes of `hash-psi` and 60-79x the bytes
of plaintext at these sizes. That is the price of blinding, of two PSI rounds
and of 256-byte group elements; an elliptic-curve instantiation would cut it to
roughly 32-byte elements (about 1/8 of the traffic). We report the measured
number rather than extrapolate.

## 6. Runtime budget

The whole evaluation took 132.87 s (`meta.total_wall_s`), under the 240 s
budget, with this composition:

| configuration | measured wall time (s) |
|---|---|
| scaling n=64 | 11.10 |
| scaling n=256 | 32.62 |
| scaling n=512 | 57.97 |
| fuzzy n=48, t=2 / 4 / 6 / 8 | 7.33 / 7.45 / 7.50 / 7.48 |
| dataset construction, ground truth, baselines | remainder |

Why the largest set is 512 and not 1024 or 4096: at the measured 0.113 s per item
(57.97 s / 512), one `n = 1024` configuration would add about 116 s and
`n = 4096` about 464 s (arithmetic on the measured rate, not a measurement).
The 1024 configuration would put the run at roughly 250 s on this machine, over
the budget, and the same benchmark measured 1.5x slower earlier in the session,
so the cap is set at 512. `--sizes` stays open for faster machines. The spec's
fallback of "2^10 max" was not reachable within 240 s here, and the report says
512 rather than silently reducing the group size. No 1024-bit mode is shipped
(see `docs/DESIGN.md`, section 1).

## 7. TCP validation

`python -m fuzzy_psi.cli demo --n 64 --radius 4` runs the same protocol over
`127.0.0.1` with the server in a thread and reports byte counts from the
sockets:

```
wall time       9.31 s
client -> server 170,957 bytes
server -> client 171,201 bytes
total            342,158 bytes
bytes/item       5346.2
recall           1.000
precision        1.000
```

342,158 bytes is exactly the local-channel figure for the same configuration,
which validates the byte accounting: the local channel counts the same framed
bytes a socket sees, and the test suite asserts equality between the two paths.
The wall time differs slightly (9.31 s over TCP vs 11.10 s inside the sweep for
the same `n`) purely from machine load; see below.

## 8. Threats to validity

1. Single run, shared machine. Every configuration is measured once. The
   same `n = 512` workload measured 57.97 s in the reported run and 86.33 s in
   an earlier run of the same build (1.5x), the same `n = 64` workload measured
   11.10 s in the sweep and 9.31 s over TCP, and modular exponentiation measured
   2.2 ms, 4.5 ms and 6.8 ms at three points of the session, on an 18-core
   laptop with background desktop software. Bytes and counts are deterministic
   and reproducible; ratios are stable; absolute seconds are indicative of this
   machine at this moment.
2. Python overhead. `pow()` in CPython is roughly an order of magnitude
   slower than a C or Go implementation, and the proof aggregate loop adds pure
   Python work per item. The 20 modexps per item per side are inherent to the
   design, but the constant is not representative of an optimised deployment.
3. Loopback versus WAN. The demo has no WAN latency; the protocol has three
   round trips, so a 60 ms RTT adds ~180 ms regardless of size. At `n = 512` the
   transfer is 2.06 MB, which is bandwidth-bound (about 0.8 s on a 20 Mbit/s
   link), not RTT-bound.
4. No TLS. Bytes are counted at the application layer; TLS records, TCP/IP
   headers and retransmissions are excluded. A deployment would add 5-10% plus
   handshake costs.
5. Synthetic data. Indicators are generated from five templates with
   character-level mutations, so the simhash distance distribution is a model of
   typos, not of real blocklists. A real corpus would have different duplicate
   and variant structure; the recall numbers would move with it.
6. Sketch distance, not semantics. Ground truth is Hamming distance on the
   64-bit simhash. Two semantically identical indicators with different
   formatting can be far apart in sketch space and are counted as non-matches.
7. Small fuzzy sample. `n = 48` gives 26-38 true matches per radius; the
   `t = 8` recall of 36/38 has a 95% interval of [0.827, 0.985]. The shape of the
   curve is informative, the third decimal is not.
8. Candidate precision is data dependent. It depends on how many pairs sit
   just outside `t`; a corpus with fewer near misses would show higher precision
   at the same parameters.

## 9. Reproducibility

* Fixed seeds for data generation (`--seed`, default 20241114); the protocol's
  own exponents are drawn from `secrets` and are intentionally not seeded.
* `results/results.json` records the seed, machine, parameters and every number
  in the tables above.
* `python scripts/make_figures.py results/results.json` regenerates the three
  figures at 1600x1000 px, dpi=200 from that JSON, so the figures cannot drift
  from the numbers.
* The unit suite (`python -m unittest discover -s tests -v`) covers correctness,
  proof acceptance/rejection, LSH recall and the TCP path; it does not depend on
  the benchmark machine's speed.
