# Design

This document explains the cryptographic choices, the four rounds on the wire,
the consistency proof, the LSH parameter selection, and the exact byte
accounting. Measured numbers live in `results/results.json` and are quoted in
`README.md` and `EVALUATION.md`; nothing in this file is estimated unless it is
labelled as a formula.

## 1. Group choice

The protocol runs in the RFC 3526 2048-bit MODP group (group id 14):

```
p = 2^2048 - 2^1984 - 1 + 2^64 * ( floor(2^1918 * pi) + 124476 )
g = 2
q = (p - 1) / 2          (prime, 2047 bits)
```

Properties used by the code and asserted in `tests/test_group.py`:

| property | value | why it matters |
|---|---|---|
| modulus size | 2048 bits | ~110-bit discrete-log security with GNFS; no 1024-bit shortcut is shipped |
| safe prime | `p = 2q + 1`, `p mod 4 = 3` | the only proper subgroups are `{1}` and `{1, p-1}`, so a range check `1 < x < p-1` removes small-subgroup elements |
| generator | `g = 2`, `2^q = 1 mod p` | all bases live in the order-q subgroup, which is what the DDH argument needs |
| element encoding | 256 bytes, big-endian, fixed width | message sizes are exactly predictable and easy to account |

### Hashing into the group

`hash_to_group(data)` computes

```
x = int(sha256(tag || counter || data)) mod p
h = x^2 mod p                       # cofactor clearing
reject and retry if h <= 1
```

Squaring is the cofactor-clearing step for a safe prime: it maps a random
element of `Z_p^*` into the order-q subgroup with one modular squaring, and a
random quadratic residue is statistically close to uniform in that subgroup.
This is the standard substitute for hash-to-curve in a MODP setting. A real
deployment should use an RFC 9380 hash-to-curve construction against an
elliptic curve, because that gives a uniform-output proof and much shorter
elements (32-48 bytes instead of 256). We keep the MODP group because the
project must not use third-party crypto libraries; it also makes the cost of
the naive approach visible, which is part of the honest evaluation.

### Exponent size

`rand_exponent()` returns a uniform value in `[2, p-2]` as specified. The
protocol calls `rand_exponent(bits=256)`: a 256-bit exponent keeps the
exponent search space at 2^128 while the group itself caps security at ~110
bits, so nothing is lost, and CPython's `pow` is roughly eight times faster
with 256-bit exponents than with 2048-bit ones (measured: 2.2 ms vs 18.5 ms
per exponentiation on the benchmark machine). `bits` below 224 is rejected.

We deliberately do not ship an `--insecure-1024` mode. A 1024-bit MODP
group gives roughly 80-bit discrete-log security, below the 112-bit target of
the 2048-bit group, and mixing both in one results table would make the
numbers incomparable.

## 2. The protocol

Notation: `H(.)` is `hash_to_group`, `a` is the client exponent, `b` the
server exponent, `t` the Hamming radius, `b_lsh`/`r` the band count/width.

```
client (set X, |X| = n)                                   server (set Y, |Y| = n)
-------------------------------------------------------------------------------
round 0   sketch every item: 3-grams -> 64-bit simhash -> 5 band keys of 12 bits
          (both parties do this locally; nothing is sent)

round 1   U = shuffle{ H(key_i)^a }  for every distinct client band key
          B = matching bases, same order
          proof1 = batch Chaum-Pedersen for (a, B, U)
                       ------------------------------>
                       <------------------------------
                                          V = shuffle{ H(key_j)^b }
                                          W = { u_i^b }   (received order)
          Z = { v^a }, learn K = { own keys with W_i in Z }

round 2   for candidate items only: token = 64-bit sketch (8 bytes)
          T_c = shuffle{ H(token)^a2 }, proof2
                       ------------------------------>
                       <------------------------------
                                          T_s = { H(sketch_j)^b2 } for its n items
                                          W2 = { t^b2 }
          learn which of its sketches exist verbatim on the server (d = 0)

round 3   send the remaining candidate tokens in the clear
                       ------------------------------>
                       <------------------------------
                                          for each token, if any server sketch in
                                          that band is within Hamming distance t,
                                          return sha256(token) (32 bytes)
          learn which of its items have a near match
```

### Round 1 - band-key PSI

Both sides de-duplicate band keys (`b_lsh * n` keys at most, fewer when items
share a band), blind them with their own exponent, and exchange. This is the
textbook two-round DH-PSI with client-only output:

* correctness: `W_i = H(x_i)^{ab}` and `v_j^a = H(y_j)^{ab}`, so the value sets
  coincide exactly on matching band keys;
* server privacy: the server sees a permutation of `H(x_i)^a` and learns
  nothing about `x_i` beyond the size of the submission (DDH in the order-q
  subgroup);
* client privacy: the client learns `H(y_j)^b` only for the `n_k` elements it
  submitted - the one-more-DH caveat. Rate limiting the number of elements per
  session is what turns that into "one membership test per band key".

One deviation from the sketch in the task statement, and why: with `W`
shuffled, the client can still test membership (`z_j = v_j^a in W`) but can no
longer tell *which of its own items* matched, because it cannot link a `w`
value back to its `u` value without `b`. The match relation is unchanged; we
only require `W` to come back in the order it was sent so the client can name
its own hits. The server learns nothing from that ordering (it computed `W`
itself), while `U` stays shuffled so the server cannot map positions to items.
Cost is identical: one exponentiation per item either way.

### Round 2 - verification PSI over exact sketches

A shared band key means "possibly similar", not "similar". Round 2 runs a
second DH-PSI over the 64-bit sketch of every candidate item. A hit means the
server holds an item with an identical sketch, hence Hamming distance 0, and
the client learns that without either side revealing a non-matching hash.

The obvious token is the composite `(band_key, simhash)`. We dropped the band
prefix for a measured reason: candidate scoping already comes from round 1, so
the band adds no matching power, while it multiplies the server's PSI input by
`b_lsh = 5` (a composite server set is 5n elements, the sketch-only set is n).
An earlier build that used the composite token spent 84.6 s in round 2 against
64.9 s in round 1 at n = 512, both measured in the same run; the shipped build
spends 13.8 s in round 2. Semantics are unchanged: identical sketches always
share every band, so no exact duplicate is lost.

### Round 3 - distance completion

An equality PSI cannot certify `1 <= d <= t` without either revealing
sketches or running an oblivious Hamming-distance protocol. We take the
explicit, documented trade-off: the client sends the still-unconfirmed
candidate tokens (band key + its own sketch) in the clear, and the server
evaluates `Hamming(sketch_client, sketch_server) <= t` and returns a 32-byte
confirmation for each hit. Leakage: 64 bits of client sketch per candidate to
the server (which already knows 60 of those bits from the band keys), and one
bit per candidate back. The client never learns the server's sketches, so the
output stays client-only in the sense that only the client can name its own
matching items; the server does learn which of its items each probe hit, since
it runs the test. Under a *malicious* server this step is not trustworthy -
see `THREAT_MODEL.md`.

Why 64-bit confirmations instead of group elements: the token is already known
to the client, so a hash is a perfectly binding capability; 32 bytes instead
of 256.

## 3. Batch consistency proof

### Statement

Given a transcript `B = (B_1..B_n)` of bases and `U = (U_1..U_n)` of blinded
values, prove knowledge of one exponent `a` with

```
A = g^a        and        U_i = B_i^a   for all i.
```

### Construction (Fiat-Shamir Chaum-Pedersen)

```
transcript = "fpsi-cp-v1" || context || n || B_1..B_n || U_1..U_n
rho_i      = int(sha256(transcript || i)[0:16])          # 128-bit scalars
B_agg      = prod_i B_i^{rho_i}  mod p
U_agg      = prod_i U_i^{rho_i}  mod p
k          <- [2, 2^256)                                  # prover randomness
T1         = g^k
T2         = B_agg^k
c          = sha256(domain || transcript || A || T1 || T2 || B_agg || U_agg)
s          = (k + c * a) mod (p-1)
proof      = (A, T1, T2, c, s)                            # 1056 bytes
```

Verification recomputes `rho_i`, `B_agg`, `U_agg`, checks `c`, then checks the
two Chaum-Pedersen equations

```
g^s == A^c * T1        and        B_agg^s == U_agg^c * T2     (mod p).
```

The reduction to `mod (p-1)` is harmless because `g` has order `q | p-1`, so
`g^s` is well defined for any representative of `s`.

### Soundness argument

Suppose the client fixes `U` (and therefore `rho` by Fiat-Shamir) and deviates
on at least one item, `U_k = B_k^{a + delta}` with `delta != 0 mod q`. The
verification equation holds only if `B_k^{rho_k * delta} = 1`. Since `B_k` lies
in the order-q subgroup and `q` is prime, that requires `rho_k = 0`, i.e.
probability `2^-128` per attempt under the random-oracle assumption, with no
grinding opportunity because `c` also binds `U`. Hence a single flipped item
is detected with probability at least `1 - 2^-128`.

The proof also binds the base vector: swapping bases or changing them without
changing `U` breaks both the challenge and the second equation. Deleting an
item changes the transcript, hence `rho`, hence the challenge.

### What it does and does not achieve

What it stops:

* per-item exponents (`a + delta_i`), which would let a client compute `b`-th
  powers of *linear combinations* of server elements - the opening for
  one-more-DH amplification and predicate probing;
* reordering or dropping items between what is proven and what is sent;
* substituting arbitrary group elements for blinded values.

What it cannot stop, and we say so rather than hand-wave:

* The verifier must see the bases. `B_i` is an input to the aggregate the
  verifier recomputes, so a proof that is checkable by the server necessarily
  discloses `B`. In our parameterization the bases are `H(band_key)` over a
  12-bit key space, so a server can recover each client band key with about
  4096 hash evaluations per band (measured in `EVALUATION.md`). The client
  therefore keeps band-key privacy against a *semi-honest* server only until
  it submits the proof. Removing this requires proving the statement with the
  bases as *private witnesses*, i.e. a zk-SNARK over a Merkle commitment to
  the client set - out of scope here and roughly three orders of magnitude
  slower in Python.
* Input size is not bounded. A client may submit any `|X'|` keys it likes;
  the proof says "one exponent for whatever was submitted", not "this is a
  faithful commitment to a declared set". Rate limiting is the mitigation.
* Bases need not be real band keys. The verifier checks consistency
  relative to the supplied bases, not that each base is a hash of a legitimate
  key. Again, inherent to PSI: the client chooses its input.

This is why `THREAT_MODEL.md` describes the proof as an *accountability and
rate-limiting* mechanism rather than a privacy amplifier.

## 4. LSH parameter selection

### Pipeline

```
text --normalize--> "^text$" --3-grams--> shingle set
     --blake2b-64 per shingle--> weighted majority vote --> 64-bit simhash
     --> b disjoint chunks of r bits --> b band keys
```

Weights are 1.0 per shingle by default (uniform majority); `simhash()` accepts
an explicit weight table so an IDF scheme can be dropped in without changing
the rest of the pipeline.

### Recall math

A pair with Hamming distance `d` becomes a candidate if any band is untouched.
With disjoint bands, uniform bit placement and inclusion-exclusion:

```
P(miss) = sum_{k=0..b} (-1)^k * C(b,k) * C(64 - k*r, d) / C(64, d)
R(d)    = 1 - P(miss)
```

With `b = 5`, `r = 12` (60 of 64 bits; the 4 spare bits keep bands disjoint):

| d | 0-4 | 6 | 8 | 10 | 12 | 16 |
|---|---|---|---|---|---|---|
| R(d) | 1.000 | 0.896 | 0.683 | 0.467 | 0.297 | 0.105 |

The textbook approximation `1 - (1 - (1 - d/64)^r)^b` gives 0.954 at d = 4.
That is wrong here: 4 differing bits cannot hit all 5 bands, so by pigeonhole
some band is untouched and the exact recall at `d = 4` is 1.0. We use the exact
formula everywhere (code, tests, documents).

### The trade-off

| b x r | tokens per item | R(4) | R(6) | R(8) | PSI cost |
|---|---|---|---|---|---|
| 2 x 32 | 2 | 0.113 | 0.024 | 0.005 | cheapest, unusable recall |
| 4 x 16 | 4 | 0.897 | 0.583 | 0.327 | 20% cheaper, misses the 0.90 bar |
| 5 x 12 | 5 | 1.000 | 0.895 | 0.683 | chosen |
| 8 x 8 | 8 | 1.000 | 1.000 | 0.996 | 60% more tokens and time |
| 16 x 4 | 16 | 1.000 | 1.000 | 1.000 | 3.2x tokens, far too slow in Python |

`b x r = 5 x 12` is the smallest configuration that reaches the required
recall at radius 4 while keeping the PSI input at `5n` elements. Recall at
`d = 8` is 0.68 in the uniform model; measured recall is higher (0.94 at
`t = 8`, see `EVALUATION.md`) because real simhash differences cluster in a
few bands, which the uniform model does not capture.

### Candidate precision

Candidate precision (fraction of candidate pairs actually within `t`) is not a
property of the banding alone: at `r = 12` the chance that a *random* unrelated
pair collides is `b / 2^r = 0.12%` per pair, but pairs at `d = 5..8` collide
with probability 0.90-0.68. Measured candidate precision at `t = 4` is
therefore around 0.6: most false candidates are near misses, not chance
collisions. Final precision is 1.000 by construction because round 3 verifies
the exact distance.

## 5. Byte accounting

Every element is 256 bytes, every token 12 bytes, every confirmation 32 bytes,
every proof 1056 bytes, every header 15 bytes (7-byte tag, 4 parameter bytes,
4-byte count). Sizes per message:

| message | bytes |
|---|---|
| C1 (band keys) | `15 + 1056 + 512 * n_k` |
| S1 | `19 + 256 * (n_s + n_k)` |
| C2 (candidate sketches) | `15 + 1056 + 512 * t_c` |
| S2 | `19 + 256 * (n + t_c)` |
| C3 (pending probes) | `15 + 12 * p` |
| S3 | `15 + 32 * h` |

with `n_k`, `n_s` the distinct band-key counts, `t_c` the distinct candidate
sketches, `p` the pending `(band key, sketch)` probes and `h` the returned
confirmations. The channel counts framed bytes (4-byte length prefix plus
payload), so the numbers are what a byte-level capture of the connection shows,
without Ethernet/IP/TCP headers.

Check against the `n = 512` measurement (`n_k = 1520`, `n_s = 1473`,
`t_c = 476`, `p = 1149`, `h = 86`):

```
PSI-1  = (15 + 1056 + 512*1520) + (19 + 256*(1473+1520)) = 1,545,538  measured 1,545,538
PSI-2  = (15 + 1056 + 512*476)  + (19 + 256*(512+476))   =   497,730  measured   497,730
step 3 = (15 + 12*1149) + (15 + 32*86)                   =    16,570  measured    16,570
total  = 2,059,838 payload + 6 frame prefixes (24 bytes)  = 2,059,862  measured 2,059,862
```

Two consequences worth stating plainly:

1. Bases dominate. `B` costs as much as `U`: 1280 bytes per item of the
   roughly 7 KB. Because the bases are enumerable hashes of 12-bit band keys,
   sending the 4-byte key would leak exactly the same information and cut the
   message 128-fold. We keep the generic base vector because it is what makes
   the proof checkable for *arbitrary* bases (e.g. a high-entropy item hash),
   and we report the cost instead of hiding it.
2. Two PSI rounds. Round 2 roughly doubles the traffic; its purpose is to
   confirm `d = 0` without sketch disclosure, and it is the price of not
   leaking the server's sketches to every candidate.

## 6. Complexity

Let `n` be the set size per party, `b_lsh = 5`, and count modular
exponentiations with a 256-bit exponent (2.2 ms on the benchmark machine).
Band-key counts are bounded by `5n` and measured `n_k = 1520`, `n_s = 1473` at
`n = 512` (2.97n and 2.88n); the candidate sketch count `t_c = 476` (0.93n) is
data dependent.

| phase | client modexps | server modexps | measured at n = 512 |
|---|---|---|---|
| round 1 | `3 n_k + n_s` = 6033 | `3 n_k + n_s` = 6033 | 43.57 s |
| round 2 | `3 t_c + n` = 1940 | `2 t_c + n + t_c` = 1940 | 13.80 s |
| round 3 | 0 | 0 (Hamming only) | 0.0057 s |
| total | 7973 | 7973 | 57.97 s |

(`n_k = 1520`, `n_s = 1473`, `t_c = 476`, `n = 512`, and the proof's two
aggregate exponentiations per item are the `2 n_k` inside round 1.) The
15,946 exponentiations in 57.4 s of phase time give 3.6 ms per exponentiation,
slightly below the 4.5 ms microbenchmark because the 128-bit proof scalars are
cheaper than the 256-bit protocol exponents.

Wall time is dominated by `pow()`. At `n = 512` the measured cost is 0.113 s per
item of wall time across both parties, so one `n = 1024` configuration would
cost about 116 s (arithmetic on the measured rate). That is why the benchmark
caps at `n = 512`; see `EVALUATION.md`, section 6.

## 7. Failure modes and what the code does

| situation | behaviour |
|---|---|
| proof fails | server sends `FPSI-ERR` and aborts; client raises `ProofRejected` |
| element outside `[2, p-2]` | decoder raises, session aborts |
| empty client or server set | empty vectors, no proof (nothing to prove), still in lockstep |
| radius 0 | round 3 still exchanged with an empty pending list, `d = 0` only |
| peer disappears | channel timeout raises `TransportError`; server thread joined with timeout |
