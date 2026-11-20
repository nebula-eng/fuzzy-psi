# Threat model

## 1. Setting

Two organisations share threat-intelligence indicators. Party C (client)
queries with set `X`, party S (server) answers with set `Y`. The intended
output is `{ x in X : exists y in Y with Hamming(simhash(x), simhash(y)) <= t }`
delivered to C only. Neither party should learn the other's non-matching items,
and S must not be usable as an oracle that answers more membership tests than C
is entitled to.

## 2. Assets

| asset | owner | sensitivity |
|---|---|---|
| indicator strings in `X`, `Y` | each party | high (customer data, victim identities) |
| 64-bit simhash and 12-bit band keys | derived from items | medium (60 of 64 bits are fingerprinted; dictionary-attackable) |
| set size, submission size | each party | low-medium (metadata) |
| the intersection itself | shared | high |

## 3. Trust assumptions

* Semi-honest server. Follows the protocol, may try to infer `X` from what
  it receives. No malicious-server protection is claimed (see section 8).
* Malicious client for the consistency property: may deviate arbitrarily in
  what it sends, but cannot break DDH or the random oracle.
* Both parties have authentic channels to each other's public parameters. No
  authentication of the peer identity is provided by this code: run it inside
  TLS or a mutually authenticated channel if identities matter.
* No side-channel resistance is claimed (Python big integers, timing of `pow`).

## 4. What each party learns

Client C learns:

* `|Y|` (the length of the server's `v` list in round 1);
* which of its own band keys collide with `Y` - this is the fuzzy-match signal,
  and a collision reveals "something similar exists" but not which server item;
* for confirmed candidates, that a near match exists (not the server's sketch
  or item);
* the intersection at item level (the intended output).

Server S learns:

* `|X|` and the number of distinct band keys `n_k = |{band keys of X}|`, which is
  at most `5|X|` and typically `0.54 |X|` per band in the measurements;
* a uniformly shuffled vector of blinded band keys `H(x)^a` - pseudorandom under
  DDH, no per-item information;
* the bases `B_i`, because the batch consistency proof is only checkable if
  the verifier can evaluate `prod B_i^{rho_i}`. This is the dominant leak, see
  section 5;
* in round 3, the client's candidate sketches in the clear (64 bits per
  candidate), of which it already knew 60 bits from the band keys;
* in round 3 it also evaluates the distance test itself, so it learns *which of
  its own items* are within `t` of a client probe - the match relation at
  sketch level, without learning the client's item strings. This is a direct
  consequence of server-side evaluation and is the reason a malicious server is
  out of scope: the same code path could lie about the answer and cannot be
  caught.

## 5. The consistency proof: coverage and cost

### What it proves

One exponent `a` for the entire submission, `U_i = B_i^a`, via a batched
Chaum-Pedersen argument with per-item 128-bit scalars `rho_i` derived by
Fiat-Shamir from the transcript (`docs/DESIGN.md`, section 3).

### What it prevents

| attack | effect of the proof |
|---|---|
| per-item exponents `a + delta_i` to obtain `b`-th powers of linear combinations of server elements | rejected with probability `>= 1 - 2^-128` |
| reordering, dropping or substituting items between the proof and the message | transcript and challenge change, rejected |
| replaying a proof against a different vector | challenge binds the full transcript, rejected |
| small-subgroup or `p-1` elements | decoder range check rejects `x <= 1` and `x >= p-1` |

The bound is one-shot: the client cannot grind because `c` hashes the same
transcript that determines `rho`. Twenty random perturbations are rejected in
the test suite; the security argument is the random-oracle one, not the test.

### What it does not prevent

* Base disclosure. Because `B_i` is needed by the verifier, the server
  learns `H(band_key_i)`. The band-key space is `5 * 2^12` candidates, so a
  server builds one recovery table for the whole `5 x 4096` space in 53.0 ms
  (median of 20 runs, Python 3.13, `results/leakage.json`); lookups per item are
  then O(1). From the recovered 60-bit sketch prefix it can run an offline
  dictionary attack on the client's items at 354 us per candidate simhash.
  `scripts/leak_probe.py` reproduces both numbers. In other words, against a
  semi-honest but curious server, the proof costs the client its band-key
  privacy, which in turn weakens item privacy to sketch-prefix privacy.
* Input-size inflation. The proof says "one exponent for what you sent", not
  "what you sent is a commitment to a declared set of size n". A client can
  submit more keys than its declared set. Mitigation: enforce the declared size
  and rate-limit sessions.
* Base substitution. The verifier checks consistency relative to supplied
  bases; it cannot tell whether a base is a hash of a legitimate band key.
  Inherent to PSI (the client chooses its input); it means the proof is an
  audit and rate-limiting mechanism, not a privacy amplifier.

The fix for base disclosure is to prove the same statement with `B_i` as
private witnesses, e.g. a zk-SNARK over a Merkle commitment to the client's
band keys, and to give the server only the commitment. That is out of scope for
a standard-library implementation.

## 6. LSH leakage

* Frequency/pattern leakage. Band keys are 12-bit chunks of a 64-bit
  simhash. Duplicated or near-duplicated indicators collapse onto the same
  keys; the server sees the *deduplicated* key multiset, so it learns how many
  distinct bands the client's set contains and, after the proof, their values.
  A client whose set contains many variants of one family shows a distinctive
  band-reuse pattern.
* Cross-session linkage. `H(band_key)` is deterministic, so the same key
  produces the same base in every session and the same blinded value under a
  reused exponent. Mitigation: a fresh server-chosen per-session salt in the
  base derivation (`H(salt || band_key)`). The salt must be public for both
  sides to agree, so it does not stop enumeration, only cross-session linkage.
* Candidate-set leakage in round 3. The client's pending tokens reveal
  which bands it is probing and its full sketch for those items. Padding or
  batching can hide the volume, not the values.
* Size leakage. `|X|`, `|Y|` and the number of colliding bands are visible.
  Fixed-size submissions (`pad_client_keys`) and dummy queries reduce this at
  linear cost in bandwidth and time.

## 7. Mitigations available in this code base

| leak | mitigation | status |
|---|---|---|
| submission size | `Params(pad_client_keys=N)` adds random dummy keys | implemented, off by default |
| volume of round-3 probes | batch several radii into one session, rate-limit | policy, not code |
| cross-session linkage | per-session salt in base derivation | documented, not implemented |
| base disclosure | zk proof over a commitment | out of scope |
| server evaluating round 3 | MPC Hamming distance | out of scope |

## 8. Out of scope

* Malicious server. It can lie in round 3, return a subset of matches, or
  run a different protocol. It can also learn the client's band keys (section
  5), so it can compute the honest answer itself; correctness against a
  malicious server needs verifiable computation, not implemented.
* Collusion of one party with an observer of the other's traffic.
* Traffic analysis. Message sizes reveal `n_k`, `t_c` and `h`, even if the
  payloads are opaque.
* Denial of service, memory exhaustion, and malformed-input fuzzing beyond
  the length and range checks in the decoders.
* Quantum adversaries. DDH in a 2048-bit MODP group gives no post-quantum
  security.
* Legal/compliance constraints on sharing indicators across jurisdictions.

## 9. Ethics

The code is a research artefact for authorised threat-intelligence sharing and
for teaching. It processes synthetic indicators only; no real victim data,
personal data or live blocklists are included. Running the protocol against a
party that has not consented to the leakage described above would be deceptive:
the base-disclosure leak (section 5) should be disclosed to participants before
deployment, and the 2048-bit MODP parameters should be replaced with an
elliptic-curve group before any production use.

## 10. Residual risk summary

| risk | severity | note |
|---|---|---|
| server recovers client band keys from bases | high | 53.0 ms per submission, measured |
| offline dictionary attack on client items | high | follows from the above, 354 us/candidate |
| client probes more items than declared | medium | rate limiting required |
| candidate-set leakage in round 3 | medium | inherent to server-side distance check |
| size/linkage metadata | low-medium | padding and per-session salt help |
| malicious server correctness | high | explicitly out of scope |
