"""Two-round Diffie-Hellman PSI with client-only output.

Protocol for client set X = {x_1..x_n} and server set Y = {y_1..y_m}:

    C -> S : U = shuffle{ H(x_i)^a }                  (a random)
    S -> C : V = shuffle{ H(y_j)^b }, W = { U_i^b }    (b random, W in the
                                                       order received)
    C      : Z = { v_j^a } = { H(y_j)^{ab} };
             learn { x_i : W_i in Z }

Correctness: W_i = H(x_i)^{ab} and v_j^a = H(y_j)^{ab}, so the value sets
coincide exactly on matching items.  W must come back in the order the client
sent it; otherwise the client could still test membership but could no longer
tell *which* of its own items matched (the values are unlinkable without b).
The server learns nothing from that ordering because it computed W itself,
while U stays shuffled so the server cannot map positions to client items.
The assignment sketch writes the test as "z_j in W"; we invert it to
"W_i in Z" purely so the client can name its own matches.  Cost is the same
one exponentiation per item.  The client cannot recover H(y_j)^b for
a y_j it did not query, and the server sees only a permutation of blinded
elements.  Security rests on DDH in the order-q subgroup of the RFC 3526
2048-bit group; the usual one-more-DH caveat applies (the client obtains one
b-th power per element it submits, so a client that submits t elements
learns t b-th powers).  That is why the query count must be checked against
the declared set size, and why the batch consistency proof in schnorr.py
matters: it forces a single exponent for the whole submission.

Cost: two exponentiations per item per side.  Elements are serialized at a
fixed 256 bytes, so message sizes are exactly 256 * (number of elements).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import group
from .group import P


@dataclass
class BlindState:
    """Client-side state of the first round."""

    keys: list[bytes]
    bases: list[int]
    blinded: list[int]

    @property
    def count(self) -> int:
        return len(self.keys)


def unique_keys(keys) -> list[bytes]:
    """De-duplicate while preserving first-seen order."""
    seen: set[bytes] = set()
    ordered: list[bytes] = []
    for key in keys:
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def client_blind(keys: list[bytes], a: int) -> BlindState:
    """Compute bases H(key) and blinded values H(key)^a (order preserved)."""
    if not 2 <= a < P:
        raise ValueError("exponent out of range")
    bases = [group.hash_to_group(k) for k in keys]
    blinded = [pow(base, a, P) for base in bases]
    return BlindState(keys=list(keys), bases=bases, blinded=blinded)


def server_respond(
    server_keys: list[bytes], blinded: list[int], b: int, rng: secrets.SystemRandom | None = None
) -> tuple[list[int], list[int]]:
    """Server round: V = H(y)^b shuffled, W = u^b in the order received.

    Shuffling W would destroy the client's ability to map a positive test back
    to its own input, so the server keeps the received order (see module
    docstring).
    """
    if not 2 <= b < P:
        raise ValueError("exponent out of range")
    rng = rng or secrets.SystemRandom()
    v_list = [pow(group.hash_to_group(key), b, P) for key in server_keys]
    w_list = [pow(value, b, P) for value in blinded]
    rng.shuffle(v_list)
    return v_list, w_list


def client_finish(
    state: BlindState, a: int, v_list: list[int], w_list: list[int]
) -> set[bytes]:
    """Intersect client keys against the server reply.

    ``w_list`` must be in the same order as ``state.blinded`` (the order the
    client sent), which server_respond guarantees.
    """
    if len(w_list) != state.count:
        raise ValueError("server reply does not match the client submission")
    targets = {pow(value, a, P) for value in v_list}
    return {key for key, w in zip(state.keys, w_list) if w in targets}


def intersect(
    client_keys: list[bytes],
    server_keys: list[bytes],
    a: int | None = None,
    b: int | None = None,
    exponent_bits: int = group.DEFAULT_EXPONENT_BITS,
) -> set[bytes]:
    """Convenience wrapper used by tests and micro-benchmarks."""
    a = group.rand_exponent(bits=exponent_bits) if a is None else a
    b = group.rand_exponent(bits=exponent_bits) if b is None else b
    state = client_blind(client_keys, a)
    v_list, w_list = server_respond(server_keys, state.blinded, b)
    return client_finish(state, a, v_list, w_list)


def client_payload_size(count: int) -> int:
    """Bytes on the wire for the client's first message (elements only)."""
    return count * group.ELEMENT_BYTES


def server_payload_size(client_count: int, server_count: int) -> int:
    return (client_count + server_count) * group.ELEMENT_BYTES
