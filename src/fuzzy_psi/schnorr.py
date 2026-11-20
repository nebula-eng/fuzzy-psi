"""Batch Chaum-Pedersen consistency proof (Fiat-Shamir, non-interactive).

Statement proved by the client for one PSI submission:

    A = g^a  and  prod_i U_i^{rho_i} = ( prod_i H_i^{rho_i} )^a

with per-item scalars rho_i = H(transcript || i) truncated to 128 bits and
U_i = H_i^a.  Passing the check means the whole submission was produced with
a single exponent a, i.e. the client cannot mix exponents across items.

Why that matters: with per-item, freely chosen exponents a_i = a + delta_i
the returned w_i = (H_i^{a_i})^b lets a client compute b-th powers of
*chosen linear combinations* of server elements, which is the opening for
one-more-DH style amplification and for probing predicates instead of plain
membership.  A single exponent reduces the client's capability to exactly
one membership test per submitted band key.

Batch soundness: a client that fixes U (hence rho, by Fiat-Shamir) and
deviates on at least one item, U_k = H_k^{a + delta}, passes only if
H_k^{rho_k * delta} = 1.  H_k lies in the order-q subgroup, delta != 0 and q
is prime, so this requires rho_k = 0 mod q, i.e. probability 2^-128 per
attempt under the random-oracle assumption.  Detecting a single flipped item
therefore succeeds with probability >= 1 - 2^-128, and the guarantee is
one-shot: the client cannot grind, because rho is a function of U and the
challenge c binds U as well.

What the proof does NOT do is documented in docs/THREAT_MODEL.md: it binds
the client to *some* exponent and to *some* base vector, but the verifier
cannot tell whether the declared bases are hashes of real band keys.  A
client may therefore submit any |X| keys it likes (that is inherent to PSI:
the client chooses its input).  The proof bounds exponent inconsistency and
makes the submission auditable; it does not bound the size of the input.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from . import group
from .group import G, P

PROOF_BYTES = 3 * group.ELEMENT_BYTES + 32 + group.ELEMENT_BYTES  # A, T1, T2, c, s
_RHO_BYTES = 16  # 128-bit per-item scalars
_CONTEXT = b"fpsi-cp-v1"


@dataclass(frozen=True)
class BatchProof:
    a_pub: int
    t1: int
    t2: int
    challenge: int
    response: int

    def to_bytes(self) -> bytes:
        return (
            group.element_to_bytes(self.a_pub)
            + group.element_to_bytes(self.t1)
            + group.element_to_bytes(self.t2)
            + self.challenge.to_bytes(32, "big")
            + group.element_to_bytes(self.response)
        )

    @classmethod
    def from_bytes(cls, blob: bytes) -> "BatchProof":
        if len(blob) != PROOF_BYTES:
            raise ValueError(f"proof must be {PROOF_BYTES} bytes")
        step = group.ELEMENT_BYTES
        a_pub = group.bytes_to_element(blob[0:step])
        t1 = group.bytes_to_element(blob[step : 2 * step])
        t2 = group.bytes_to_element(blob[2 * step : 3 * step])
        challenge = int.from_bytes(blob[3 * step : 3 * step + 32], "big")
        response = group.bytes_to_element(blob[3 * step + 32 :])
        return cls(a_pub, t1, t2, challenge, response)


def build_transcript(bases: list[int], blinded: list[int], context: bytes = b"") -> bytes:
    if len(bases) != len(blinded):
        raise ValueError("bases and blinded vectors must have equal length")
    return (
        _CONTEXT
        + context
        + len(bases).to_bytes(4, "big")
        + group.encode_elements(bases)
        + group.encode_elements(blinded)
    )


def derive_rhos(transcript: bytes, count: int) -> list[int]:
    """Per-item scalars rho_i = H(transcript || i) truncated to 128 bits."""
    return [
        int.from_bytes(
            hashlib.sha256(transcript + i.to_bytes(4, "big")).digest()[:_RHO_BYTES],
            "big",
        )
        for i in range(count)
    ]


def _aggregate(values: list[int], rhos: list[int]) -> int:
    acc = 1
    for value, rho in zip(values, rhos):
        acc = (acc * pow(value, rho, P)) % P
    return acc


def _challenge(
    transcript: bytes, a_pub: int, t1: int, t2: int, base_agg: int, blind_agg: int
) -> int:
    payload = (
        b"fpsi-cp-chal-v1"
        + transcript
        + group.element_to_bytes(a_pub)
        + group.element_to_bytes(t1)
        + group.element_to_bytes(t2)
        + group.element_to_bytes(base_agg)
        + group.element_to_bytes(blind_agg)
    )
    return int.from_bytes(hashlib.sha256(payload).digest(), "big")


def prove(
    exponent: int,
    bases: list[int],
    blinded: list[int],
    context: bytes = b"",
) -> BatchProof:
    """Create a proof that every blinded[i] equals bases[i]^exponent."""
    if len(bases) != len(blinded):
        raise ValueError("bases and blinded vectors must have equal length")
    if not bases:
        raise ValueError("an empty statement has no content to prove")
    transcript = build_transcript(bases, blinded, context)
    rhos = derive_rhos(transcript, len(bases))
    base_agg = _aggregate(bases, rhos)
    blind_agg = _aggregate(blinded, rhos)

    a_pub = pow(G, exponent, P)
    k = group.rand_exponent(bits=group.DEFAULT_EXPONENT_BITS)
    t1 = pow(G, k, P)
    t2 = pow(base_agg, k, P)
    challenge = _challenge(transcript, a_pub, t1, t2, base_agg, blind_agg)
    response = (k + challenge * exponent) % (P - 1)
    return BatchProof(a_pub, t1, t2, challenge, response)


def verify(
    proof: BatchProof,
    bases: list[int],
    blinded: list[int],
    context: bytes = b"",
) -> bool:
    """Check the batch consistency statement; returns False on any deviation."""
    try:
        if len(bases) != len(blinded) or not bases:
            return False
        if not (
            group.is_valid_element(proof.a_pub)
            and group.is_valid_element(proof.t1)
            and group.is_valid_element(proof.t2)
            and group.is_valid_element(proof.response)
        ):
            return False
        if not 0 <= proof.challenge < (1 << 256):
            return False
        if not 0 <= proof.response < P - 1:
            return False

        transcript = build_transcript(bases, blinded, context)
        rhos = derive_rhos(transcript, len(bases))
        base_agg = _aggregate(bases, rhos)
        blind_agg = _aggregate(blinded, rhos)

        expected = _challenge(transcript, proof.a_pub, proof.t1, proof.t2, base_agg, blind_agg)
        if not secrets.compare_digest(
            expected.to_bytes(32, "big"), proof.challenge.to_bytes(32, "big")
        ):
            return False

        left = pow(G, proof.response, P)
        right = (pow(proof.a_pub, proof.challenge, P) * proof.t1) % P
        if left != right:
            return False
        left = pow(base_agg, proof.response, P)
        right = (pow(blind_agg, proof.challenge, P) * proof.t2) % P
        return left == right
    except (ValueError, TypeError):
        return False
