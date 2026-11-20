"""Locality-sensitive hashing over character 3-grams (simhash + banding).

Pipeline for one indicator string s:

    shingles(s)  ->  frozenset of 3-grams (with boundary markers)
    simhash(...) ->  64-bit sketch, one weighted majority vote per bit
    band_keys(..)->  b disjoint r-bit chunks used as PSI keys

A pair collides (becomes a candidate) if at least one band is bit-identical.
With disjoint bands of r bits over a 64-bit sketch and d differing bits placed
uniformly, the probability that every band is hit at least once is given by
inclusion-exclusion:

    P(miss) = sum_{k=0..b} (-1)^k * C(b, k) * C(64 - k*r, d) / C(64, d)

so recall is R(d) = 1 - P(miss).  The textbook shortcut
1 - (1 - (1 - d/64)^r)^b ignores that d < b forces some band to be untouched;
for b = 5, r = 12 it predicts 0.954 at d = 4 while the exact value is 1.0
(pigeonhole: 4 differing bits cannot hit all 5 bands).  We report the exact
value in the documents and use the same function in the tests.

The 4 spare bits (60 of 64 are covered) are kept unused so the bands stay
disjoint; using all 64 would need 5 bands of 12.8 bits.
"""

from __future__ import annotations

import hashlib
import struct
import math
from dataclasses import dataclass

BANDS = 5
BAND_BITS = 12

_PERSON = b"fpsi-simhash01"
MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class LshParams:
    bands: int = BANDS
    band_bits: int = BAND_BITS

    def __post_init__(self) -> None:
        if self.bands < 1 or self.band_bits < 1:
            raise ValueError("bands and band_bits must be positive")
        if self.bands * self.band_bits > 64:
            raise ValueError("bands * band_bits must not exceed 64")

    @property
    def chunk_mask(self) -> int:
        return (1 << self.band_bits) - 1


def shingles(text: str, k: int = 3) -> frozenset[bytes]:
    """Character k-grams of the normalized string, with ^ and $ sentinels."""
    normalized = text.strip().lower()
    padded = "^" + normalized + "$"
    if len(padded) < k:
        return frozenset({padded.encode("utf-8")})
    return frozenset(
        padded[i : i + k].encode("utf-8") for i in range(len(padded) - k + 1)
    )


def _shingle_hash(shingle: bytes) -> int:
    return int.from_bytes(
        hashlib.blake2b(shingle, digest_size=8, person=_PERSON).digest(), "big"
    )


def simhash(grams: frozenset[bytes], weights: dict[bytes, float] | None = None) -> int:
    """64-bit simhash by weighted majority vote over the shingle hashes.

    ``weights`` maps a shingle to a positive weight (an IDF table would go
    here); shingles missing from the table weigh 1.0, which is the default
    uniform weighting used throughout this project.
    """
    accumulator = [0.0] * 64
    for gram in grams:
        weight = 1.0 if weights is None else float(weights.get(gram, 1.0))
        if weight <= 0.0:
            continue
        value = _shingle_hash(gram)
        for bit in range(64):
            if (value >> bit) & 1:
                accumulator[bit] += weight
            else:
                accumulator[bit] -= weight
    sketch = 0
    for bit in range(64):
        if accumulator[bit] > 0.0:
            sketch |= 1 << bit
    return sketch & MASK64


def band_keys(sketch: int, params: LshParams = LshParams()) -> list[bytes]:
    """Return b band keys, each 2-byte band index + r/8 bytes of chunk."""
    width = (params.band_bits + 7) // 8
    keys = []
    for band in range(params.bands):
        chunk = (sketch >> (band * params.band_bits)) & params.chunk_mask
        keys.append(struct.pack(">H", band) + chunk.to_bytes(width, "big"))
    return keys


def band_of(key: bytes) -> int:
    return struct.unpack(">H", key[:2])[0]


def hamming(a: int, b: int) -> int:
    return ((a ^ b) & MASK64).bit_count()


def expected_recall(distance: int, params: LshParams = LshParams()) -> float:
    """Exact candidate recall for d uniformly placed differing bits.

    Idealization: real simhash differences cluster around edited regions, so
    these values are a reference point, not a guarantee (see EVALUATION.md).
    """
    if distance < 0 or distance > 64:
        raise ValueError("distance must be in [0, 64]")
    total = math.comb(64, distance)
    if total == 0:
        return 0.0
    missing = 0
    for k in range(params.bands + 1):
        available = 64 - k * params.band_bits
        if available < distance:
            continue
        term = math.comb(params.bands, k) * math.comb(available, distance)
        missing += term if k % 2 == 0 else -term
    recall = 1.0 - missing / total
    return min(1.0, max(0.0, recall))
