"""Group arithmetic for the fuzzy-PSI protocol.

The protocol runs in the RFC 3526 2048-bit MODP group (id 14):

    p = 2^2048 - 2^1984 - 1 + 2^64 * ( floor(2^1918 * pi) + 124476 )
    g = 2

The modulus is a safe prime (p = 2q + 1 with q prime), so Z_p^* has the
subgroup structure {1} x Z_q.  Because p = 7 (mod 8), 2 is a quadratic
residue and therefore generates the prime-order subgroup of size q; all
exponents are understood modulo q even when the arithmetic below reduces
them modulo p-1 (the two are equivalent in the exponent because g^q = 1).

Design note (also recorded in docs/DESIGN.md): hashing into the group is
done by hashing to an integer and squaring it ("cofactor clearing").  A
real deployment should use a hash-to-curve construction with a
uniform-output proof; for a safe-prime MODP group the squaring step is the
standard substitute and keeps every base inside the order-q subgroup, which
is what the DDH-based privacy argument needs.
"""

from __future__ import annotations

import hashlib
import secrets

# ---------------------------------------------------------------------------
# RFC 3526, 2048-bit MODP group (group id 14).
# ---------------------------------------------------------------------------
_MODP2048_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)

P = int(_MODP2048_HEX, 16)
Q = (P - 1) // 2
G = 2

#: Fixed-width serialization.  Every group element travels as 256 bytes so
#: that message sizes are easy to account for and independent of the value.
ELEMENT_BYTES = 256

#: 256-bit exponents.  Discrete-log security comes from the 2048-bit
#: modulus (~110 bits with GNFS); a 256-bit exponent keeps the exponent
#: search space at 2^128, so it is not the bottleneck.  Full-size exponents
#: (2048 bits) cost ~8x more per exponentiation in CPython with no security
#: gain, see docs/DESIGN.md.
DEFAULT_EXPONENT_BITS = 256
MIN_EXPONENT_BITS = 224

_H2G_TAG = b"fpsi-h2g-v1"


def hash_to_group(data: bytes, tag: bytes = _H2G_TAG) -> int:
    """Map arbitrary bytes to a non-trivial element of the order-q subgroup.

    x = int(sha256(tag || ctr || data)) mod p, squared to clear the
    cofactor 2, retrying with an incremented counter on 0/1.
    """
    for counter in range(1, 257):
        digest = hashlib.sha256(tag + counter.to_bytes(2, "big") + data).digest()
        x = int.from_bytes(digest, "big") % P
        if x <= 1:
            continue
        h = (x * x) % P
        if h > 1:
            return h
    raise RuntimeError("hash_to_group failed to find a valid element")


def rand_exponent(bits: int | None = None) -> int:
    """Return a secret exponent in [2, p-2] (or in [2, 2^bits))."""
    if bits is None or bits >= P.bit_length():
        return 2 + secrets.randbelow(P - 3)
    if bits < MIN_EXPONENT_BITS:
        raise ValueError(f"exponent must be at least {MIN_EXPONENT_BITS} bits")
    while True:
        value = secrets.randbits(bits)
        if value >= 2:
            return value


def element_to_bytes(value: int) -> bytes:
    if not 1 < value < P - 1:
        raise ValueError("element out of range")
    return value.to_bytes(ELEMENT_BYTES, "big")


def bytes_to_element(blob: bytes) -> int:
    """Decode and range-check a group element.

    For a safe prime the only proper subgroups are {1} and {1, p-1}, so the
    range test 1 < x < p-1 excludes both small-subgroup elements.  We do not
    run a full order-q membership test (one 2047-bit exponentiation per
    element) and say so in the design document.
    """
    if len(blob) != ELEMENT_BYTES:
        raise ValueError(f"element must be {ELEMENT_BYTES} bytes, got {len(blob)}")
    value = int.from_bytes(blob, "big")
    if not 1 < value < P - 1:
        raise ValueError("element out of range")
    return value


def is_valid_element(value: int) -> bool:
    return isinstance(value, int) and 1 < value < P - 1


def encode_elements(values: list[int]) -> bytes:
    return b"".join(element_to_bytes(v) for v in values)


def decode_elements(blob: bytes) -> list[int]:
    if len(blob) % ELEMENT_BYTES != 0:
        raise ValueError("element vector is not a multiple of the element size")
    return [
        bytes_to_element(blob[i : i + ELEMENT_BYTES])
        for i in range(0, len(blob), ELEMENT_BYTES)
    ]
