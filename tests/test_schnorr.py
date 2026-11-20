"""Tests for the batch Chaum-Pedersen consistency proof."""

import unittest

from fuzzy_psi import group, schnorr


def _setup(count=6, exponent_bits=256):
    exponent = group.rand_exponent(bits=exponent_bits)
    bases = [group.hash_to_group(b"base-%d" % i) for i in range(count)]
    blinded = [pow(base, exponent, group.P) for base in bases]
    return exponent, bases, blinded


class TestBatchProof(unittest.TestCase):
    def test_honest_proof_verifies(self):
        exponent, bases, blinded = _setup()
        proof = schnorr.prove(exponent, bases, blinded)
        self.assertTrue(schnorr.verify(proof, bases, blinded))

    def test_proof_is_1056_bytes(self):
        exponent, bases, blinded = _setup(4)
        proof = schnorr.prove(exponent, bases, blinded)
        self.assertEqual(len(proof.to_bytes()), schnorr.PROOF_BYTES)
        self.assertEqual(schnorr.PROOF_BYTES, 1056)

    def test_serialization_roundtrip(self):
        exponent, bases, blinded = _setup(4)
        proof = schnorr.prove(exponent, bases, blinded)
        restored = schnorr.BatchProof.from_bytes(proof.to_bytes())
        self.assertTrue(schnorr.verify(restored, bases, blinded))

    def test_tampered_blinded_rejected(self):
        exponent, bases, blinded = _setup()
        proof = schnorr.prove(exponent, bases, blinded)
        tampered = list(blinded)
        tampered[3] = pow(tampered[3], 5, group.P)
        self.assertFalse(schnorr.verify(proof, bases, tampered))

    def test_swapped_items_rejected(self):
        exponent, bases, blinded = _setup()
        proof = schnorr.prove(exponent, bases, blinded)
        swapped = list(blinded)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        self.assertFalse(schnorr.verify(proof, bases, swapped))

    def test_tampered_base_rejected(self):
        exponent, bases, blinded = _setup()
        proof = schnorr.prove(exponent, bases, blinded)
        tampered = list(bases)
        tampered[0] = group.hash_to_group(b"different")
        self.assertFalse(schnorr.verify(proof, tampered, blinded))

    def test_per_item_exponents_rejected(self):
        """The attack the proof exists to stop: mix exponents across items."""
        exponent, bases, blinded = _setup(5)
        proof = schnorr.prove(exponent, bases, blinded)
        mixed = list(blinded)
        mixed[2] = pow(bases[2], exponent + 12345, group.P)
        self.assertFalse(schnorr.verify(proof, bases, mixed))

    def test_tampered_response_rejected(self):
        exponent, bases, blinded = _setup()
        proof = schnorr.prove(exponent, bases, blinded)
        broken = schnorr.BatchProof(
            proof.a_pub, proof.t1, proof.t2, proof.challenge, (proof.response + 1) % (group.P - 1)
        )
        self.assertFalse(schnorr.verify(broken, bases, blinded))

    def test_tampered_challenge_rejected(self):
        exponent, bases, blinded = _setup()
        proof = schnorr.prove(exponent, bases, blinded)
        broken = schnorr.BatchProof(
            proof.a_pub, proof.t1, proof.t2, (proof.challenge + 1) % (1 << 256), proof.response
        )
        self.assertFalse(schnorr.verify(broken, bases, blinded))

    def test_context_binding(self):
        exponent, bases, blinded = _setup()
        proof = schnorr.prove(exponent, bases, blinded, context=b"stage-one")
        self.assertTrue(schnorr.verify(proof, bases, blinded, context=b"stage-one"))
        self.assertFalse(schnorr.verify(proof, bases, blinded, context=b"stage-two"))

    def test_empty_statement_rejected(self):
        exponent, bases, blinded = _setup(3)
        proof = schnorr.prove(exponent, bases, blinded)
        self.assertFalse(schnorr.verify(proof, [], []))
        with self.assertRaises(ValueError):
            schnorr.prove(exponent, [], [])

    def test_random_forgeries_rejected(self):
        """20 random perturbations are all rejected (empirical tamper check)."""
        exponent, bases, blinded = _setup(8)
        proof = schnorr.prove(exponent, bases, blinded)
        rejected = 0
        for i in range(20):
            modified = list(blinded)
            modified[i % len(modified)] = pow(modified[i % len(modified)], 2 + i, group.P)
            rejected += 0 if schnorr.verify(proof, bases, modified) else 1
        self.assertEqual(rejected, 20)


if __name__ == "__main__":
    unittest.main()
