"""Tests for the RFC 3526 group helpers."""

import unittest

from fuzzy_psi import group


class TestGroupConstants(unittest.TestCase):
    def test_modulus_is_2048_bits(self):
        self.assertEqual(group.P.bit_length(), 2048)

    def test_safe_prime_structure(self):
        self.assertEqual(group.P % 4, 3)
        self.assertEqual(group.P, 2 * group.Q + 1)

    def test_generator_has_prime_order(self):
        self.assertEqual(pow(group.G, group.Q, group.P), 1)
        self.assertNotEqual(pow(group.G, 2, group.P), 1)
        self.assertNotEqual(pow(group.G, 1, group.P), 1)

    def test_element_size(self):
        self.assertEqual(group.ELEMENT_BYTES, 256)


class TestHashToGroup(unittest.TestCase):
    def test_range_and_subgroup(self):
        for i in range(16):
            value = group.hash_to_group(b"indicator-%d" % i)
            self.assertGreater(value, 1)
            self.assertLess(value, group.P - 1)
            self.assertEqual(pow(value, group.Q, group.P), 1)

    def test_deterministic(self):
        self.assertEqual(group.hash_to_group(b"same"), group.hash_to_group(b"same"))

    def test_domain_separation(self):
        self.assertNotEqual(
            group.hash_to_group(b"same"), group.hash_to_group(b"same", tag=b"other-tag")
        )

    def test_distinct_inputs(self):
        values = {group.hash_to_group(b"x-%d" % i) for i in range(64)}
        self.assertEqual(len(values), 64)


class TestExponents(unittest.TestCase):
    def test_default_range(self):
        for _ in range(8):
            value = group.rand_exponent()
            self.assertGreaterEqual(value, 2)
            self.assertLessEqual(value, group.P - 2)

    def test_bounded(self):
        for _ in range(8):
            value = group.rand_exponent(bits=256)
            self.assertGreaterEqual(value, 2)
            self.assertLess(value, 1 << 256)

    def test_rejects_weak_exponents(self):
        with self.assertRaises(ValueError):
            group.rand_exponent(bits=8)


class TestSerialization(unittest.TestCase):
    def test_roundtrip(self):
        value = group.hash_to_group(b"serialize")
        self.assertEqual(group.bytes_to_element(group.element_to_bytes(value)), value)

    def test_rejects_wrong_length(self):
        with self.assertRaises(ValueError):
            group.bytes_to_element(b"\x01" * 16)

    def test_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            group.bytes_to_element((0).to_bytes(group.ELEMENT_BYTES, "big"))
        with self.assertRaises(ValueError):
            group.bytes_to_element((group.P - 1).to_bytes(group.ELEMENT_BYTES, "big"))

    def test_vector_roundtrip(self):
        values = [group.hash_to_group(b"v%d" % i) for i in range(4)]
        blob = group.encode_elements(values)
        self.assertEqual(len(blob), 4 * group.ELEMENT_BYTES)
        self.assertEqual(group.decode_elements(blob), values)


if __name__ == "__main__":
    unittest.main()
