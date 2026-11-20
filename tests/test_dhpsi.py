"""Tests for the two-round DH-PSI core."""

import unittest

from fuzzy_psi import dhpsi, group


class TestDhpsiCorrectness(unittest.TestCase):
    def test_overlap_is_exact(self):
        client = [b"alpha", b"beta", b"gamma", b"delta"]
        server = [b"gamma", b"delta", b"epsilon"]
        self.assertEqual(
            dhpsi.intersect(client, server), {b"gamma", b"delta"}
        )

    def test_disjoint_sets(self):
        self.assertEqual(dhpsi.intersect([b"a", b"b"], [b"c", b"d"]), set())

    def test_full_overlap(self):
        keys = [b"k%d" % i for i in range(12)]
        self.assertEqual(dhpsi.intersect(keys, keys), set(keys))

    def test_empty_client(self):
        self.assertEqual(dhpsi.intersect([], [b"x", b"y"]), set())

    def test_empty_server(self):
        self.assertEqual(dhpsi.intersect([b"x", b"y"], []), set())

    def test_duplicate_client_items(self):
        client = [b"dup", b"dup", b"other"]
        self.assertEqual(dhpsi.intersect(client, [b"dup"]), {b"dup"})

    def test_no_false_negatives_over_many_keys(self):
        client = [b"item-%03d" % i for i in range(40)]
        server = [b"item-%03d" % i for i in range(20, 60)]
        expected = set(client) & set(server)
        self.assertEqual(dhpsi.intersect(client, server), expected)
        self.assertEqual(len(expected), 20)

    def test_repeated_runs_are_stable(self):
        client = [b"q%d" % i for i in range(10)]
        server = [b"q%d" % i for i in range(5, 15)]
        for _ in range(3):
            self.assertEqual(dhpsi.intersect(client, server), {b"q%d" % i for i in range(5, 10)})


class TestDhpsiWire(unittest.TestCase):
    def test_payload_size_formula(self):
        self.assertEqual(dhpsi.client_payload_size(7), 7 * group.ELEMENT_BYTES)
        self.assertEqual(dhpsi.server_payload_size(7, 5), 12 * group.ELEMENT_BYTES)

    def test_state_alignment(self):
        a = group.rand_exponent(bits=256)
        b = group.rand_exponent(bits=256)
        keys = [b"z1", b"z2", b"z3"]
        state = dhpsi.client_blind(keys, a)
        self.assertEqual(state.keys, keys)
        self.assertEqual(len(state.blinded), 3)
        v_list, w_list = dhpsi.server_respond([b"z2"], state.blinded, b)
        matched = dhpsi.client_finish(state, a, v_list, w_list)
        self.assertEqual(matched, {b"z2"})

    def test_reply_length_mismatch_rejected(self):
        a = group.rand_exponent(bits=256)
        state = dhpsi.client_blind([b"a", b"b"], a)
        with self.assertRaises(ValueError):
            dhpsi.client_finish(state, a, [], [])


if __name__ == "__main__":
    unittest.main()
