"""End-to-end tests: local channel, real TCP loopback, proof enforcement."""

import unittest

from fuzzy_psi import group, metrics, protocol


def _dataset(size=12, seed=5):
    return metrics.build_dataset(size, seed, overlap_ratio=0.25, variant_ratio=0.25, edits=1)


class TestProtocolLocal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = _dataset(12)
        cls.params = protocol.Params(radius=4)
        cls.result = protocol.run(cls.dataset.client, cls.dataset.server, cls.params)

    def test_no_false_negatives_against_ground_truth(self):
        truth = self.dataset.truth(4)
        missing = truth - self.result.client.matches
        self.assertEqual(missing, set())

    def test_no_false_positives(self):
        truth = self.dataset.truth(4)
        self.assertEqual(self.result.client.matches - truth, set())

    def test_precision_is_one(self):
        recall, precision = metrics.precision_recall(
            self.result.client.matches, self.dataset.truth(4)
        )
        self.assertEqual(precision, 1.0)
        self.assertEqual(recall, 1.0)

    def test_exact_duplicates_confirmed_by_second_psi(self):
        self.assertGreater(self.result.client.exact_tokens, 0)
        self.assertTrue(self.result.client.exact_matches)

    def test_bytes_are_counted(self):
        self.assertGreater(self.result.total_bytes, 0)
        self.assertGreater(self.result.client_channel_bytes, 0)
        self.assertGreater(self.result.server_channel_bytes, 0)

    def test_phase_times_present(self):
        phases = metrics.phase_breakdown(self.result)
        self.assertGreater(phases["psi1"], 0.0)
        self.assertGreater(phases["psi2"], 0.0)
        self.assertGreater(self.result.wall_time, 0.0)

    def test_proof_bytes_in_wire_format(self):
        self.assertEqual(protocol.schnorr.PROOF_BYTES, 1056)

    def test_deterministic_matches_across_runs(self):
        again = protocol.run(self.dataset.client, self.dataset.server, self.params)
        self.assertEqual(again.client.matches, self.result.client.matches)


class TestProtocolEdgeCases(unittest.TestCase):
    def test_empty_client(self):
        result = protocol.run([], ["only-on-server"], protocol.Params(radius=4))
        self.assertEqual(result.client.matches, set())

    def test_no_candidates(self):
        client = ["completely-unrelated-alpha"]
        server = ["zulu-bravo-" + "9" * 30]
        result = protocol.run(client, server, protocol.Params(radius=4))
        self.assertEqual(result.client.matches, set())

    def test_radius_zero_matches_exact_sketches(self):
        dataset = _dataset(10, seed=9)
        result = protocol.run(dataset.client, dataset.server, protocol.Params(radius=0))
        truth = dataset.truth(0)
        self.assertTrue(truth.issubset(result.client.matches))

    def test_padding_changes_byte_count(self):
        dataset = _dataset(8, seed=3)
        plain = protocol.run(dataset.client, dataset.server, protocol.Params(radius=4))
        padded = protocol.run(
            dataset.client, dataset.server,
            protocol.Params(radius=4, pad_client_keys=400),
        )
        self.assertGreater(padded.total_bytes, plain.total_bytes)
        self.assertEqual(padded.client.matches, plain.client.matches)


class TestProofEnforcement(unittest.TestCase):
    def test_inconsistent_exponent_is_rejected(self):
        dataset = _dataset(8, seed=11)

        def tamper(blinded, bases):
            broken = list(blinded)
            broken[-1] = pow(broken[-1], 7, group.P)
            return broken, bases

        with self.assertRaises(protocol.ProofRejected):
            protocol.run(dataset.client, dataset.server, protocol.Params(radius=4), tamper=tamper)

    def test_identity_tamper_still_accepted(self):
        dataset = _dataset(8, seed=12)

        def tamper(blinded, bases):
            return list(blinded), list(bases)

        result = protocol.run(dataset.client, dataset.server, protocol.Params(radius=4), tamper=tamper)
        self.assertEqual(result.client.matches, protocol.run(
            dataset.client, dataset.server, protocol.Params(radius=4)).client.matches)

    def test_proof_disabled_accepts_inconsistent_exponent(self):
        dataset = _dataset(8, seed=13)

        def tamper(blinded, bases):
            broken = list(blinded)
            broken[-1] = pow(broken[-1], 7, group.P)
            return broken, bases

        params = protocol.Params(radius=4, use_proof=False)
        result = protocol.run(dataset.client, dataset.server, params, tamper=tamper)
        self.assertIsInstance(result.client.matches, set)


class TestServerGuards(unittest.TestCase):
    def test_client_cannot_disable_the_proof_flag(self):
        channel_client, channel_server = protocol.net.local_pair()
        forged = protocol._encode_c1(
            protocol.CLIENT1_TAG, protocol.Params(radius=4, use_proof=False), [], [], None
        )
        channel_client.send(forged)
        with self.assertRaises(protocol.ProtocolError):
            protocol.server_side(channel_server, ["item"], protocol.Params(radius=4))

    def test_radius_mismatch_rejected(self):
        channel_client, channel_server = protocol.net.local_pair()
        forged = protocol._encode_c1(
            protocol.CLIENT1_TAG, protocol.Params(radius=8), [], [], None
        )
        channel_client.send(forged)
        with self.assertRaises(protocol.ProtocolError):
            protocol.server_side(channel_server, ["item"], protocol.Params(radius=4))


class TestProtocolTcp(unittest.TestCase):
    def test_loopback_tcp_run(self):
        dataset = _dataset(8, seed=21)
        params = protocol.Params(radius=4)
        local = protocol.run(dataset.client, dataset.server, params)
        tcp = protocol.run_tcp(dataset.client, dataset.server, params)
        self.assertEqual(tcp.client.matches, local.client.matches)
        self.assertGreater(tcp.client_channel_bytes, 0)
        self.assertGreater(tcp.server_channel_bytes, 0)
        self.assertEqual(tcp.total_bytes, local.total_bytes)


class TestBaselines(unittest.TestCase):
    def test_plaintext_baseline(self):
        dataset = _dataset(8, seed=31)
        result = protocol.run_plaintext(dataset.client, dataset.server)
        self.assertGreater(result.total_bytes, 0)
        self.assertTrue(result.matches)

    def test_hash_psi_baseline(self):
        dataset = _dataset(8, seed=31)
        result = protocol.run_hash_psi(dataset.client, dataset.server)
        self.assertGreater(result.total_bytes, 0)
        self.assertTrue(result.matches)

    def test_baseline_is_exact_match_only(self):
        client = ["http://cdn1.example/a", "http://cdn1.example/b0"]
        server = ["http://cdn1.example/a", "http://cdn1.example/b1"]
        exact = protocol.run_plaintext(client, server)
        self.assertEqual(exact.matches, {"http://cdn1.example/a"})


if __name__ == "__main__":
    unittest.main()
