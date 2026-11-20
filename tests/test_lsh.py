"""Tests for shingling, simhash and banding."""

import random
import unittest

from fuzzy_psi import lsh


class TestShingles(unittest.TestCase):
    def test_deterministic_and_lowercased(self):
        self.assertEqual(lsh.shingles("AbC"), lsh.shingles("abc"))

    def test_boundary_markers(self):
        self.assertIn(b"^ab", lsh.shingles("abc"))
        self.assertIn(b"bc$", lsh.shingles("abc"))

    def test_short_string(self):
        self.assertEqual(len(lsh.shingles("a")), 1)

    def test_one_edit_changes_few_shingles(self):
        base = lsh.shingles("http://cdn7.malware.example/payload.bin")
        variant = lsh.shingles("http://cdn7.malware.example/payl0ad.bin")
        overlap = len(base & variant) / len(base | variant)
        self.assertGreater(overlap, 0.7)


class TestSimhash(unittest.TestCase):
    def test_deterministic(self):
        text = "sha256:" + "ab" * 32
        self.assertEqual(lsh.simhash(lsh.shingles(text)), lsh.simhash(lsh.shingles(text)))

    def test_64_bits(self):
        value = lsh.simhash(lsh.shingles("anything"))
        self.assertGreaterEqual(value, 0)
        self.assertLess(value, 1 << 64)

    def test_identical_text_zero_distance(self):
        text = "actor-1@drop.malware.example"
        self.assertEqual(
            lsh.hamming(lsh.simhash(lsh.shingles(text)), lsh.simhash(lsh.shingles(text))), 0
        )

    def test_near_duplicate_is_close(self):
        base = "http://cdn00042.malware.example/assets/0a1b2c3d/payload.bin?sig=deadbeef"
        variant = "http://cdn00042.malware.example/assets/0a1b2c3d/payl0ad.bin?sig=deadbeef"
        distance = lsh.hamming(
            lsh.simhash(lsh.shingles(base)), lsh.simhash(lsh.shingles(variant))
        )
        self.assertLessEqual(distance, 12)

    def test_unrelated_texts_are_far(self):
        a = lsh.simhash(lsh.shingles("alpha.example/path/one"))
        b = lsh.simhash(lsh.shingles("zulu.example/" + "9" * 40))
        self.assertGreater(lsh.hamming(a, b), 12)


class TestBanding(unittest.TestCase):
    def test_band_count_and_indices(self):
        keys = lsh.band_keys(0x1234_5678_9ABC_DEF0)
        self.assertEqual(len(keys), lsh.BANDS)
        self.assertEqual([lsh.band_of(key) for key in keys], list(range(lsh.BANDS)))
        self.assertEqual(len(set(keys)), lsh.BANDS)

    def test_band_width(self):
        params = lsh.LshParams(bands=4, band_bits=16)
        keys = lsh.band_keys(0xFFFF_0000_FFFF_0000, params)
        self.assertEqual(len(keys), 4)
        self.assertEqual(len(keys[0]), 4)  # 2-byte index + 2-byte chunk

    def test_invalid_params(self):
        with self.assertRaises(ValueError):
            lsh.LshParams(bands=8, band_bits=9)

    def test_recall_at_radius_four(self):
        """Empirical candidate recall at exact Hamming distance 4."""
        rng = random.Random(20241114)
        params = lsh.LshParams()
        hits = 0
        trials = 1500
        for _ in range(trials):
            left = rng.getrandbits(64)
            flip = 0
            for position in rng.sample(range(64), 4):
                flip |= 1 << position
            right = left ^ flip
            if set(lsh.band_keys(left, params)) & set(lsh.band_keys(right, params)):
                hits += 1
        recall = hits / trials
        self.assertGreaterEqual(recall, 0.90, f"measured recall {recall:.3f}")
        # 4 differing bits cannot hit all 5 bands, so at d=4 the exact value is 1.0.
        self.assertEqual(recall, 1.0)

    def test_far_pairs_rarely_collide(self):
        rng = random.Random(7)
        params = lsh.LshParams()
        hits = 0
        trials = 800
        for _ in range(trials):
            left = rng.getrandbits(64)
            flip = 0
            for position in rng.sample(range(64), 32):
                flip |= 1 << position
            if set(lsh.band_keys(left, params)) & set(lsh.band_keys(left ^ flip, params)):
                hits += 1
        self.assertLess(hits / trials, 0.02)

    def test_analytic_recall_matches_simulation_at_radius_eight(self):
        rng = random.Random(99)
        params = lsh.LshParams()
        hits = 0
        trials = 1200
        for _ in range(trials):
            left = rng.getrandbits(64)
            flip = 0
            for position in rng.sample(range(64), 8):
                flip |= 1 << position
            if set(lsh.band_keys(left, params)) & set(lsh.band_keys(left ^ flip, params)):
                hits += 1
        measured = hits / trials
        analytical = lsh.expected_recall(8)
        self.assertAlmostEqual(measured, analytical, delta=0.06)
        self.assertLess(analytical, 0.90)

    def test_recall_monotone_in_distance(self):
        values = [lsh.expected_recall(d) for d in range(0, 33)]
        for previous, current in zip(values, values[1:]):
            self.assertGreaterEqual(previous + 1e-12, current)


if __name__ == "__main__":
    unittest.main()
