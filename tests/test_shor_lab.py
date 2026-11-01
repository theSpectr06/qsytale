import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import shor_lab


class ShorLabTests(unittest.TestCase):
    def test_n15_peaks_and_factors(self):
        r = shor_lab.run_shor(15)
        peaks = {h["y"] for h in r["histogram"]}
        self.assertEqual(peaks, {0, 64, 128, 192})   # multiples of 2^8 / 4
        self.assertEqual(r["r"], 4)
        self.assertEqual((r["p"], r["q"]), (3, 5))
        self.assertEqual(r["d"], 7)
        self.assertEqual(r["decrypted_digits"], [1, 0, 3, 1])
        self.assertEqual(r["qubits"]["total"], 12)

    def test_n21_order_six(self):
        r = shor_lab.run_shor(21)
        self.assertEqual(r["r"], 6)
        self.assertEqual((r["p"], r["q"]), (3, 7))
        self.assertTrue(r["decryption_matches"])

    def test_controlled_mulmod_is_a_permutation(self):
        import numpy as np
        for N, a in ((15, 7), (21, 2)):
            n = N.bit_length()
            U = shor_lab.ctrl_mulmod(a, N, n).to_matrix()
            self.assertTrue(np.allclose(U @ U.T, np.eye(2 * 2 ** n)))

    def test_post_processing_edge_cases(self):
        self.assertEqual(shor_lab.candidate_orders(0, 8, 7, 15), [])
        self.assertIsNone(shor_lab.factors_from_order(7, 3, 15))      # odd order
        self.assertIsNone(shor_lab.factors_from_order(14, 2, 15))     # a^(r/2) = -1 mod N
        self.assertEqual(shor_lab.factors_from_order(7, 4, 15), [3, 5])

    def test_rejects_unsupported_n(self):
        with self.assertRaises(ValueError):
            shor_lab.run_shor(35)


if __name__ == "__main__":
    unittest.main()
