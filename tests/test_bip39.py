from __future__ import annotations

import unittest

from vaultkit.bip39 import WORDLIST_SHA256, check_mnemonic, load_wordlist, wordlist_path


GOOD = " ".join(["abandon"] * 11 + ["about"])


class Bip39Tests(unittest.TestCase):
    def test_wordlist_is_the_english_bip39_list(self) -> None:
        words = load_wordlist()
        self.assertEqual(len(words), 2048)
        self.assertEqual(words[0], "abandon")
        self.assertEqual(words[-1], "zoo")
        digest = __import__("hashlib").sha256(wordlist_path().read_bytes()).hexdigest()
        self.assertEqual(digest, WORDLIST_SHA256)

    def test_known_vector_and_rejections(self) -> None:
        self.assertTrue(check_mnemonic(GOOD).ok)
        self.assertEqual(check_mnemonic("  " + GOOD.upper() + "\n").reason, "ok")
        self.assertFalse(check_mnemonic(" ".join(["abandon"] * 12)).ok)
        self.assertEqual(check_mnemonic("abandon abandon").reason, "count")
        unknown = check_mnemonic(GOOD.rsplit(" ", 1)[0] + " notaword")
        self.assertEqual(unknown.reason, "unknown")
        self.assertIn("notaword", unknown.unknown)


if __name__ == "__main__":
    unittest.main()
