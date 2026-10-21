from __future__ import annotations

import base64
import json
import tempfile
import time
import unittest
import unicodedata
from pathlib import Path

from vaultkit.app import VaultApp, exclusive
from vaultkit.crypto import KdfParams, VaultError, load_file
from vaultkit.entries import entry_from_user

FAST = KdfParams(time_cost=1, memory_cost=1024, parallelism=1, hash_len=32, salt=b"\x22" * 16)
PASSWORD = "test-password-ok"
NEW_PASSWORD = "another-password-ok"
PHRASE = " ".join(["abandon"] * 11 + ["about"])
CARD = "4242424242424242"


def mnemonic_body(title: str = "冷钱包") -> dict:
    return {
        "id": "",
        "kind": "mnemonic",
        "title": title,
        "secret": {
            "words": PHRASE,
            "words_confirm": PHRASE,
            "passphrase": "UniquePassphraseZZZ",
            "address_hint": "",
            "note": "",
        },
    }


class AppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / ".offline-vault" / "vault.ovlt"
        self.app = VaultApp(self.path, kdf=FAST, idle_seconds=300, sleeper=lambda _seconds: None)

    def _create(self) -> str:
        result = self.app.create(PASSWORD, PASSWORD)
        token = result.token or ""
        self.assertTrue(token)
        return token

    def test_create_refuses_overwrite_and_hides_plaintext(self) -> None:
        token = self._create()
        with self.assertRaises(VaultError):
            self.app.create(PASSWORD, PASSWORD)
        saved = self.app.save_entry(token, mnemonic_body("Title-9f3c2a7b-unique"), PASSWORD)
        raw = self.path.read_bytes()
        self.assertNotIn(b"Title-9f3c2a7b-unique", raw)
        self.assertNotIn(PHRASE.encode(), raw)
        self.assertNotIn(b"UniquePassphraseZZZ", raw)
        self.assertNotIn(PASSWORD.encode(), raw)
        self.assertNotIn(b"abandon abandon", raw)
        listed = self.app.list_entries(token).data["entries"]
        self.assertEqual(listed[0]["id"], saved.data["entry"]["id"])
        self.assertNotIn("secret", listed[0])
        self.assertNotIn("abandon", json.dumps(listed))
        revealed = self.app.reveal(token, saved.data["entry"]["id"], PASSWORD).data["entry"]
        self.assertEqual(revealed["secret"]["words"], PHRASE)
        self.assertTrue(revealed["secret"]["verified"])
        with self.assertRaises(VaultError):
            self.app.reveal(token, saved.data["entry"]["id"], "wrong-password-xx")

    def test_keep_mnemonic_does_not_replace_words(self) -> None:
        token = self._create()
        saved = self.app.save_entry(token, mnemonic_body(), PASSWORD)
        entry_id = saved.data["entry"]["id"]
        self.app.save_entry(
            token,
            {
                "id": entry_id,
                "kind": "mnemonic",
                "title": "改过标题",
                "secret": {
                    "keep_mnemonic": True,
                    "words": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
                    "words_confirm": "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo",
                    "passphrase": "UniquePassphraseZZZ",
                    "note": "只改备注",
                    "address_hint": "",
                },
            },
            PASSWORD,
        )
        revealed = self.app.reveal(token, entry_id, PASSWORD).data["entry"]
        self.assertEqual(revealed["secret"]["words"], PHRASE)
        self.assertEqual(revealed["secret"]["note"], "只改备注")
        self.assertEqual(revealed["title"], "改过标题")

    def test_card_hint_hides_full_number(self) -> None:
        token = self._create()
        saved = self.app.save_entry(
            token,
            {
                "kind": "card",
                "title": "工资卡",
                "secret": {
                    "bank": "测试银行",
                    "holder": "测试",
                    "number": CARD,
                    "expiry": "12/30",
                    "cvv": "123",
                    "pin": "",
                    "note": "",
                },
            },
            PASSWORD,
        )
        listed = json.dumps(self.app.list_entries(token).data, ensure_ascii=False)
        self.assertNotIn(CARD, listed)
        self.assertIn("4242", listed)
        revealed = self.app.reveal(token, saved.data["entry"]["id"], PASSWORD).data["entry"]
        self.assertTrue(revealed["secret"]["luhn_ok"])
        self.assertNotIn(CARD.encode(), self.path.read_bytes())

    def test_change_password_and_wrong_current_does_not_write(self) -> None:
        token = self._create()
        self.app.save_entry(token, mnemonic_body(), PASSWORD)
        before = self.path.read_bytes()
        with self.assertRaises(VaultError):
            self.app.change_password(token, "wrong-password-xx", NEW_PASSWORD, NEW_PASSWORD)
        self.assertEqual(self.path.read_bytes(), before)
        changed = self.app.change_password(token, PASSWORD, NEW_PASSWORD, NEW_PASSWORD)
        self.app.lock()
        with self.assertRaises(VaultError):
            self.app.unlock(PASSWORD)
        reopened = VaultApp(self.path, sleeper=lambda _seconds: None).unlock(NEW_PASSWORD)
        words = VaultApp(self.path, sleeper=lambda _seconds: None)
        token2 = words.unlock(NEW_PASSWORD).token
        revealed = words.reveal(token2, words.list_entries(token2).data["entries"][0]["id"], NEW_PASSWORD)
        self.assertEqual(revealed.data["entry"]["secret"]["words"], PHRASE)
        self.assertTrue(changed.token)

    def test_tamper_does_not_overwrite_and_salt_repair_keeps_password(self) -> None:
        token = self._create()
        self.app.save_entry(token, mnemonic_body(), PASSWORD)
        header, nonce, ciphertext = load_file(self.path)
        flipped = bytearray(ciphertext)
        flipped[-1] ^= 1
        self.path.write_bytes(dump(header, nonce, bytes(flipped)))
        before = self.path.read_bytes()
        with self.assertRaises(VaultError) as caught:
            self.app.list_entries(token)
        self.assertEqual(caught.exception.code, "locked")
        self.assertEqual(self.path.read_bytes(), before)
        self.assertIsNone(self.app.session.key)

        self.path.write_bytes(dump(header, nonce, ciphertext))
        token = self.app.unlock(PASSWORD).token
        original_salt = self.app.session.header.kdf.salt
        obj = json.loads(self.path.read_text(encoding="utf-8"))
        obj["kdf"]["salt"] = base64.b64encode(b"0123456789abcdef").decode("ascii")
        self.path.write_text(json.dumps(obj), encoding="utf-8")
        self.app.list_entries(token)
        repaired, _, _ = load_file(self.path)
        self.assertEqual(repaired.kdf.salt, original_salt)
        fresh = VaultApp(self.path, sleeper=lambda _seconds: None)
        fresh.unlock(PASSWORD)

    def test_too_many_bad_reveals_lock(self) -> None:
        token = self._create()
        entry_id = self.app.save_entry(token, mnemonic_body(), PASSWORD).data["entry"]["id"]
        last = None
        for _ in range(8):
            try:
                self.app.reveal(token, entry_id, "wrong-password-xx")
            except VaultError as exc:
                last = exc
        self.assertIsNotNone(last)
        assert last is not None
        self.assertEqual(last.code, "locked")
        self.assertIsNone(self.app.session.key)

    def test_idle_lock(self) -> None:
        token = self._create()
        self.app.session.last_active = time.monotonic() - 301
        with self.assertRaises(VaultError) as caught:
            self.app.list_entries(token)
        self.assertEqual(caught.exception.code, "locked")

    def test_symlink_and_huge_kdf_are_refused(self) -> None:
        self._create()
        link = Path(self.tmp.name) / "link.ovlt"
        link.symlink_to(self.path)
        linked = VaultApp(link, sleeper=lambda _seconds: None)
        with self.assertRaises(VaultError):
            linked.unlock(PASSWORD)
        obj = json.loads(self.path.read_text(encoding="utf-8"))
        obj["kdf"]["memory_cost"] = 999999999
        self.path.write_text(json.dumps(obj), encoding="utf-8")
        with self.assertRaises(VaultError) as caught:
            VaultApp(self.path, sleeper=lambda _seconds: None).unlock(PASSWORD)
        self.assertNotIn("派生", caught.exception.message)

    def test_exclusive_lock_and_passphrase_normalization(self) -> None:
        with exclusive(self.path):
            with self.assertRaises(VaultError):
                with exclusive(self.path):
                    pass
        left = entry_from_user(
            {
                "kind": "mnemonic",
                "title": "甲",
                "secret": {
                    "words": PHRASE,
                    "words_confirm": PHRASE,
                    "passphrase": "e\u0301",
                    "note": "",
                    "address_hint": "",
                },
            },
            previous=None,
        )
        right = entry_from_user(
            {
                "kind": "mnemonic",
                "title": "乙",
                "secret": {
                    "words": PHRASE,
                    "words_confirm": PHRASE,
                    "passphrase": "\u00e9",
                    "note": "",
                    "address_hint": "",
                },
            },
            previous=None,
        )
        self.assertEqual(left["secret"]["passphrase"], unicodedata.normalize("NFKD", "\u00e9"))
        self.assertEqual(left["secret"]["passphrase"], right["secret"]["passphrase"])

    def test_mismatched_mnemonic_is_rejected(self) -> None:
        with self.assertRaises(VaultError):
            entry_from_user(
                {
                    "kind": "mnemonic",
                    "title": "甲",
                    "secret": {"words": PHRASE, "words_confirm": PHRASE + " extra", "passphrase": ""},
                },
                previous=None,
            )


def dump(header, nonce: bytes, ciphertext: bytes) -> bytes:
    from vaultkit.crypto import dump_file

    return dump_file(header, nonce, ciphertext)


if __name__ == "__main__":
    unittest.main()
