from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from vaultkit.crypto import (
    PRODUCTION_MEMORY_KIB,
    PRODUCTION_PARALLELISM,
    PRODUCTION_TIME_COST,
    Header,
    KdfParams,
    VaultError,
    atomic_write,
    decrypt_payload,
    derive_key,
    dump_file,
    encrypt_payload,
    failure_delay,
    load_file,
    validate_new_password,
)

FAST = KdfParams(time_cost=1, memory_cost=1024, parallelism=1, hash_len=32, salt=b"\x11" * 16)


class CryptoTests(unittest.TestCase):
    def test_production_parameters_are_slow_enough(self) -> None:
        params = KdfParams.production()
        self.assertGreaterEqual(params.memory_cost, 262144)
        self.assertGreaterEqual(params.time_cost, 8)
        self.assertEqual(params.parallelism, 1)
        self.assertEqual(PRODUCTION_MEMORY_KIB, 262144)
        self.assertEqual(PRODUCTION_TIME_COST, 8)
        self.assertEqual(PRODUCTION_PARALLELISM, 1)
        self.assertEqual(len(params.salt), 16)

    def test_roundtrip_and_wrong_password_and_tamper(self) -> None:
        header = Header(version=1, vault_id=b"vault-id-16bytes", kdf=FAST)
        key = derive_key("test-password-ok", FAST)
        payload = {"version": 1, "entries": [{"id": "x"}]}
        nonce, ciphertext = encrypt_payload(key, header, payload)
        self.assertEqual(decrypt_payload(key, header, nonce, ciphertext)["entries"][0]["id"], "x")
        with self.assertRaises(VaultError):
            decrypt_payload(derive_key("other-password-ok", FAST), header, nonce, ciphertext)
        flipped = bytearray(ciphertext)
        flipped[-1] ^= 1
        with self.assertRaises(VaultError):
            decrypt_payload(key, header, nonce, bytes(flipped))

    def test_master_password_is_exact_bytes(self) -> None:
        composed = derive_key("caf\u00e9-password", FAST)
        decomposed = derive_key("cafe\u0301-password", FAST)
        self.assertNotEqual(composed, decomposed)
        self.assertNotEqual("caf\u00e9-password", "cafe\u0301-password")

    def test_password_policy_only_applies_to_new_passwords(self) -> None:
        with self.assertRaises(VaultError):
            validate_new_password("short-pass")
        with self.assertRaises(VaultError):
            validate_new_password("passwordpassword")
        derive_key("short-pass", FAST)

    def test_failure_delay_grows_then_caps(self) -> None:
        self.assertEqual(failure_delay(1), 0)
        self.assertEqual(failure_delay(3), 0)
        self.assertEqual(failure_delay(4), 2)
        self.assertEqual(failure_delay(20), 8)

    def test_rejects_absurd_kdf_before_hashing(self) -> None:
        bad = KdfParams(time_cost=1, memory_cost=99999999, parallelism=1, hash_len=32, salt=b"\x11" * 16)
        with self.assertRaises(VaultError):
            bad.check_bounds()

    def test_atomic_write_permissions_and_roundtrip_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".offline-vault" / "vault.ovlt"
            header = Header(version=1, vault_id=b"vault-id-16bytes", kdf=FAST)
            nonce, ciphertext = encrypt_payload(derive_key("test-password-ok", FAST), header, {"version": 1, "entries": []})
            atomic_write(path, dump_file(header, nonce, ciphertext))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            loaded, loaded_nonce, loaded_ct = load_file(path)
            self.assertEqual(loaded, header)
            self.assertEqual(loaded_nonce, nonce)
            self.assertEqual(loaded_ct, ciphertext)
            self.assertEqual(list(path.parent.glob(".tmp-*")), [])
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["kdf"]["name"] = "argon2i"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(VaultError):
                load_file(path)


if __name__ == "__main__":
    unittest.main()
