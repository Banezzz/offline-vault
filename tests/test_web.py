from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from vaultkit.app import VaultApp
from vaultkit.cli import run_self_check
from vaultkit.crypto import KdfParams
from vaultkit.web import make_server

FAST = KdfParams(time_cost=1, memory_cost=1024, parallelism=1, hash_len=32, salt=b"\x33" * 16)
PASSWORD = "test-password-ok"
PHRASE = " ".join(["abandon"] * 11 + ["about"])


class WebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vault.ovlt"
        self.app = VaultApp(self.path, kdf=FAST, idle_seconds=300, sleeper=lambda _seconds: None)
        self.httpd = make_server(self.app, "127.0.0.1", 0)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = ""

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def request(self, method: str, path: str, payload: dict | None = None, *, header: bool = True, origin: str | None = None, host: str | None = None, cookie: bool = True) -> tuple[int, bytes, str]:
        raw = b"" if payload is None else json.dumps(payload).encode("utf-8")
        headers = {}
        if payload is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(raw))
        if header and method == "POST":
            headers["X-Offline-Vault"] = "1"
        if origin:
            headers["Origin"] = origin
        if host:
            headers["Host"] = host
        if cookie and self.cookie:
            headers["Cookie"] = self.cookie
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=raw, headers=headers)
        response = conn.getresponse()
        body = response.read()
        set_cookie = response.getheader("Set-Cookie") or ""
        status = response.status
        conn.close()
        if "ov_session=" in set_cookie and "Max-Age=0" not in set_cookie:
            self.cookie = set_cookie.split(";", 1)[0]
        if "Max-Age=0" in set_cookie:
            self.cookie = ""
        return status, body, set_cookie

    def post(self, path: str, payload: dict, **kwargs) -> tuple[int, dict, str]:
        status, body, cookie = self.request("POST", path, payload, **kwargs)
        return status, json.loads(body.decode("utf-8")), cookie

    def test_page_is_local_and_session_cookie_is_httponly(self) -> None:
        status, body, _ = self.request("GET", "/", payload=None, header=False)
        text = body.decode("utf-8")
        self.assertEqual(status, 200)
        self.assertIn("离线保险库", text)
        self.assertNotIn("https://", text)
        self.assertNotIn("http://", text)
        self.assertNotIn("unsafe-inline", text)
        self.assertIn("connect-src 'self'", text)
        self.assertIn('src="/app.js"', text)
        for path in ("/app.css", "/app.js"):
            status, asset, _ = self.request("GET", path, payload=None, header=False)
            self.assertEqual(status, 200, path)
            self.assertNotIn(b"https://", asset)
            self.assertNotIn(b"http://", asset)
        status, missing, _ = self.request("GET", "/app.js/../../vaultkit/crypto.py", payload=None, header=False)
        self.assertEqual(status, 404)
        self.assertNotIn(b"argon2", missing)
        status, page, _ = self.request("GET", "/", payload=None, header=False, host="evil.example")
        self.assertEqual(status, 403)
        self.assertNotIn(b"abandon", page)

    def test_flow_keeps_secrets_off_the_list_and_requires_password(self) -> None:
        status, created, cookie = self.post("/api/create", {"password": PASSWORD, "confirm": PASSWORD})
        self.assertEqual(status, 200)
        self.assertTrue(created["ok"])
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        token = self.cookie.split("=", 1)[1]
        self.assertNotIn(token, json.dumps(created))
        status, saved, _ = self.post(
            "/api/entries/save",
            {
                "kind": "mnemonic",
                "title": "Title-9f3c2a7b-unique",
                "password": PASSWORD,
                "secret": {
                    "words": PHRASE,
                    "words_confirm": PHRASE,
                    "passphrase": "UniquePassphraseZZZ",
                    "note": "",
                    "address_hint": "",
                },
            },
        )
        self.assertEqual(status, 200, saved)
        raw = self.path.read_bytes()
        self.assertNotIn(PHRASE.encode(), raw)
        self.assertNotIn(PASSWORD.encode(), raw)
        self.assertNotIn(b"UniquePassphraseZZZ", raw)
        self.assertNotIn(b"Title-9f3c2a7b-unique", raw)
        status, listed, _ = self.post("/api/entries/list", {})
        self.assertEqual(status, 200)
        dumped = json.dumps(listed, ensure_ascii=False)
        self.assertNotIn(PHRASE, dumped)
        self.assertNotIn("secret", listed["entries"][0])
        entry_id = saved["entry"]["id"]
        status, wrong, _ = self.post("/api/entries/reveal", {"id": entry_id, "password": "wrong-password-xx"})
        self.assertEqual(status, 401)
        self.assertNotIn(PHRASE, json.dumps(wrong))
        status, right, _ = self.post("/api/entries/reveal", {"id": entry_id, "password": PASSWORD})
        self.assertEqual(status, 200)
        self.assertEqual(right["entry"]["secret"]["words"], PHRASE)
        status, blocked, _ = self.post("/api/entries/reveal", {"id": entry_id, "password": PASSWORD}, header=False)
        self.assertEqual(status, 403)
        self.assertNotIn(PHRASE, json.dumps(blocked))
        status, foreign, _ = self.request(
            "POST",
            "/api/entries/reveal",
            {"id": entry_id, "password": PASSWORD},
            origin="https://evil.example",
        )
        self.assertEqual(status, 403)
        self.assertNotIn(PHRASE.encode(), foreign)
        self.post("/api/lock", {})
        self.assertEqual(self.cookie, "")
        status, locked, _ = self.post("/api/entries/list", {})
        self.assertEqual(status, 401)
        self.assertTrue(locked["locked"])

    def test_self_check_without_production_kdf(self) -> None:
        self.assertIn("自检通过", run_self_check(skip_kdf=True))

    def test_check_mnemonic_is_readonly_and_requires_unlock(self) -> None:
        self.post("/api/create", {"password": PASSWORD, "confirm": PASSWORD})
        before = self.path.read_bytes()
        status, good, _ = self.post("/api/entries/check-mnemonic", {"words": PHRASE})
        self.assertEqual(status, 200)
        self.assertTrue(good["check"]["ok"])
        self.assertEqual(good["check"]["reason"], "ok")
        status, checksum, _ = self.post("/api/entries/check-mnemonic", {"words": " ".join(["abandon"] * 12)})
        self.assertEqual(status, 200)
        self.assertFalse(checksum["check"]["ok"])
        self.assertEqual(checksum["check"]["reason"], "checksum")
        status, unknown, _ = self.post(
            "/api/entries/check-mnemonic", {"words": " ".join(["abandon"] * 11 + ["abanddn"])}
        )
        self.assertEqual(status, 200)
        self.assertEqual(unknown["check"]["reason"], "unknown")
        self.assertIn("abanddn", unknown["check"]["unknown"])
        status, count, _ = self.post("/api/entries/check-mnemonic", {"words": "abandon abandon"})
        self.assertEqual(status, 200)
        self.assertEqual(count["check"]["reason"], "count")
        status, empty, _ = self.post("/api/entries/check-mnemonic", {"words": "   "})
        self.assertEqual(status, 200)
        self.assertEqual(empty["check"]["reason"], "empty")
        status, bad, _ = self.post("/api/entries/check-mnemonic", {"words": 12})
        self.assertEqual(status, 400)
        self.assertFalse(bad["ok"])
        self.assertEqual(self.path.read_bytes(), before)
        self.post("/api/lock", {})
        status, locked, _ = self.post("/api/entries/check-mnemonic", {"words": PHRASE})
        self.assertEqual(status, 401)
        self.assertTrue(locked["locked"])


if __name__ == "__main__":
    unittest.main()
