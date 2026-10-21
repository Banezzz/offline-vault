"""只绑定本机回环地址的页面。不提供局域网访问，也不加载外部资源。"""

from __future__ import annotations

import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from vaultkit.app import Result, VaultApp, exclusive
from vaultkit.crypto import VaultError, file_fingerprint

FRONTEND = Path(__file__).with_name("frontend")
ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}
COOKIE = "ov_session"
MAX_BODY = 256_000

_SECURITY_HEADERS = (
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    (
        "Content-Security-Policy",
        "default-src 'none'; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    ),
)


def make_handler(app: VaultApp):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "offline-vault"
        sys_version = ""

        def do_GET(self) -> None:
            if not self._host_ok():
                self._send(403, b"forbidden", "text/plain; charset=utf-8")
                return
            asset = ASSETS.get(self.path.split("?", 1)[0])
            if asset is None:
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            name, content_type = asset
            file_path = FRONTEND / name
            if file_path.is_symlink() or not file_path.is_file():
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            self._send(200, file_path.read_bytes(), content_type)

        def do_POST(self) -> None:
            try:
                if not self._host_ok() or not self._origin_ok():
                    self._send(403, b"forbidden", "text/plain; charset=utf-8")
                    return
                if self.headers.get("X-Offline-Vault") != "1":
                    self._send(403, self._error_body("拒绝跨站请求", "forbidden"), "application/json; charset=utf-8")
                    return
                content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    raise VaultError("请求格式不正确")
                body = self._read_json()
                token = self._cookie_token()
                result = self._dispatch(token, body)
                payload = {"ok": True}
                payload.update(result.data)
                self._send(
                    200,
                    json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                    "application/json; charset=utf-8",
                    set_cookie=self._cookie(result.token) if result.token else None,
                    clear_cookie=result.clear_token,
                )
            except VaultError as exc:
                self._send(
                    exc.status,
                    self._error_body(exc.message, exc.code, locked=exc.code == "locked"),
                    "application/json; charset=utf-8",
                )
            except Exception as exc:
                sys.stderr.write("[offline-vault] internal %s\n" % type(exc).__name__)
                self._send(500, self._error_body("内部错误", "error"), "application/json; charset=utf-8")

        def do_OPTIONS(self) -> None:
            self._send(403, b"forbidden", "text/plain; charset=utf-8")

        def log_message(self, fmt: str, *args) -> None:
            try:
                line = str(args[0])
            except Exception:
                return
            if "/api/status" in line or "/api/touch" in line:
                return
            sys.stderr.write("[offline-vault] " + (fmt % args) + "\n")

        def _dispatch(self, token: str, body: dict) -> Result:
            path = self.path.split("?", 1)[0]
            if path == "/api/status":
                return app.status(token)
            if path == "/api/suggest-password":
                return app.suggest_password()
            if path == "/api/create":
                return app.create(body.get("password"), body.get("confirm"))
            if path == "/api/unlock":
                return app.unlock(body.get("password"))
            if path == "/api/lock":
                return app.lock()
            if path == "/api/touch":
                return app.touch(token)
            if path == "/api/idle":
                return app.set_idle(token, body.get("seconds"))
            if path == "/api/entries/list":
                return app.list_entries(token)
            if path == "/api/entries/check-mnemonic":
                return app.mnemonic_check(token, body.get("words"))
            if path == "/api/entries/reveal":
                return app.reveal(token, body.get("id"), body.get("password"))
            if path == "/api/entries/save":
                return app.save_entry(token, body, body.get("password"))
            if path == "/api/entries/delete":
                return app.delete_entry(token, body.get("id"), body.get("password"))
            if path == "/api/change-password":
                return app.change_password(
                    token,
                    body.get("current"),
                    body.get("password"),
                    body.get("confirm"),
                )
            raise VaultError("没有这个功能", status=404)

        def _host_ok(self) -> bool:
            port = self.server.server_address[1]
            allowed = {"127.0.0.1:%s" % port, "localhost:%s" % port, "[::1]:%s" % port}
            return self.headers.get("Host", "") in allowed

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            if origin is None:
                return True
            port = self.server.server_address[1]
            allowed = {
                "http://127.0.0.1:%s" % port,
                "http://localhost:%s" % port,
                "http://[::1]:%s" % port,
            }
            return origin in allowed

        def _read_json(self) -> dict:
            if self.headers.get("Transfer-Encoding"):
                raise VaultError("请求格式不正确")
            length = self.headers.get("Content-Length")
            if length is None:
                raise VaultError("请求不完整")
            try:
                size = int(length)
            except ValueError as exc:
                raise VaultError("请求不完整") from exc
            if size < 0 or size > MAX_BODY:
                raise VaultError("请求过大", status=413)
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise VaultError("请求不完整")
            try:
                data = json.loads(raw.decode("utf-8"))
            except Exception as exc:
                raise VaultError("请求格式不正确") from exc
            if not isinstance(data, dict):
                raise VaultError("请求格式不正确")
            return data

        def _cookie_token(self) -> str:
            for part in self.headers.get("Cookie", "").split(";"):
                part = part.strip()
                if not part.startswith(COOKIE + "="):
                    continue
                value = part.split("=", 1)[1].strip()
                if 0 < len(value) <= 128:
                    return value
            return ""

        def _cookie(self, token: str) -> str:
            return "%s=%s; HttpOnly; SameSite=Strict; Path=/" % (COOKIE, token)

        def _error_body(self, message: str, code: str, locked: bool = False) -> bytes:
            return json.dumps(
                {"ok": False, "error": message, "code": code, "locked": locked},
                ensure_ascii=False,
            ).encode("utf-8")

        def _send(
            self,
            status: int,
            body: bytes,
            content_type: str,
            set_cookie: str | None = None,
            clear_cookie: bool = False,
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            for key, value in _SECURITY_HEADERS:
                self.send_header(key, value)
            if set_cookie:
                self.send_header("Set-Cookie", set_cookie)
            if clear_cookie:
                self.send_header(
                    "Set-Cookie",
                    "%s=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" % COOKIE,
                )
            self.end_headers()
            self.wfile.write(body)

    return Handler


def make_server(app: VaultApp, host: str, port: int) -> ThreadingHTTPServer:
    family = socket.AF_INET6 if host == "::1" else socket.AF_INET

    class Server(ThreadingHTTPServer):
        address_family = family
        allow_reuse_address = False
        daemon_threads = True

        def server_bind(self) -> None:
            if family == socket.AF_INET6:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

        def handle_error(self, request, client_address) -> None:
            sys.stderr.write("[offline-vault] connection error\n")

    return Server((host, port), make_handler(app))


def serve(path: Path, port: int, idle_seconds: int) -> None:
    app = VaultApp(path, idle_seconds=idle_seconds)
    with exclusive(path):
        try:
            v4 = make_server(app, "127.0.0.1", port)
        except OSError as exc:
            raise VaultError("打不开 127.0.0.1:%s。换一个端口，或关掉占用它的程序。" % port) from exc
        bound = v4.server_address[1]
        v6 = None
        try:
            v6 = make_server(app, "::1", bound)
        except OSError:
            v6 = None
        if v6 is not None:
            threading.Thread(target=v6.serve_forever, name="offline-vault-v6", daemon=True).start()
        print("离线保险库只监听本机，不监听局域网。")
        print("在浏览器打开  http://127.0.0.1:%s/" % bound)
        if v6 is None:
            print("不要用 localhost 打开：它在这台机器上可能指向 IPv6，而 IPv6 监听没有成功。")
        print("保险库文件    %s" % path)
        fingerprint = file_fingerprint(path)
        if fingerprint:
            print("文件校验      %s" % fingerprint)
        print("空闲 %s 秒后锁定。按 Ctrl+C 会清掉内存里的密钥并退出。" % idle_seconds)
        try:
            v4.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            app.session.lock()
            if v6 is not None:
                v6.shutdown()
                v6.server_close()
            v4.server_close()
            print("\n已锁定并退出。")
