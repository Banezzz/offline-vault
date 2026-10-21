"""保险库会话。

解锁后内存里只留派生密钥，用来列出标题。
查看、修改、删除都要再验一次主密码。空闲后密钥会被清掉。
"""

from __future__ import annotations

import fcntl
import os
import secrets
import threading
import time
import unicodedata
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from vaultkit.bip39 import WordlistError, check_mnemonic, load_wordlist
from vaultkit.crypto import (
    KEY_LEN,
    VERSION,
    Header,
    KdfParams,
    VaultError,
    atomic_write,
    decrypt_payload,
    derive_key,
    dump_file,
    encrypt_payload,
    failure_delay,
    file_fingerprint,
    load_file,
    location_warning,
    passwords_match,
    prepare_parent,
    same_bytes,
    validate_new_password,
    wipe,
)
from vaultkit.entries import MAX_ENTRIES, empty_payload, entry_from_user, parse_payload_entries, public_view


@dataclass
class Result:
    data: dict
    token: str | None = None
    clear_token: bool = False


class Session:
    def __init__(self, idle_seconds: int) -> None:
        self.idle_seconds = idle_seconds
        self.token: str | None = None
        self.key: bytearray | None = None
        self.header: Header | None = None
        self.last_active = 0.0

    def open(self, key: bytes, header: Header) -> str:
        self.lock()
        self.key = bytearray(key)
        self.header = header
        self.token = secrets.token_urlsafe(32)
        self.touch()
        return self.token

    def lock(self) -> None:
        wipe(self.key)
        self.key = None
        self.header = None
        self.token = None
        self.last_active = 0.0

    def touch(self) -> None:
        self.last_active = time.monotonic()

    def active(self) -> bool:
        if self.key is None or self.token is None or self.header is None:
            return False
        if time.monotonic() - self.last_active > self.idle_seconds:
            self.lock()
            return False
        return True

    def remaining(self) -> int:
        if self.key is None or self.last_active <= 0:
            return 0
        left = self.idle_seconds - (time.monotonic() - self.last_active)
        return max(0, int(left))


class VaultApp:
    def __init__(
        self,
        path: Path,
        *,
        kdf: KdfParams | None = None,
        sleeper=time.sleep,
        idle_seconds: int = 180,
    ) -> None:
        if not isinstance(idle_seconds, int) or isinstance(idle_seconds, bool):
            raise VaultError("空闲时间无效")
        if not 30 <= idle_seconds <= 900:
            raise VaultError("空闲锁定只能设在 30 秒到 15 分钟之间")
        self.path = Path(path)
        self.kdf_template = kdf
        self.sleeper = sleeper
        self.session = Session(idle_seconds)
        self.failures = 0
        self._lock = threading.Lock()

    def status(self, token: object) -> Result:
        with self._lock:
            unlocked = self.session.active() and self._token_ok(token)
            remaining = 0
            notice = ""
            exists = self.path.is_file() and not self.path.is_symlink()
            if unlocked and not exists:
                self.session.lock()
                unlocked = False
                notice = "保险库文件不见了，已锁定。"
            elif unlocked:
                remaining = self.session.remaining()
            return Result(
                data={
                    "vault_exists": exists,
                    "unlocked": unlocked,
                    "idle_seconds": self.session.idle_seconds,
                    "idle_remaining": remaining,
                    "path": str(self.path),
                    "fingerprint": file_fingerprint(self.path) if exists else "",
                    "location_warning": location_warning(self.path),
                    "notice": notice,
                }
            )

    def suggest_password(self) -> Result:
        words = load_wordlist()
        picked = [secrets.choice(words) for _ in range(8)]
        return Result(data={"password": " ".join(picked)})

    def mnemonic_check(self, token: object, words: object) -> Result:
        """输入时的实时校验：只读，不落盘，不验主密码，也不计入失败次数。"""
        with self._lock:
            self._auth(token, touch=True)
            if not isinstance(words, str):
                raise VaultError("助记词必须是文本")
            if len(words) > 10_000:
                raise VaultError("助记词过长")
            text = unicodedata.normalize("NFKC", words).replace("\u00a0", " ")
            text = " ".join(text.lower().split())
            if not text:
                return Result(data={"check": {"ok": False, "reason": "empty", "unknown": []}})
            try:
                checked = check_mnemonic(text)
            except WordlistError as exc:
                raise VaultError("英文词表不可用，已停止校验") from exc
            return Result(
                data={"check": {"ok": checked.ok, "reason": checked.reason, "unknown": list(checked.unknown)}}
            )

    def create(self, password: object, confirm: object) -> Result:
        with self._lock:
            if self.path.is_symlink() or self.path.exists():
                raise VaultError("保险库已经存在，不会覆盖。", status=409)
            self._check_pair(password, confirm)
            assert isinstance(password, str)
            validate_new_password(password)
            kdf = self._fresh_kdf()
            key = derive_key(password, kdf)
            header = Header(version=VERSION, vault_id=secrets.token_bytes(16), kdf=kdf)
            try:
                self._write_with_key(header, key, empty_payload())
                token = self.session.open(key, header)
            except Exception:
                wipe(bytearray(key))
                self.session.lock()
                raise
            self.failures = 0
            return Result(data={"created": True}, token=token)

    def unlock(self, password: object) -> Result:
        with self._lock:
            if self.path.is_symlink() or not self.path.is_file():
                raise VaultError("还没有保险库")
            if not isinstance(password, str) or password == "":
                raise VaultError("请输入主密码")
            self._pause_for_failures()
            header, nonce, ciphertext = load_file(self.path)
            try:
                key = derive_key(password, header.kdf)
                payload = decrypt_payload(key, header, nonce, ciphertext)
                payload["entries"] = parse_payload_entries(payload["entries"])
            except VaultError as exc:
                wipe(bytearray(key) if "key" in locals() else None)
                if exc.code == "auth":
                    self._note_unlock_failure()
                raise
            self.failures = 0
            token = self.session.open(key, header)
            return Result(data={"unlocked": True}, token=token)

    def lock(self) -> Result:
        with self._lock:
            self.session.lock()
            self.failures = 0
            return Result(data={"locked": True}, clear_token=True)

    def touch(self, token: object) -> Result:
        with self._lock:
            self._auth(token, touch=True)
            return Result(data={"idle_remaining": self.session.remaining()})

    def set_idle(self, token: object, seconds: object) -> Result:
        with self._lock:
            self._auth(token, touch=False)
            if not isinstance(seconds, int) or isinstance(seconds, bool) or not 30 <= seconds <= 900:
                raise VaultError("空闲锁定只能设在 30 秒到 15 分钟之间")
            self.session.idle_seconds = seconds
            self.session.touch()
            return Result(data={"idle_seconds": seconds, "idle_remaining": seconds})

    def list_entries(self, token: object) -> Result:
        with self._lock:
            self._auth(token, touch=True)
            payload = self._decrypt_current()
            views = [public_view(entry) for entry in payload["entries"]]
            views.sort(key=lambda item: item["updated_at"], reverse=True)
            return Result(data={"entries": views})

    def reveal(self, token: object, entry_id: object, password: object) -> Result:
        with self._lock:
            self._auth(token, touch=False)
            self._verify_password(password)
            self.session.touch()
            payload = self._decrypt_current()
            entry = self._find(payload, entry_id)
            return Result(data={"entry": entry})

    def save_entry(self, token: object, body: object, password: object) -> Result:
        with self._lock:
            self._auth(token, touch=False)
            self._verify_password(password)
            self.session.touch()
            if not isinstance(body, dict):
                raise VaultError("条目格式不正确")
            payload = self._decrypt_current()
            previous = None
            entry_id = body.get("id")
            if entry_id not in (None, ""):
                previous = self._find(payload, entry_id)
            elif len(payload["entries"]) >= MAX_ENTRIES:
                raise VaultError("条目太多，已拒绝保存")
            entry = entry_from_user(body, previous=previous)
            if previous is None:
                payload["entries"].append(entry)
            else:
                payload["entries"] = [
                    entry if item["id"] == entry["id"] else item for item in payload["entries"]
                ]
            header = self.session.header
            if header is None:
                raise VaultError("保险库已锁定", code="locked", status=401)
            self._write_unlocked(header, payload)
            return Result(data={"entry": public_view(entry)})

    def delete_entry(self, token: object, entry_id: object, password: object) -> Result:
        with self._lock:
            self._auth(token, touch=False)
            self._verify_password(password)
            self.session.touch()
            payload = self._decrypt_current()
            self._find(payload, entry_id)
            wanted = str(uuid.UUID(str(entry_id)))
            payload["entries"] = [item for item in payload["entries"] if item["id"] != wanted]
            header = self.session.header
            if header is None:
                raise VaultError("保险库已锁定", code="locked", status=401)
            self._write_unlocked(header, payload)
            return Result(data={"deleted": True})

    def change_password(self, token: object, current: object, new: object, confirm: object) -> Result:
        with self._lock:
            self._auth(token, touch=False)
            self._check_pair(new, confirm)
            assert isinstance(new, str)
            validate_new_password(new)
            if not isinstance(current, str):
                raise VaultError("请输入现在的主密码")
            if passwords_match(current, new):
                raise VaultError("新主密码不能和现在的一样")
            self._verify_password(current)
            payload = self._decrypt_current()
            old = self.session.header
            if old is None:
                raise VaultError("保险库已锁定", code="locked", status=401)
            new_kdf = KdfParams(
                time_cost=old.kdf.time_cost,
                memory_cost=old.kdf.memory_cost,
                parallelism=old.kdf.parallelism,
                hash_len=KEY_LEN,
                salt=secrets.token_bytes(16),
            )
            new_key = derive_key(new, new_kdf)
            new_header = Header(version=VERSION, vault_id=old.vault_id, kdf=new_kdf)
            self.session.open(new_key, new_header)
            try:
                self._write_unlocked(new_header, payload)
            except Exception:
                self.session.lock()
                raise
            self.failures = 0
            return Result(data={"changed": True}, token=self.session.token)

    def _fresh_kdf(self) -> KdfParams:
        if self.kdf_template is None:
            return KdfParams.production()
        template = self.kdf_template
        template.check_bounds()
        return KdfParams(
            time_cost=template.time_cost,
            memory_cost=template.memory_cost,
            parallelism=template.parallelism,
            hash_len=KEY_LEN,
            salt=secrets.token_bytes(16),
        )

    def _check_pair(self, password: object, confirm: object) -> None:
        if not isinstance(password, str) or not isinstance(confirm, str):
            raise VaultError("请输入主密码")
        if not passwords_match(password, confirm):
            raise VaultError("两次输入的主密码不一致")

    def _pause_for_failures(self) -> None:
        delay = failure_delay(self.failures)
        if delay:
            self.sleeper(delay)

    def _note_unlock_failure(self) -> None:
        self.failures += 1
        extra = ""
        if self.failures >= 5:
            extra = " 多次错误。慢哈希会拖住穷举，也请核对是不是输错了。"
        raise VaultError("主密码错误，或保险库文件已损坏。" + extra, code="auth", status=401)

    def _verify_password(self, password: object) -> None:
        if not isinstance(password, str) or password == "" or self.session.header is None or self.session.key is None:
            raise VaultError("请输入主密码")
        self._pause_for_failures()
        derived = derive_key(password, self.session.header.kdf)
        if not same_bytes(derived, bytes(self.session.key)):
            self.failures += 1
            if self.failures >= 8:
                self.failures = 0
                self.session.lock()
                raise VaultError("主密码错误次数太多，已锁定。", code="locked", status=401)
            raise VaultError("主密码错误", code="auth", status=401)
        self.failures = 0

    def _auth(self, token: object, *, touch: bool) -> None:
        if not self.session.active() or not self._token_ok(token):
            raise VaultError("保险库已锁定", code="locked", status=401)
        if touch:
            self.session.touch()

    def _token_ok(self, token: object) -> bool:
        current = self.session.token
        if not isinstance(token, str) or not current:
            return False
        return same_bytes(token.encode("utf-8"), current.encode("utf-8"))

    def _decrypt_current(self) -> dict:
        pinned = self.session.header
        key = self.session.key
        if pinned is None or key is None:
            raise VaultError("保险库已锁定", code="locked", status=401)
        file_header, nonce, ciphertext = load_file(self.path)
        try:
            payload = decrypt_payload(key, pinned, nonce, ciphertext)
        except VaultError as exc:
            self.session.lock()
            raise VaultError(
                "保险库文件没有通过校验，会话已锁定。文件没有被改写。如果这是唯一副本，先把文件另存再排查。",
                code="locked",
                status=401,
            ) from exc
        payload["entries"] = parse_payload_entries(payload["entries"])
        if file_header != pinned:
            self._write_unlocked(pinned, payload)
        return payload

    def _write_unlocked(self, header: Header, payload: dict) -> None:
        if self.session.key is None:
            raise VaultError("保险库已锁定", code="locked", status=401)
        self._write_with_key(header, bytes(self.session.key), payload)

    def _write_with_key(self, header: Header, key: bytes, payload: dict) -> None:
        body = {"version": VERSION, "entries": payload["entries"]}
        nonce, ciphertext = encrypt_payload(key, header, body)
        atomic_write(self.path, dump_file(header, nonce, ciphertext))

    def _find(self, payload: dict, entry_id: object) -> dict:
        if not isinstance(entry_id, str):
            raise VaultError("找不到这条记录", status=404)
        try:
            wanted = str(uuid.UUID(entry_id))
        except ValueError as exc:
            raise VaultError("找不到这条记录", status=404) from exc
        for item in payload["entries"]:
            if item["id"] == wanted:
                return item
        raise VaultError("找不到这条记录", status=404)


@contextmanager
def exclusive(path: Path):
    prepare_parent(path)
    lock_path = path.with_name(path.name + ".lock")
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        os.fchmod(fd, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise VaultError("保险库正被另一个本机进程使用。请先关掉正在运行的窗口或命令。") from exc
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)
