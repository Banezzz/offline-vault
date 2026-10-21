"""加密与保险库文件格式。

磁盘上只有盐、KDF 参数和 AES-256-GCM 密文。主密码不保存。
每次写入都使用新的 nonce。关联数据绑住 vault_id，避免把别的密文换进来。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path

from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = "OVLT1"
VERSION = 1
MAX_FILE_BYTES = 1_000_000
MAX_PLAINTEXT_BYTES = 700_000
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
VAULT_ID_LEN = 16

# 256 MiB × 8 次。这台机器上大约一秒，并且每次猜测都要占这么多内存。
PRODUCTION_TIME_COST = 8
PRODUCTION_MEMORY_KIB = 262144
PRODUCTION_PARALLELISM = 1

# 上限就停在正式参数上：改文件不能让解锁比正常打开更贵。
MAX_TIME_COST = PRODUCTION_TIME_COST
MAX_MEMORY_KIB = PRODUCTION_MEMORY_KIB
MAX_PARALLELISM = 4

MIN_PASSWORD_CHARS = 12
MAX_PASSWORD_BYTES = 1024

COMMON_PASSWORDS = frozenset(
    {
        "passwordpassword",
        "password123456",
        "123456789012",
        "1234567890123",
        "12345678901234",
        "qwertyuiopas",
        "qwertyuiopasd",
        "qwertyuiopasdf",
        "iloveyouilove",
        "iloveyouiloveyou",
        "adminadminadmin",
        "changemeplease",
        "letmeinletmein",
    }
)


class VaultError(Exception):
    def __init__(self, message: str, *, code: str = "error", status: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


def wipe(buf: bytearray | None) -> None:
    if not buf:
        return
    for index in range(len(buf)):
        buf[index] = 0


def same_bytes(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(value: object, expected_len: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) > 2_000_000:
        raise VaultError("保险库文件损坏")
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise VaultError("保险库文件损坏") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise VaultError("保险库文件损坏")
    return raw


def failure_delay(failures: int) -> float:
    if failures < 4:
        return 0.0
    return float(min(8, failures - 2))


@dataclass(frozen=True)
class KdfParams:
    time_cost: int
    memory_cost: int
    parallelism: int
    hash_len: int
    salt: bytes

    @staticmethod
    def production(salt: bytes | None = None) -> KdfParams:
        return KdfParams(
            time_cost=PRODUCTION_TIME_COST,
            memory_cost=PRODUCTION_MEMORY_KIB,
            parallelism=PRODUCTION_PARALLELISM,
            hash_len=KEY_LEN,
            salt=salt if salt is not None else secrets.token_bytes(SALT_LEN),
        )

    def check_bounds(self) -> None:
        if self.hash_len != KEY_LEN or len(self.salt) != SALT_LEN:
            raise VaultError("保险库文件损坏")
        if not _in_range(self.time_cost, MAX_TIME_COST):
            raise VaultError("保险库的密钥参数异常，已拒绝打开")
        if not _in_range(self.memory_cost, MAX_MEMORY_KIB):
            raise VaultError("保险库的密钥参数异常，已拒绝打开")
        if not _in_range(self.parallelism, MAX_PARALLELISM):
            raise VaultError("保险库的密钥参数异常，已拒绝打开")
        if self.memory_cost < 8 * self.parallelism:
            raise VaultError("保险库的密钥参数异常，已拒绝打开")


@dataclass(frozen=True)
class Header:
    version: int
    vault_id: bytes
    kdf: KdfParams


def _in_range(value: object, upper: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= upper


def _expect_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise VaultError("保险库文件损坏")
    return value


def aad_for(vault_id: bytes) -> bytes:
    return b"OVLT1\x00" + vault_id


def password_bytes(password: str) -> bytes:
    """派生密钥时用。不在这里检查强度，否则旧密码或解锁错误提示会泄露策略。"""
    if not isinstance(password, str) or password == "":
        raise VaultError("请输入主密码")
    if "\x00" in password:
        raise VaultError("主密码不能包含空字符")
    try:
        raw = password.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise VaultError("主密码编码无效") from exc
    if len(raw) > MAX_PASSWORD_BYTES:
        raise VaultError("主密码过长")
    return raw


def validate_new_password(password: str) -> None:
    password_bytes(password)
    if password.strip() == "":
        raise VaultError("主密码不能是空白")
    if len(password) < MIN_PASSWORD_CHARS:
        raise VaultError(
            f"主密码至少 {MIN_PASSWORD_CHARS} 个字符。保管助记词时，建议用 8 个互不相关的随机词。"
        )
    if len(set(password)) == 1:
        raise VaultError("主密码太单一")
    folded = password.casefold().strip()
    if folded in COMMON_PASSWORDS:
        raise VaultError("这个主密码太常见，请换一个。")
    if password.isdigit() and len(password) < 16:
        raise VaultError("不要只用较短的纯数字做主密码。")


def passwords_match(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        left_bytes = left.encode("utf-8", "strict")
        right_bytes = right.encode("utf-8", "strict")
    except UnicodeError:
        return False
    return same_bytes(left_bytes, right_bytes)


def derive_key(password: str, kdf: KdfParams) -> bytes:
    kdf.check_bounds()
    raw = password_bytes(password)
    try:
        return hash_secret_raw(
            secret=raw,
            salt=bytes(kdf.salt),
            time_cost=kdf.time_cost,
            memory_cost=kdf.memory_cost,
            parallelism=kdf.parallelism,
            hash_len=kdf.hash_len,
            type=Type.ID,
            version=ARGON2_VERSION,
        )
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError("无法派生密钥") from exc


def encrypt_payload(key: bytes, header: Header, payload: dict) -> tuple[bytes, bytes]:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(raw) > MAX_PLAINTEXT_BYTES:
        raise VaultError("内容过多，已拒绝保存")
    nonce = secrets.token_bytes(NONCE_LEN)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, raw, aad_for(header.vault_id))
    return nonce, ciphertext


def decrypt_payload(key: bytes, header: Header, nonce: bytes, ciphertext: bytes) -> dict:
    if len(nonce) != NONCE_LEN or len(ciphertext) < 17 or len(ciphertext) > MAX_FILE_BYTES:
        raise VaultError("主密码错误，或保险库文件已损坏", code="auth", status=401)
    try:
        raw = AESGCM(bytes(key)).decrypt(bytes(nonce), bytes(ciphertext), aad_for(header.vault_id))
    except Exception as exc:
        raise VaultError("主密码错误，或保险库文件已损坏", code="auth", status=401) from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise VaultError("主密码错误，或保险库文件已损坏", code="auth", status=401) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("version") != VERSION
        or not isinstance(payload.get("entries"), list)
    ):
        raise VaultError("保险库内容无法识别")
    return payload


def dump_file(header: Header, nonce: bytes, ciphertext: bytes) -> bytes:
    if header.version != VERSION or len(header.vault_id) != VAULT_ID_LEN:
        raise VaultError("保险库文件损坏")
    header.kdf.check_bounds()
    if len(nonce) != NONCE_LEN or len(ciphertext) < 17:
        raise VaultError("保险库文件损坏")
    body = {
        "ciphertext": b64e(ciphertext),
        "kdf": {
            "hash_len": header.kdf.hash_len,
            "memory_cost": header.kdf.memory_cost,
            "name": "argon2id",
            "parallelism": header.kdf.parallelism,
            "salt": b64e(bytes(header.kdf.salt)),
            "time_cost": header.kdf.time_cost,
        },
        "magic": MAGIC,
        "nonce": b64e(nonce),
        "vault_id": b64e(header.vault_id),
        "version": VERSION,
    }
    return (
        json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        + b"\n"
    )


def load_file(path: Path) -> tuple[Header, bytes, bytes]:
    if path.is_symlink():
        raise VaultError("保险库路径不能是符号链接")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise VaultError("找不到保险库文件") from exc
    if size <= 0 or size > MAX_FILE_BYTES:
        raise VaultError("保险库文件大小异常，已拒绝打开")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise VaultError("无法读取保险库文件") from exc
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise VaultError("保险库文件损坏") from exc
    if not isinstance(obj, dict) or obj.get("magic") != MAGIC or obj.get("version") != VERSION:
        raise VaultError("无法识别的保险库文件")
    kdf_obj = obj.get("kdf")
    if not isinstance(kdf_obj, dict) or kdf_obj.get("name") != "argon2id":
        raise VaultError("保险库使用了不支持的密钥算法，已拒绝打开")
    try:
        kdf = KdfParams(
            time_cost=_expect_int(kdf_obj.get("time_cost")),
            memory_cost=_expect_int(kdf_obj.get("memory_cost")),
            parallelism=_expect_int(kdf_obj.get("parallelism")),
            hash_len=_expect_int(kdf_obj.get("hash_len")),
            salt=b64d(kdf_obj.get("salt"), SALT_LEN),
        )
        kdf.check_bounds()
        header = Header(version=VERSION, vault_id=b64d(obj.get("vault_id"), VAULT_ID_LEN), kdf=kdf)
        nonce = b64d(obj.get("nonce"), NONCE_LEN)
        ciphertext = b64d(obj.get("ciphertext"))
    except VaultError:
        raise
    except Exception as exc:
        raise VaultError("保险库文件损坏") from exc
    if len(ciphertext) < 17:
        raise VaultError("保险库文件损坏")
    return header, nonce, ciphertext


def prepare_parent(path: Path) -> None:
    parent = path.parent
    created = not parent.exists()
    parent.mkdir(parents=True, exist_ok=True)
    if created or parent.name == ".offline-vault":
        os.chmod(parent, 0o700)


def atomic_write(path: Path, data: bytes) -> None:
    if path.is_symlink():
        raise VaultError("保险库路径不能是符号链接")
    prepare_parent(path)
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".ovlt")
    tmp_path = Path(tmp_name)
    owned = True
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            owned = False
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        if owned:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise
    os.chmod(path, 0o600)
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def file_fingerprint(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def location_warning(path: Path) -> str:
    text = str(path)
    lowered = text.lower()
    found = []
    for marker in ("icloud", "dropbox", "onedrive", "google drive", "mobile documents"):
        if marker in lowered and marker not in found:
            found.append(marker)
    git = False
    for parent in [path.parent, *path.parents]:
        if parent == parent.parent:
            break
        if (parent / ".git").exists():
            git = True
            break
    parts = []
    if found:
        parts.append("这个路径像是云同步目录（" + "、".join(found) + "）。加密文件仍可能被同步走。")
    if git:
        parts.append("这个位置在 git 仓库里，保险库文件有被提交的风险。")
    if parts:
        parts.append("更稳妥的位置是 ~/.offline-vault/vault.ovlt。")
    return "".join(parts)


def default_vault_path() -> Path:
    return Path.home() / ".offline-vault" / "vault.ovlt"
