"""条目格式。列表只暴露标题和很短的提示，不暴露助记词或完整卡号。"""

from __future__ import annotations

import re
import unicodedata
import uuid
from datetime import datetime, timezone

from vaultkit.bip39 import WordlistError, check_mnemonic
from vaultkit.crypto import VERSION, VaultError

MAX_ENTRIES = 200
KINDS = ("mnemonic", "card", "secret")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id() -> str:
    return str(uuid.uuid4())


def public_view(entry: dict) -> dict:
    return {
        "id": entry["id"],
        "kind": entry["kind"],
        "title": entry["title"],
        "hint": hint_for(entry),
        "created_at": entry["created_at"],
        "updated_at": entry["updated_at"],
    }


def hint_for(entry: dict) -> str:
    kind = entry["kind"]
    secret = entry["secret"]
    if kind == "mnemonic":
        count = len(str(secret.get("words", "")).split())
        state = "校验通过" if secret.get("verified") else "未校验"
        return f"{count} 个词 · {state}"
    if kind == "card":
        bank = str(secret.get("bank") or "银行卡")
        digits = "".join(ch for ch in str(secret.get("number", "")) if ch.isdigit())
        tail = digits[-4:] if len(digits) >= 4 else ""
        if tail:
            return f"{bank} · 尾号 {tail}"
        return bank
    return "机密文本"


def empty_payload() -> dict:
    return {"version": VERSION, "entries": []}


def parse_payload_entries(entries: object) -> list[dict]:
    if not isinstance(entries, list):
        raise VaultError("保险库内容无法识别")
    if len(entries) > MAX_ENTRIES:
        raise VaultError("条目数量异常，已停止打开")
    seen = set()
    cleaned = []
    for item in entries:
        entry = _parse_stored_entry(item)
        if entry["id"] in seen:
            raise VaultError("保险库里有重复记录，已停止打开以免写坏它")
        seen.add(entry["id"])
        cleaned.append(entry)
    return cleaned


def entry_from_user(body: dict, *, previous: dict | None) -> dict:
    if not isinstance(body, dict):
        raise VaultError("条目格式不正确")
    kind = body.get("kind")
    if kind not in KINDS:
        raise VaultError("不支持的条目类型")
    if previous is not None and previous["kind"] != kind:
        raise VaultError("不能更改条目类型")
    secret_in = body.get("secret")
    if not isinstance(secret_in, dict):
        raise VaultError("条目格式不正确")
    title = _single_line(body.get("title"), field="标题", max_len=80, required=True)
    timestamp = now_iso()
    if kind == "mnemonic":
        secret = _mnemonic_secret(secret_in, body.get("allow_unsafe_mnemonic") is True, previous)
    elif kind == "card":
        secret = _card_secret(secret_in)
    else:
        secret = _note_secret(secret_in)
    return {
        "id": previous["id"] if previous else new_id(),
        "kind": kind,
        "title": title,
        "created_at": previous["created_at"] if previous else timestamp,
        "updated_at": timestamp,
        "secret": secret,
    }


def _mnemonic_secret(secret_in: dict, allow_unsafe: bool, previous: dict | None) -> dict:
    if secret_in.get("keep_mnemonic") is True:
        if previous is None:
            raise VaultError("新建助记词时必须填写单词")
        words = previous["secret"]["words"]
        verified = bool(previous["secret"]["verified"])
    else:
        words = _normalize_words(secret_in.get("words"))
        confirm = _normalize_words(secret_in.get("words_confirm"))
        if not words:
            raise VaultError("请填写助记词")
        if words != confirm:
            raise VaultError("两次输入的助记词不一致")
        try:
            checked = check_mnemonic(words)
        except WordlistError as exc:
            raise VaultError("英文词表不可用，已停止保存助记词") from exc
        if checked.ok:
            verified = True
        elif allow_unsafe and checked.reason in ("unknown", "checksum"):
            verified = False
        elif checked.reason == "count":
            raise VaultError("助记词必须是 12、15、18、21 或 24 个词", code="mnemonic")
        elif checked.reason == "unknown":
            shown = "、".join(checked.unknown)
            raise VaultError(
                f"这些词不在英文 BIP39 词表里：{shown}。如果这是其他语言，核对后再勾选强制保存。",
                code="mnemonic",
            )
        else:
            raise VaultError(
                "英文 BIP39 校验未通过，可能有错词或顺序错了。请对照纸面检查，确认无误后再勾选强制保存。",
                code="mnemonic",
            )
    return {
        "words": words,
        "passphrase": _passphrase(secret_in.get("passphrase")),
        "address_hint": _single_line(
            secret_in.get("address_hint", ""),
            field="核对地址",
            max_len=200,
            required=False,
        ),
        "note": _multiline(secret_in.get("note", ""), field="备注", max_len=4000),
        "verified": verified,
    }


def _card_secret(secret_in: dict) -> dict:
    if not isinstance(secret_in.get("number"), str):
        raise VaultError("卡号必须是文本")
    number = "".join(ch for ch in secret_in.get("number", "") if ch.isdigit())
    if not 12 <= len(number) <= 19:
        raise VaultError("卡号需要 12 到 19 位数字")
    if secret_in.get("cvv") not in (None, "") and not isinstance(secret_in.get("cvv"), str):
        raise VaultError("CVV 必须是文本")
    if secret_in.get("pin") not in (None, "") and not isinstance(secret_in.get("pin"), str):
        raise VaultError("卡密码必须是文本")
    cvv = "".join(ch for ch in str(secret_in.get("cvv") or "") if ch.isdigit())
    if cvv and not 3 <= len(cvv) <= 4:
        raise VaultError("CVV 只能是 3 或 4 位数字，也可以留空")
    pin = "".join(ch for ch in str(secret_in.get("pin") or "") if ch.isdigit())
    if pin and not 4 <= len(pin) <= 12:
        raise VaultError("卡密码只能是 4 到 12 位数字，也可以留空")
    return {
        "bank": _single_line(secret_in.get("bank"), field="银行", max_len=40, required=True),
        "holder": _single_line(secret_in.get("holder", ""), field="持卡人", max_len=80, required=False),
        "number": number,
        "expiry": _single_line(secret_in.get("expiry", ""), field="有效期", max_len=10, required=False),
        "cvv": cvv,
        "pin": pin,
        "note": _multiline(secret_in.get("note", ""), field="备注", max_len=4000),
        "luhn_ok": luhn_ok(number),
    }


def _note_secret(secret_in: dict) -> dict:
    return {
        "body": _multiline(secret_in.get("body"), field="内容", max_len=8000, required=True),
        "note": _multiline(secret_in.get("note", ""), field="备注", max_len=4000),
    }


def _parse_stored_entry(item: object) -> dict:
    if not isinstance(item, dict):
        raise VaultError("保险库里有一条无法识别的记录，已停止打开以免写坏它")
    kind = item.get("kind")
    if kind not in KINDS:
        raise VaultError("保险库里有一条无法识别的记录，已停止打开以免写坏它")
    try:
        entry_id = str(uuid.UUID(str(item.get("id"))))
    except (ValueError, TypeError, AttributeError) as exc:
        raise VaultError("保险库里有一条无法识别的记录，已停止打开以免写坏它") from exc
    title = item.get("title")
    created = item.get("created_at")
    updated = item.get("updated_at")
    secret = item.get("secret")
    if (
        not isinstance(title, str)
        or not title.strip()
        or not isinstance(created, str)
        or not isinstance(updated, str)
        or not _TIMESTAMP.match(created)
        or not _TIMESTAMP.match(updated)
        or not isinstance(secret, dict)
    ):
        raise VaultError("保险库里有一条无法识别的记录，已停止打开以免写坏它")
    if kind == "mnemonic":
        stored = {
            "words": _require_stored_str(secret, "words"),
            "passphrase": _optional_stored_str(secret, "passphrase"),
            "address_hint": _optional_stored_str(secret, "address_hint"),
            "note": _optional_stored_str(secret, "note"),
            "verified": secret.get("verified") is True,
        }
    elif kind == "card":
        stored = {
            "bank": _require_stored_str(secret, "bank"),
            "holder": _optional_stored_str(secret, "holder"),
            "number": _require_stored_str(secret, "number"),
            "expiry": _optional_stored_str(secret, "expiry"),
            "cvv": _optional_stored_str(secret, "cvv"),
            "pin": _optional_stored_str(secret, "pin"),
            "note": _optional_stored_str(secret, "note"),
            "luhn_ok": secret.get("luhn_ok") is True,
        }
    else:
        stored = {
            "body": _require_stored_str(secret, "body"),
            "note": _optional_stored_str(secret, "note"),
        }
    return {
        "id": entry_id,
        "kind": kind,
        "title": title.strip(),
        "created_at": created,
        "updated_at": updated,
        "secret": stored,
    }


def _require_stored_str(secret: dict, key: str) -> str:
    value = secret.get(key)
    if not isinstance(value, str) or value == "":
        raise VaultError("保险库里有一条无法识别的记录，已停止打开以免写坏它")
    return value


def _optional_stored_str(secret: dict, key: str) -> str:
    value = secret.get(key, "")
    if not isinstance(value, str):
        raise VaultError("保险库里有一条无法识别的记录，已停止打开以免写坏它")
    return value


def _normalize_words(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise VaultError("助记词必须是文本")
    text = unicodedata.normalize("NFKC", value).replace("\u00a0", " ")
    text = _reject_bad_controls(text, allow_newlines=False)
    return " ".join(text.lower().split())


def _passphrase(value: object) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise VaultError("BIP39 口令必须是文本")
    text = unicodedata.normalize("NFKD", value)
    text = _reject_bad_controls(text, allow_newlines=False)
    if len(text) > 256:
        raise VaultError("BIP39 口令过长")
    return text


def _single_line(value: object, *, field: str, max_len: int, required: bool) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise VaultError(f"{field}必须是文本")
    text = " ".join(_reject_bad_controls(value, allow_newlines=False).split())
    if len(text) > max_len:
        raise VaultError(f"{field}过长")
    if required and text == "":
        raise VaultError(f"请填写{field}")
    return text


def _multiline(value: object, *, field: str, max_len: int, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise VaultError(f"{field}必须是文本")
    text = _reject_bad_controls(value, allow_newlines=True).replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > max_len:
        raise VaultError(f"{field}过长")
    if required and text.strip() == "":
        raise VaultError(f"请填写{field}")
    return text


def _reject_bad_controls(value: str, *, allow_newlines: bool) -> str:
    if "\x00" in value:
        raise VaultError("文本里有非法字符")
    out = []
    for char in value:
        if char in "\n\r":
            if not allow_newlines:
                out.append(" ")
            else:
                out.append(char)
            continue
        if char == "\t":
            out.append(" ")
            continue
        if ord(char) < 32 or ord(char) == 127:
            raise VaultError("文本里有控制字符")
        out.append(char)
    return "".join(out)


def luhn_ok(number: str) -> bool:
    digits = [int(char) for char in number if char.isdigit()]
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    alt = False
    for digit in reversed(digits):
        if alt:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        alt = not alt
    return total % 10 == 0
