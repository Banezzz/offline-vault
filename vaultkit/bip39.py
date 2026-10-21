"""英文 BIP39 词表与校验。

只判断词是否完整、顺序是否正确，不推导种子或私钥。
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
VALID_COUNTS = (12, 15, 18, 21, 24)
_WORDS: tuple[str, ...] | None = None
_INDEX: dict[str, int] | None = None


class WordlistError(Exception):
    pass


def wordlist_path() -> Path:
    return Path(__file__).with_name("english.txt")


def load_wordlist() -> tuple[str, ...]:
    global _WORDS, _INDEX
    if _WORDS is not None and _INDEX is not None:
        return _WORDS
    path = wordlist_path()
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(digest, WORDLIST_SHA256):
        raise WordlistError("英文词表已被改动，已停止校验")
    words = tuple(line.strip() for line in raw.decode("utf-8").splitlines())
    if len(words) != 2048 or words[0] != "abandon" or words[-1] != "zoo":
        raise WordlistError("英文词表不完整")
    if len(set(words)) != 2048:
        raise WordlistError("英文词表有重复")
    _WORDS = words
    _INDEX = {word: index for index, word in enumerate(words)}
    return words


@dataclass(frozen=True)
class MnemonicCheck:
    ok: bool
    reason: str
    unknown: tuple[str, ...] = ()


def check_mnemonic(phrase: str) -> MnemonicCheck:
    words = phrase.strip().lower().split()
    if len(words) not in VALID_COUNTS:
        return MnemonicCheck(False, "count")
    index = _INDEX if _INDEX is not None else None
    if index is None:
        load_wordlist()
        index = _INDEX or {}
    unknown = tuple(word for word in words if word not in index)
    if unknown:
        return MnemonicCheck(False, "unknown", unknown[:4])
    bits = "".join(f"{index[word]:011b}" for word in words)
    checksum_len = len(words) // 3
    entropy_bits = bits[:-checksum_len]
    checksum_bits = bits[-checksum_len:]
    entropy = int(entropy_bits, 2).to_bytes(len(entropy_bits) // 8, "big")
    digest_bits = "".join(f"{byte:08b}" for byte in hashlib.sha256(entropy).digest())
    expected = digest_bits[:checksum_len]
    if not hmac.compare_digest(expected, checksum_bits):
        return MnemonicCheck(False, "checksum")
    return MnemonicCheck(True, "ok")
