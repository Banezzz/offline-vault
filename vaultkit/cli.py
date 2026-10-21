"""命令行。主密码只从隐藏输入读取，不接受命令行参数。"""

from __future__ import annotations

import argparse
import getpass
import secrets
import sys
import time
from pathlib import Path

from vaultkit import __version__
from vaultkit.app import VaultApp, exclusive
from vaultkit.bip39 import check_mnemonic, load_wordlist
from vaultkit.crypto import (
    PRODUCTION_MEMORY_KIB,
    PRODUCTION_TIME_COST,
    Header,
    KdfParams,
    VaultError,
    decrypt_payload,
    default_vault_path,
    derive_key,
    encrypt_payload,
    file_fingerprint,
    location_warning,
)
from vaultkit.entries import entry_from_user

LABELS = {"mnemonic": "助记词", "card": "银行卡", "secret": "机密"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m vaultkit",
        description="本地离线保险库。主密码和助记词不要写进命令参数。",
    )
    parser.add_argument("--path", help="保险库文件，默认 ~/.offline-vault/vault.ovlt")
    parser.add_argument("--version", action="version", version="offline-vault %s" % __version__)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", help="创建保险库")
    commands.add_parser("path", help="显示保险库路径和位置提醒")
    check = commands.add_parser("check", help="检查词表和加密是否可用")
    check.add_argument("--skip-kdf", action="store_true", help=argparse.SUPPRESS)

    serve_cmd = commands.add_parser("serve", help="打开只在本机可访问的页面")
    serve_cmd.add_argument("--port", type=int, default=41731, help="本机端口，默认 41731")
    serve_cmd.add_argument("--idle", type=int, default=180, help="空闲锁定秒数，30 到 900")

    commands.add_parser("list", help="解锁并列出标题")

    add = commands.add_parser("add", help="添加条目")
    add.add_argument("--kind", choices=("mnemonic", "card", "secret"))

    show = commands.add_parser("show", help="查看一条。会再要一次主密码")
    show.add_argument("query", help="标题或 id 前缀")

    delete = commands.add_parser("delete", help="删除一条")
    delete.add_argument("query", help="标题或 id 前缀")

    commands.add_parser("passwd", help="更换主密码")

    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            print(run_self_check(skip_kdf=args.skip_kdf))
            return 0
        path = Path(args.path).expanduser() if args.path else default_vault_path()
        if args.command == "path":
            print(path)
            warning = location_warning(path)
            print(warning or "没有发现常见网盘或 git 目录。首选仍是 ~/.offline-vault/。")
            if path.is_file() and not path.is_symlink():
                print("文件校验  " + file_fingerprint(path))
            return 0
        if args.command == "serve":
            from vaultkit.web import serve

            serve(path, args.port, args.idle)
            return 0
        if args.command == "init":
            command_init(path)
            return 0
        if args.command == "list":
            command_list(path)
            return 0
        if args.command == "add":
            command_add(path, args.kind)
            return 0
        if args.command == "show":
            command_show(path, args.query)
            return 0
        if args.command == "delete":
            command_delete(path, args.query)
            return 0
        if args.command == "passwd":
            command_passwd(path)
            return 0
    except VaultError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n已取消", file=sys.stderr)
        return 130
    except Exception:
        print("内部错误：" + "操作没有完成", file=sys.stderr)
        return 1
    print("未知命令", file=sys.stderr)
    return 2


def run_self_check(*, skip_kdf: bool = False) -> str:
    load_wordlist()
    good = " ".join(["abandon"] * 11 + ["about"])
    if not check_mnemonic(good).ok or check_mnemonic(" ".join(["abandon"] * 12)).ok:
        raise VaultError("词表自检失败")
    if skip_kdf:
        kdf = KdfParams(time_cost=1, memory_cost=1024, parallelism=1, hash_len=32, salt=secrets.token_bytes(16))
    else:
        kdf = KdfParams.production()
    started = time.perf_counter()
    key = derive_key("offline-vault-self-check", kdf)
    elapsed = time.perf_counter() - started
    header = Header(version=1, vault_id=secrets.token_bytes(16), kdf=kdf)
    nonce, ciphertext = encrypt_payload(key, header, {"version": 1, "entries": []})
    decrypt_payload(key, header, nonce, ciphertext)
    if skip_kdf:
        return "自检通过（未跑正式的慢哈希）。"
    return "自检通过。Argon2id（%s MiB × %s）耗时 %.2f 秒。" % (
        PRODUCTION_MEMORY_KIB // 1024,
        PRODUCTION_TIME_COST,
        elapsed,
    )


def command_init(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise VaultError("保险库已经存在，不会覆盖。")
    print("主密码丢了就打不开，程序不保存、也不能找回。")
    print("建议用 8 个互不相关的随机词，并另外手抄一份。")
    first = ask_password("主密码: ")
    second = ask_password("再输入一次: ")
    with exclusive(path):
        app = VaultApp(path)
        try:
            app.create(first, second)
        finally:
            app.session.lock()
    print("已创建  " + str(path))
    warning = location_warning(path)
    if warning:
        print(warning)


def command_list(path: Path) -> None:
    password = ask_password("主密码: ")
    with exclusive(path):
        app = VaultApp(path)
        try:
            opened = app.unlock(password)
            listed = app.list_entries(opened.token)
        finally:
            app.session.lock()
            password = ""
    entries = listed.data["entries"]
    if not entries:
        print("（还没有条目）")
        return
    for entry in entries:
        print("%s  %s  %s  %s" % (entry["id"][:8], LABELS.get(entry["kind"], entry["kind"]), entry["title"], entry["hint"]))


def command_add(path: Path, kind: str | None) -> None:
    if kind is None:
        kind = ask("类型 mnemonic / card / secret: ").strip()
    if kind not in LABELS:
        raise VaultError("类型只能是 mnemonic、card 或 secret")
    if kind == "mnemonic":
        body = prompt_mnemonic()
    elif kind == "card":
        body = prompt_card()
    else:
        body = prompt_secret()
    body["kind"] = kind
    try:
        entry_from_user(body, previous=None)
    except VaultError as exc:
        if exc.code != "mnemonic":
            raise
        print(exc.message)
        if ask("仍然保存请输入 YES: ").strip() != "YES":
            raise VaultError("已取消")
        body["allow_unsafe_mnemonic"] = True
        entry_from_user(body, previous=None)
    password = ask_password("主密码: ")
    try:
        with exclusive(path):
            app = VaultApp(path)
            try:
                opened = app.unlock(password)
                app.save_entry(opened.token, body, password)
            finally:
                app.session.lock()
    finally:
        password = ""
        clear_screen()
    print("已保存。如果终端滚动记录里还看得到明文，请手动清掉。")


def command_show(path: Path, query: str) -> None:
    password = ask_password("主密码: ")
    with exclusive(path):
        app = VaultApp(path)
        try:
            opened = app.unlock(password)
            listed = app.list_entries(opened.token)
            match = pick(listed.data["entries"], query)
            revealed = app.reveal(opened.token, match["id"], password)
        finally:
            app.session.lock()
            password = ""
    print_entry(revealed.data["entry"])
    pause_and_clear()


def command_delete(path: Path, query: str) -> None:
    password = ask_password("主密码: ")
    with exclusive(path):
        app = VaultApp(path)
        try:
            opened = app.unlock(password)
            listed = app.list_entries(opened.token)
            match = pick(listed.data["entries"], query)
            print("将删除  %s  %s" % (LABELS.get(match["kind"], match["kind"]), match["title"]))
            if ask("输入 DELETE 确认: ").strip() != "DELETE":
                raise VaultError("已取消")
            app.delete_entry(opened.token, match["id"], password)
        finally:
            app.session.lock()
            password = ""
    print("已删除。")


def command_passwd(path: Path) -> None:
    current = ask_password("现在的主密码: ")
    new = ask_password("新主密码: ")
    confirm = ask_password("再输入一次新主密码: ")
    with exclusive(path):
        app = VaultApp(path)
        try:
            opened = app.unlock(current)
            app.change_password(opened.token, current, new, confirm)
        finally:
            app.session.lock()
            current = ""
            new = ""
            confirm = ""
    print("主密码已更换。请记住新密码，旧密码已经作废。")


def prompt_mnemonic() -> dict:
    print("单词用空格分开。这一步会显示在屏幕上，方便你核对。")
    words = ask("助记词: ")
    confirm = ask("再输入一次: ")
    passphrase = ask("BIP39 口令（没有就直接回车，这不是主密码）: ")
    address = ask("核对用地址（可空，不会拿去推导私钥）: ")
    note = ask("备注（可空）: ")
    return {
        "title": ask("标题: "),
        "secret": {
            "words": words,
            "words_confirm": confirm,
            "passphrase": passphrase,
            "address_hint": address,
            "note": note,
        },
    }


def prompt_card() -> dict:
    return {
        "title": ask("标题: "),
        "secret": {
            "bank": ask("银行: "),
            "holder": ask("持卡人（可空）: "),
            "number": ask("卡号: "),
            "expiry": ask("有效期（可空）: "),
            "cvv": ask("CVV（可空）: "),
            "pin": ask("卡密码（可空）: "),
            "note": ask("备注（可空）: "),
        },
    }


def prompt_secret() -> dict:
    return {
        "title": ask("标题: "),
        "secret": {
            "body": ask("内容: "),
            "note": ask("备注（可空）: "),
        },
    }


def print_entry(entry: dict) -> None:
    secret = entry["secret"]
    print(LABELS.get(entry["kind"], entry["kind"]) + "  " + entry["title"])
    if entry["kind"] == "mnemonic":
        words = secret["words"].split()
        for index, word in enumerate(words, start=1):
            print("%2d  %s" % (index, word))
        if secret.get("verified"):
            print("英文 BIP39 校验通过。")
        else:
            print("保存时没有通过英文 BIP39 校验。")
        if secret.get("passphrase"):
            print("BIP39 口令  " + secret["passphrase"])
        else:
            print("没有 BIP39 口令。")
        if secret.get("address_hint"):
            print("核对地址  " + secret["address_hint"])
    elif entry["kind"] == "card":
        print("银行    " + secret.get("bank", ""))
        print("持卡人  " + secret.get("holder", ""))
        print("卡号    " + group_digits(secret.get("number", "")))
        print("有效期  " + (secret.get("expiry") or ""))
        if secret.get("cvv"):
            print("CVV     " + secret["cvv"])
        if secret.get("pin"):
            print("卡密码  " + secret["pin"])
        if secret.get("luhn_ok") is False:
            print("卡号没有通过 Luhn 校验。")
    else:
        print(secret.get("body", ""))
    if secret.get("note"):
        print("备注  " + secret["note"])


def pick(entries: list[dict], query: str) -> dict:
    query = query.strip()
    if not query:
        raise VaultError("请给出标题或 id")
    exact = [entry for entry in entries if entry["id"] == query or entry["title"] == query]
    if len(exact) == 1:
        return exact[0]
    folded = query.casefold()
    matches = [
        entry
        for entry in entries
        if entry["id"].startswith(query) or folded in entry["title"].casefold()
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise VaultError("没有匹配的条目")
    lines = "\n".join("%s  %s" % (entry["id"][:8], entry["title"]) for entry in matches)
    raise VaultError("匹配到多条，请用更完整的标题或 id：\n" + lines)


def group_digits(number: str) -> str:
    return " ".join(number[index : index + 4] for index in range(0, len(number), 4))


def ask(prompt: str) -> str:
    try:
        return input(prompt)
    except EOFError as exc:
        raise VaultError("已取消") from exc


def ask_password(prompt: str) -> str:
    try:
        return getpass.getpass(prompt)
    except (EOFError, KeyboardInterrupt) as exc:
        raise VaultError("已取消") from exc


def pause_and_clear() -> None:
    try:
        input("\n看完后按回车清屏。")
    except EOFError:
        return
    clear_screen()


def clear_screen() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[2J\033[3J\033[H")
        sys.stdout.flush()
