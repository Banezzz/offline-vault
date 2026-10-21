#!/bin/bash
# 在访达里双击这个文件即可启动。窗口留着，关掉窗口就会锁定并退出。

set -u

SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  case "$SOURCE" in
    /*) ;;
    *) SOURCE="$DIR/$SOURCE" ;;
  esac
done
ROOT="$(cd -P "$(dirname "$SOURCE")" && pwd)"
cd "$ROOT" || exit 1

PORT=41731
PY="$ROOT/.venv/bin/python"
URL="http://127.0.0.1:${PORT}/"

pause() {
  echo
  read -r -p "按回车关闭这个窗口…"
}

if [ ! -x "$PY" ]; then
  echo "正在创建虚拟环境…"
  python3 -m venv "$ROOT/.venv" || {
    echo "创建虚拟环境失败。"
    pause
    exit 1
  }
fi

if ! "$PY" -c "import argon2, cryptography" >/dev/null 2>&1; then
  echo "正在安装依赖，第一次会稍慢…"
  "$PY" -m pip install -r "$ROOT/requirements.txt" || {
    echo "安装依赖失败。"
    pause
    exit 1
  }
fi

echo "离线保险库"
echo "地址  $URL"
echo "关掉这个窗口就会锁定并退出。"
echo

"$PY" -m vaultkit serve --port "$PORT" &
pid=$!

opened=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if curl -fsS -o /dev/null --max-time 1 "$URL"; then
    open "$URL"
    opened=1
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid"
    echo "没有启动成功。如果提示端口被占用，先关掉另一个保险库窗口。"
    pause
    exit 1
  fi
  sleep 0.3
done

if [ "$opened" -eq 0 ]; then
  echo "服务已经在跑，但浏览器没有自动打开。请手动打开 $URL"
fi

trap 'kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; exit 0' INT TERM HUP
wait "$pid"
