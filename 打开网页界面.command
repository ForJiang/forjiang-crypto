#!/bin/bash
# forjiang-crypto 一键启动（macOS）
# 双击本文件即可：找 Python -> 装依赖 -> 启动网页界面并自动打开浏览器
# 关闭此终端窗口 = 停止服务。自定义端口：先 export PORT=9000 再双击。

cd "$(dirname "$0")" || exit 1
PORT="${PORT:-8765}"
URL="http://127.0.0.1:${PORT}/"

# 老版本 macOS/Linux 的 locale 可能是 ASCII，中文路径和中文日志会 UnicodeEncodeError
export PYTHONUTF8=1
export PYTHONIOENCODING="${PYTHONIOENCODING:-utf-8}"

# 能 import cryptography 的 Python 优先；其次项目本地的 .venv
find_ready_python() {
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c "import cryptography" >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  if [ -x ".venv/bin/python" ] && .venv/bin/python -c "import cryptography" >/dev/null 2>&1; then
    echo "$(pwd)/.venv/bin/python"
    return 0
  fi
  return 1
}

# 任意一个 python3/python（还没装依赖的）
find_any_python() {
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then
      command -v "$c"
      return 0
    fi
  done
  return 1
}

# 装依赖：按环境逐级兜底，每一步都以“能 import”为唯一成功标准
install_deps() {
  local py="$1"
  "$py" -c "import cryptography" >/dev/null 2>&1 && return 0

  echo "首次运行，正在安装依赖 cryptography ..."

  # 1) uv 管理的 Python：PEP 668 下 pip 会被拒，用 uv 装进当前环境
  if command -v uv >/dev/null 2>&1; then
    echo "检测到 uv，使用 uv 安装 ..."
    if uv pip install --system -r requirements.txt \
       && "$py" -c "import cryptography" >/dev/null 2>&1; then
      return 0
    fi
  fi

  # 2) 常规 pip
  if "$py" -m pip install -r requirements.txt 2>/dev/null \
     && "$py" -c "import cryptography" >/dev/null 2>&1; then
    return 0
  fi

  # 3) 装到用户目录（不写系统目录，通常不需要管理员权限）
  if "$py" -m pip install --user -r requirements.txt 2>/dev/null \
     && "$py" -c "import cryptography" >/dev/null 2>&1; then
    return 0
  fi

  # 4) 系统包目录被标记为“外部管理”时，显式允许写入（PEP 668）
  if "$py" -m pip install --break-system-packages -r requirements.txt 2>/dev/null \
     && "$py" -c "import cryptography" >/dev/null 2>&1; then
    return 0
  fi

  return 1
}

PY_BIN="$(find_ready_python)"
if [ -z "$PY_BIN" ]; then
  PY_BIN="$(find_any_python)"
  if [ -z "$PY_BIN" ]; then
    echo ""
    echo "[错误] 没有找到 Python。"
    echo "请先安装 Python 3.8 或更高版本：https://www.python.org/downloads/"
    echo "装好后重新双击本文件。"
    echo ""
    read -r -p "按回车键退出..." _
    exit 1
  fi

  if ! install_deps "$PY_BIN"; then
    # 5) 最后手段：建一个项目本地虚拟环境，与系统完全隔离
    echo ""
    echo "直接安装失败，改为创建项目本地虚拟环境 .venv（与系统隔离，最稳）..."
    rm -rf .venv
    if "$PY_BIN" -m venv .venv \
       && .venv/bin/python -m pip install -r requirements.txt \
       && .venv/bin/python -c "import cryptography" >/dev/null 2>&1; then
      PY_BIN="$(pwd)/.venv/bin/python"
      echo "虚拟环境就绪：$(pwd)/.venv"
    else
      echo ""
      echo "[错误] 依赖安装失败。请手动执行以下任一命令："
      echo "  uv pip install --system -r requirements.txt"
      echo "  $PY_BIN -m pip install --user -r requirements.txt"
      echo "  $PY_BIN -m pip install --break-system-packages -r requirements.txt"
      echo ""
      read -r -p "按回车键退出..." _
      exit 1
    fi
  fi
fi

echo ""
echo "=================================================="
echo "  forjiang-crypto 网页界面正在启动"
echo "  地址：${URL}"
echo "  浏览器会自动打开；若没有，请手动访问上面的地址"
echo "  端口被别的程序占用时，服务会自动改用最近的空闲端口，以浏览器打开的地址为准"
echo "  关闭此窗口 = 停止服务"
echo "=================================================="
echo ""

# 端口上可能已经有一个本系统的界面在运行（比如之前双击过没关窗口）：
# 这种情况不必再抢端口，直接打开浏览器用现成的。
if curl -s -m 2 "${URL}api/config" 2>/dev/null | grep -q '"version"'; then
  echo "检测到 ${URL} 已有 forjiang-crypto 界面在运行，直接为你打开浏览器。"
  echo "（那个窗口就是服务本体，关掉它才会真正停止服务）"
  open "${URL}"
  read -r -p "按回车键关闭本窗口..." _
  exit 0
fi

# 服务起来后自动打开浏览器（--open 由服务端在监听就绪后触发）
# -u：输出不缓冲，端口被换掉、服务已启动这些信息立刻可见（否则重定向日志时会丢）
PYTHONPATH="$(pwd):$PYTHONPATH" "$PY_BIN" -u -m webui --port "$PORT" --open
STATUS=$?
# 128 以上是被信号打死的（Ctrl-C / 关窗口 / 被结束任务），属正常停止；
# 只有真正的错误码（端口占用、依赖缺失等）才给排查提示。
if [ "$STATUS" -lt 128 ] && [ "$STATUS" -ne 0 ]; then
  echo ""
  echo "[提示] 启动失败（退出码 ${STATUS}）。常见原因：端口 ${PORT} 被其他程序占用。"
  echo "换一个端口再试：PORT=9000 后重新双击本文件。"
fi

echo ""
echo "服务已停止。"
read -r -p "按回车键关闭窗口..." _
