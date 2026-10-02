"""forjiang-crypto 本地 Web 服务。

只监听 127.0.0.1：界面直接读写本机路径，不对外暴露。
页面在浏览器里操作，后端调用 forjiang_crypto 库，产物与 CLI 完全一致。

运行：
    python3 -m webui [--host 127.0.0.1] [--port 8765]
"""

import argparse
import errno
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from forjiang_crypto import (  # noqa: E402
    PASSWORD_MIN_LEN,
    SUFFIX,
    __version__,
    generate_keypair,
    password_decrypt_file,
    password_encrypt_file,
    save_keypair,
)
from forjiang_crypto.codec import (  # noqa: E402
    _disk_name,
    _sanitize_name,
    decrypt_forjiang,
    encrypt_uploaded,
    strip_forjiang,
)
from forjiang_crypto.cli import _collect, _collect_forjiang  # noqa: E402
from forjiang_crypto.exceptions import ForjiangCryptoError  # noqa: E402
from forjiang_crypto.keys import load_private_key, load_public_key  # noqa: E402

INDEX_HTML = os.path.join(_HERE, "index.html")
SIMPLE_HTML = os.path.join(_HERE, "simple.html")
WINDOW = 1 << 20          # 扫描窗口, 内存占用与文件大小无关
COPY_CHUNK = 1 << 16
MAX_BODY = 8 << 30        # 8 GiB 上限, 超出直接拒绝
PORT_SEARCH_SPAN = 20     # 端口被占用时往后尝试的个数（8765 起找 20 个）

# 本次会话产出的文件（供 /api/download 下发），只认这里登记过的绝对路径
_SESSION_OUTPUTS = set()


def _unique_name(name, seen):
    """同一批请求里重名时加 (2)/(3) 后缀，避免不同文件静默互相覆盖。"""
    if name not in seen:
        seen[name] = 1
        return name
    seen[name] += 1
    stem, ext = os.path.splitext(name)
    return f"{stem} ({seen[name]}){ext}"


def _quote(name):
    from urllib.parse import quote

    return quote(name)


def _unique_suffix():
    """本次请求内的唯一后缀：并发请求不能共用一个中转文件名。

    服务是 ThreadingHTTPServer，两个下载/解密请求同时落到同一个 out_dir 时，
    固定的 "staging.out" / "folderenc-forjiang.zip" 会互相覆盖或直接失败。
    """
    import uuid

    return uuid.uuid4().hex[:10]


# ---------------------------------------------------------------------------
# multipart 流式解析: body 先落临时文件, 再在磁盘上按 boundary 扫描分段,
# 段内文件内容也走临时文件, 全程内存只持有窗口和头部
# ---------------------------------------------------------------------------


def _find(fh, needle, start):
    """从 start 起找 needle, 返回 (绝对位置, 从 start 开始的缓冲)。"""
    fh.seek(start)
    overlap = max(len(needle) - 1, 0)
    buf = b""
    base = start
    while True:
        chunk = fh.read(WINDOW)
        if not chunk:
            return -1, buf
        buf += chunk
        idx = buf.find(needle)
        if idx >= 0:
            return base + idx, buf
        keep = buf[-overlap:] if overlap else b""
        base = fh.tell() - len(keep)
        buf = keep


def _copy_range(fh, dst_path, start, end):
    fh.seek(start)
    remaining = end - start
    with open(dst_path, "wb") as out:
        while remaining > 0:
            chunk = fh.read(min(COPY_CHUNK, remaining))
            if not chunk:
                break
            out.write(chunk)
            remaining -= len(chunk)


def _read_range(fh, start, end):
    fh.seek(start)
    return fh.read(end - start)


def _parse_part_headers(blob):
    """返回 (name, filename)，解析不了就返回 (None, None)。"""
    name = filename = None
    try:
        text = blob.decode("utf-8", "replace")
    except Exception:
        return None, None
    for line in text.split("\r\n"):
        if line.lower().startswith("content-disposition:"):
            m = re.search(r'name="([^"]*)"', line)
            if m:
                name = m.group(1)
            m = re.search(r'filename="([^"]*)"', line)
            if m:
                filename = m.group(1)
    return name, filename


def extract_multipart(body_path, content_type, tmpdir):
    """把 multipart body 解析成 {字段名: 值} 与 {字段名: [(文件名, 临时路径)]}。"""
    m = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not m:
        raise ValueError("multipart 请求缺少 boundary")
    boundary = m.group(1).encode()
    first_delim = b"--" + boundary
    delim = b"\r\n--" + boundary

    fields = {}
    files = {}
    with open(body_path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        pos, _buf = _find(fh, first_delim, 0)
        if pos < 0:
            return fields, files
        cursor = pos + len(first_delim)

        index = 0
        while cursor < size:
            headers_end, buf = _find(fh, b"\r\n\r\n", cursor)
            if headers_end < 0:
                break
            headers_blob = _read_range(fh, cursor, headers_end)
            body_start = headers_end + 4
            delim_pos, _buf2 = _find(fh, delim, body_start)
            if delim_pos < 0:
                break

            name, filename = _parse_part_headers(headers_blob)
            if filename is not None:
                if not name:
                    name = "file"
                # 落盘名只用 basename 并按平台裁剪（把 upload-NNNN- 前缀也算进
                # 长度预算）：浏览器可能送来带 : * ? 的名字或超长名字，
                # 直接用会让整个请求 500
                safe = _disk_name(os.path.basename(filename) or "upload",
                                  tmpdir, len(f"upload-{index:04d}-"))
                path = os.path.join(tmpdir, f"upload-{index:04d}-{safe}")
                index += 1
                _copy_range(fh, path, body_start, delim_pos)
                files.setdefault(name, []).append((filename, path))
            elif name is not None:
                value = _read_range(fh, body_start, delim_pos)
                fields[name] = value.decode("utf-8", "replace")

            cursor = delim_pos + len(delim)
            # 结尾标记是 "--\r\n" / "--"
            tail = _read_range(fh, cursor, cursor + 2)
            if tail.startswith(b"--"):
                break
            cursor += 2  # 跳过段与段之间的 \r\n

    return fields, files


# ---------------------------------------------------------------------------
# HTTP 处理
# ---------------------------------------------------------------------------


def _per_file_error(exc):
    """把单个文件的异常变成一行可读的错误信息。

    批处理里一个文件失败不该带走其他文件：除了加密错误和文件系统错误，
    文件头损坏（struct.error）、非法值（ValueError，例如名字里有非法字节）
    也按“该文件失败”上报；最后的 Exception 兜底会把堆栈打到控制台，
    既不让整批中断，也不静默吞掉真正的 bug。
    """
    if isinstance(exc, (ForjiangCryptoError, OSError, ValueError, struct.error)):
        return str(exc) or type(exc).__name__
    traceback.print_exc()
    return f"内部错误 {type(exc).__name__}: {exc}"


class Handler(BaseHTTPRequestHandler):
    server_version = "ForjiangWebUI/1.0"
    protocol_version = "HTTP/1.1"
    timeout = 300
    # -- 工具 -------------------------------------------------------------

    def _send_json(self, obj, status=200):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_html(self, text, status=200):
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _read_body_to_file(self, tmpdir):
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            raise ValueError("不支持分块传输编码，请让客户端一次性发送")
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise ValueError("请求体为空")
        if length > MAX_BODY:
            raise ValueError(f"请求体超过上限 {MAX_BODY // (1 << 30)} GiB")
        path = os.path.join(tmpdir, "body.bin")
        remaining = length
        with open(path, "wb") as fh:
            while remaining > 0:
                chunk = self.rfile.read(min(COPY_CHUNK, remaining))
                if not chunk:
                    raise ValueError("请求体被提前截断")
                fh.write(chunk)
                remaining -= len(chunk)
        return path

    def log_message(self, fmt, *args):  # 静默默认访问日志，界面自带输出区
        pass

    # -- 路由 -------------------------------------------------------------

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/simple", "/simple.html"):
            self._send_file_html(SIMPLE_HTML, "simple.html")
            return
        if path in ("/full", "/full.html", "/index.html"):
            self._send_file_html(INDEX_HTML, "index.html")
            return
        if path == "/api/config":
            self._send_json({
                "root": os.getcwd(),
                "dataDir": _default_data_dir(),
                "canPick": _native_picker_available(),
                "version": __version__,
            })
            return
        if path == "/api/download":
            self._handle_download()
            return
        self._send_json({"ok": False, "error": f"未知路径 {path}"}, status=404)

    def _send_file_html(self, path, fallback_title):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                self._send_html(fh.read())
        except OSError:
            self._send_html(f"<h1>{fallback_title} 缺失</h1>", status=500)

    def _handle_download(self):
        """把本次会话产出的文件发给浏览器下载。

        只服务于 _SESSION_OUTPUTS 里登记过的路径，避免沦为任意文件读取口。
        """
        from urllib.parse import parse_qs, urlparse

        query = parse_qs(urlparse(self.path).query)
        raw = (query.get("path") or [""])[0]
        target = os.path.abspath(raw)
        if not raw or target not in _SESSION_OUTPUTS or not os.path.isfile(target):
            self._send_json({"ok": False, "error": "文件不存在或已不是本次会话的产物"},
                            status=404)
            return
        name = os.path.basename(target)
        size = os.path.getsize(target)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition",
                         f"attachment; filename*=UTF-8''{_quote(name)}")
        self.end_headers()
        with open(target, "rb") as fh:
            shutil.copyfileobj(fh, self.wfile, COPY_CHUNK)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        tmpdir = tempfile.mkdtemp(prefix="forjiang-webui-")
        try:
            if path == "/api/keygen":
                self._handle_keygen(tmpdir)
            elif path in ("/api/encrypt", "/api/decrypt"):
                self._handle_crypto(path, tmpdir)
            elif path in ("/api/simple/encrypt", "/api/simple/decrypt"):
                self._handle_simple(path, tmpdir)
            elif path == "/api/pick":
                self._handle_pick(tmpdir)
            else:
                self._send_json({"ok": False, "error": f"未知路径 {path}"}, status=404)
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
        except ForjiangCryptoError as exc:
            # 业务校验失败（模长不够、密钥文件读不了/解析不了等）是客户端可修正的
            # 问题，按 400 回干净的一句话；此前会掉进 500 并在控制台甩堆栈
            self._send_json({"ok": False, "error": str(exc)}, status=400)
        except Exception as exc:  # 兜底：绝不给浏览器回 traceback
            # 堆栈只打到启动器控制台，方便排查；浏览器只拿到一行干净的错误
            traceback.print_exc()
            self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, status=500)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # -- 具体处理 ---------------------------------------------------------

    def _handle_simple(self, path, tmpdir):
        """简版界面：密码模式加解密。

        两种输入方式（二选一）：
        - files：浏览器选的文件（可多选）；
        - folder：服务端遍历的整个文件夹（用原生目录选择框选或手动输入），
                  遍历规则复用 CLI 的 _collect/_collect_forjiang。
        文件夹模式的多个产物会打包成一个 zip 返回，避免浏览器拦截批量下载。
        """
        body_path = self._read_body_to_file(tmpdir)
        # 两种提交方式都接受：multipart（带文件）或纯 JSON（只要文件夹时更方便）
        ctype = (self.headers.get("Content-Type") or "").lower()
        if ctype.startswith("application/json"):
            with open(body_path, "rb") as fh:
                fields = json.loads(fh.read().decode("utf-8"))
            uploads = []
        else:
            fields, files = extract_multipart(body_path, self.headers.get("Content-Type"),
                                              tmpdir)
            uploads = files.get("files") or files.get("files[]")
        folder = (fields.get("folder") or "").strip()

        password = fields.get("password") or ""
        if not password:
            raise ValueError("请输入密码")
        if not uploads and not folder:
            raise ValueError("请选择文件（可多选）或选择一个文件夹")
        if uploads and folder:
            raise ValueError("文件和文件夹只能选一种，请清空其中一个")

        out_dir = (fields.get("outdir") or "").strip() or _default_data_dir()
        os.makedirs(out_dir, exist_ok=True)
        encrypting = path.endswith("/encrypt")
        # 只在加密时要求口令长度：decrypt 的口令可能本来就短（CLI 与浏览器版都不
        # 设下限），短口令交给认证结果说话，别在入口就拒绝。
        if encrypting and len(password) < PASSWORD_MIN_LEN:
            raise ValueError(f"密码至少 {PASSWORD_MIN_LEN} 位")

        # 统一成 (显示名, 源路径) 列表
        jobs = []
        if folder:
            if not os.path.isdir(folder):
                raise ValueError(f"文件夹不存在：{folder}")
            if encrypting:
                paths = _collect([folder], recursive=True)
            else:
                paths = _collect_forjiang([folder], recursive=True)
            if not paths:
                raise ValueError("文件夹里没有可处理的文件")
            jobs = [(os.path.relpath(p, folder), p) for p in paths]
        else:
            jobs = [(os.path.basename(name), src) for name, src in uploads]

        results = []
        ok_count = 0
        seen_names = {}   # 同一批里的名字 -> 出现次数，重名加后缀防覆盖
        outputs = []
        token = _unique_suffix()   # 本次请求专属，避免并发请求互相覆盖中转件
        for display, src in jobs:
            base = os.path.basename(display)
            entry = {"file": display}
            try:
                # 简版的输出区是它自己的数据目录；跨批同名可覆盖，
                # 同一批内的重名必须区分，否则不同文件会静默丢失。
                if encrypting:
                    if base.endswith(SUFFIX):
                        raise ValueError(f"{base} 已经是 .forjiang 加密文件")
                    # 落盘名按平台清洗（把 .forjiang 后缀也算进长度预算）：
                    # 带 : * ? 或超长的名字在 Windows 上写不下去
                    stem = _unique_name(
                        _disk_name(strip_forjiang(base), out_dir, len(SUFFIX)),
                        seen_names)
                    out_path = os.path.join(out_dir, stem + SUFFIX)
                    r = password_encrypt_file(src, out_path, password, origin=stem)
                else:
                    if not base.endswith(SUFFIX):
                        raise ValueError("请选择 .forjiang 文件")
                    staging = os.path.join(out_dir, f".forjiang-staging-{token}")
                    r = password_decrypt_file(src, staging, password)
                    final_name = _unique_name(
                        _disk_name(_sanitize_name(r.origin or "decrypted.bin"),
                                   out_dir, 0), seen_names)
                    final_path = os.path.join(out_dir, final_name)
                    os.replace(r.output_path, final_path)
                    r.output_path = final_path

                _SESSION_OUTPUTS.add(os.path.abspath(r.output_path))
                outputs.append(r.output_path)
                entry.update({
                    "ok": True,
                    "output": r.output_path,
                    "plain": r.original_size,
                    "cipher": os.path.getsize(r.output_path),
                })
                ok_count += 1
            except Exception as exc:
                entry["error"] = _per_file_error(exc)
                entry["ok"] = False
            results.append(entry)

        response = {"ok": ok_count == len(results), "results": results}
        # 文件夹模式：产物打包成单个 zip（浏览器通常会拦截多个自动下载）
        if folder and outputs:
            # zip 名带本次请求的唯一后缀：同名文件夹连续处理两次时，
            # 上一次还没下载的包不会被覆盖；文件夹名按平台清洗。
            # 长度预算取两种后缀里较长的那个："-forjiang-"(10) + token(10) + ".zip"(4)
            tag = _disk_name(
                os.path.basename(folder.rstrip("/\\")) or "folder", out_dir, 24)
            zip_path = os.path.join(
                out_dir,
                f"{tag}{'-forjiang' if encrypting else '-解密'}-{token}.zip")
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for p in outputs:
                    zf.write(p, os.path.basename(p))
            _SESSION_OUTPUTS.add(os.path.abspath(zip_path))
            response["zip"] = zip_path
        self._send_json(response)

    def _json_body(self, tmpdir):
        body_path = self._read_body_to_file(tmpdir)
        with open(body_path, "rb") as fh:
            return json.loads(fh.read().decode("utf-8"))

    def _handle_pick(self, tmpdir):
        """弹出系统原生的目录/文件选择框，把选中的真实绝对路径返回给页面。

        probe=True 只探测本环境能不能弹框（不弹窗），供前端决定是否显示
        “浏览…”按钮，也供测试调用。
        """
        try:
            data = self._json_body(tmpdir)
        except ValueError:
            data = {}
        if data.get("probe"):
            self._send_json({"ok": True, "canPick": _native_picker_available()})
            return

        kind = str(data.get("kind") or "dir")
        if kind not in ("dir", "file"):
            raise ValueError(f"不支持的 kind: {kind}")
        path, pick_error = _native_pick(kind, title=str(data.get("title") or "请选择"),
                                       initial=str(data.get("initial") or "") or None)
        if pick_error:
            self._send_json({"ok": False, "error": pick_error}, status=501)
            return
        self._send_json({"ok": True, "path": path})  # path 为 None 表示用户取消

    def _handle_keygen(self, tmpdir):
        data = self._json_body(tmpdir)
        bits = int(data.get("bits") or 3072)
        out_dir = (data.get("outdir") or "keys").strip()
        password = (data.get("password") or "").strip() or None
        # 先生成再建目录：模长不合法等失败不该留下一个空目录
        keypair = generate_keypair(bits)
        os.makedirs(out_dir, exist_ok=True)
        pub_path, priv_path = save_keypair(
            keypair, out_dir, name=str(data.get("name") or "forjiang"), password=password
        )
        self._send_json({
            "ok": True,
            "bits": bits,
            "pub": pub_path,
            "priv": priv_path,
            "encrypted": bool(password),
        })

    def _handle_crypto(self, path, tmpdir):
        body_path = self._read_body_to_file(tmpdir)
        fields, files = extract_multipart(
            body_path, self.headers.get("Content-Type"), tmpdir
        )
        uploads = files.get("files") or files.get("files[]")
        if not uploads:
            raise ValueError("没有收到文件（字段名应为 files）")

        # 完整版界面：路径必须由用户显式给出，不猜、不默认到服务根目录
        out_dir = (fields.get("outdir") or "").strip()
        if not out_dir:
            raise ValueError("请先选择输出目录（字段 outdir）")
        keep_txt = (fields.get("keep_txt") or "").lower() in ("1", "true", "on", "yes")
        force = (fields.get("force") or "").lower() in ("1", "true", "on", "yes")

        # 先加载密钥，失败就不建输出目录，避免留下空目录
        if path == "/api/encrypt":
            pub_path = (fields.get("pub") or "").strip()
            if not pub_path:
                raise ValueError("缺少公钥路径（字段 pub）")
            pub = load_public_key(pub_path)
        else:
            priv_path = (fields.get("priv") or "").strip()
            if not priv_path:
                raise ValueError("缺少私钥路径（字段 priv）")
            password = (fields.get("password") or "").strip() or None
            priv = load_private_key(priv_path, password=password)

        os.makedirs(out_dir, exist_ok=True)

        if path == "/api/encrypt":
            action = lambda src, name=None: encrypt_uploaded(  # noqa: E731
                src, out_dir, pub, keep_txt=keep_txt, force=force, origin=name
            )
        else:
            action = lambda src, name=None: decrypt_forjiang(  # noqa: E731
                src, out_dir, priv, keep_txt=keep_txt, force=force
            )

        results = []
        ok_count = 0
        for filename, src in uploads:
            entry = {"file": filename}
            try:
                r = action(src, filename)
                entry["ok"] = True
                entry["output"] = r.restored_path or r.output_path
                entry["plain"] = r.original_size
                if path == "/api/encrypt":
                    entry["cipher"] = os.path.getsize(r.output_path)
                if r.txt_path:
                    entry["txt"] = r.txt_path
                ok_count += 1
            except Exception as exc:
                entry["error"] = _per_file_error(exc)
                entry["ok"] = False
            results.append(entry)

        self._send_json({"ok": ok_count == len(results), "results": results})


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------


DATA_DIR_ENV = "FORJIANG_CRYPTO_DATA_DIR"


def _default_data_dir():
    """默认数据目录：优先用户主目录下的 forjiang-crypto，避免把密钥/密文
    写进代码仓库；拿不到可用的主目录时退回服务根目录。

    设了环境变量 FORJIANG_CRYPTO_DATA_DIR 就以它为准（测试、临时换盘、
    多份数据分开存都用得上），省得让使用方往自己的数据目录里塞测试文件。
    """
    override = (os.environ.get(DATA_DIR_ENV) or "").strip()
    if override:
        return os.path.abspath(os.path.expanduser(override))
    try:
        home = os.path.expanduser("~")
    except Exception:
        home = ""
    if home and home != "/" and os.path.isdir(home) and os.access(home, os.W_OK):
        return os.path.join(home, "forjiang-crypto")
    return os.getcwd()


# 子进程里执行的取路脚本：Tk 必须在主线程初始化，所以服务进程自身绝不 import tkinter
# （macOS 上在工作线程 import 会抛 NSInternalInconsistencyException 直接 abort 整个进程）。
# 选中路径以 UTF-8 写到 stdout，中文路径不会乱码；取消时输出为空。
_PICK_CHILD = r"""
import sys
kind, title, initial = sys.argv[1], sys.argv[2], (sys.argv[3] or None)
from tkinter import Tk, filedialog
root = Tk()
root.withdraw()
try:
    root.attributes("-topmost", True)
except Exception:
    pass
if kind == "dir":
    path = filedialog.askdirectory(title=title, initialdir=initial)
else:
    path = filedialog.askopenfilename(
        title=title, initialdir=initial,
        filetypes=[("PEM 密钥文件", "*.pem"), ("所有文件", "*.*")],
    )
sys.stdout.buffer.write((path or "").encode("utf-8"))
sys.stdout.buffer.flush()
"""

_PICK_PROBE_FALSE_TTL = 60.0
_CAN_PICK_CACHE = None   # True＝能用（长期有效）；float＝“不能用”的到期时刻


def _native_picker_available():
    """本环境能否弹系统选择框。用子进程探测，服务进程不 import tkinter。

    探测成功就长期缓存（tkinter 不会自己消失）；失败只短期缓存——否则一次
    偶发的子进程调起失败（句柄紧张、fork 被限流）会让这台机器再也弹不出框，
    而重启服务也看不出原因。到期后重新探，恢复了就自动回来。
    """
    global _CAN_PICK_CACHE
    now = time.monotonic()
    if _CAN_PICK_CACHE is True:
        return True
    if isinstance(_CAN_PICK_CACHE, float) and now < _CAN_PICK_CACHE:
        return False
    try:
        proc = subprocess.run(
            [sys.executable, "-c", "import tkinter"],
            capture_output=True, timeout=30, stdin=subprocess.DEVNULL,
        )
        available = proc.returncode == 0
    except Exception:
        available = False
    _CAN_PICK_CACHE = True if available else now + _PICK_PROBE_FALSE_TTL
    return available


def _native_pick(kind, title="请选择", initial=None):
    """在子进程里弹原生选择框。

    返回 (path, error)。path 为选中路径，用户取消为 None；
    error 为 None 表示子进程正常退出，否则是给用户看的诊断文字
    （尽力透传子进程 stderr——macOS 上 tkinter 缺会话、Linux 上没 DISPLAY，
      只有把原文带出来才查得动，光说"不支持"等于没查）。
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _PICK_CHILD, kind, title, initial or ""],
            capture_output=True, timeout=3600, stdin=subprocess.DEVNULL,
        )
    except Exception as exc:
        return None, f"调起系统选择框失败：{exc}"
    if proc.returncode != 0:
        lines = (proc.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        detail = lines[-1].strip() if lines else f"子进程退出码 {proc.returncode}"
        return None, f"系统选择框调起失败：{detail}"
    return proc.stdout.decode("utf-8", "replace").strip() or None, None


def make_server(host="127.0.0.1", port=8765):
    """绑定端口；被占用时自动往后找最近的空闲端口（最多试 20 个）。

    不同机器上 8765 可能早被别的程序占了，双击启动器不该因此打不开，
    所以这里让端口自适应：先在 bind 前用同一个 socket 探测是否可听。
    """
    last = None
    for candidate in range(port, port + PORT_SEARCH_SPAN):
        try:
            return ThreadingHTTPServer((host, candidate), Handler)
        except OSError as exc:
            last = exc
            if exc.errno != errno.EADDRINUSE:
                raise
    raise last if last else OSError(f"端口 {port}-{port + PORT_SEARCH_SPAN - 1} 均不可用")


def serve(host="127.0.0.1", port=8765, open_browser=False):
    try:
        httpd = make_server(host, port)
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            url = f"http://{host}:{port}/"
            print(f"错误：端口 {port}-{port + PORT_SEARCH_SPAN - 1} 都已被占用，无法启动新的服务。",
                  file=sys.stderr)
            print(f"如果 forjiang-crypto 界面已经在运行，直接访问 {url} 即可；", file=sys.stderr)
            print("确认要再起一个就换一段端口：python3 -m webui --port 9000", file=sys.stderr)
            return 2
        raise
    url = f"http://{host}:{httpd.server_address[1]}/"
    if httpd.server_address[1] != port:
        print(f"提示：端口 {port} 已被其他程序占用，已自动改用 {httpd.server_address[1]}。")
    print(f"forjiang-crypto Web UI 已启动: {url}")
    print("仅监听本机回环地址；Ctrl-C 停止。")
    if open_browser:
        import webbrowser

        # 无图形会话/没装浏览器的机器（SSH、精简 Linux、容器）webbrowser 打不开，
        # 那就把地址显式打出来，别让用户以为服务没起来。
        try:
            browser = webbrowser.get()
        except webbrowser.Error:
            browser = None
        if browser is None or type(browser).__name__ in ("TextBrowser", "BackgroundBrowser"):
            print(f"当前环境没有可用的图形浏览器，请手动访问: {url}")
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        httpd.server_close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="forjiang-webui",
        description="forjiang-crypto 的本地 Web 界面（AES-256-GCM + 公钥加密）",
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="监听地址（默认仅本机回环，改成 0.0.0.0 会暴露给局域网，慎用）")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    args = parser.parse_args(argv)
    return serve(args.host, args.port, open_browser=args.open)
