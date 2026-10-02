"""Web 界面端到端测试：真实起服务、真实发 multipart 请求。

运行：python3 tests/test_webui.py
"""

import contextlib
import http.client
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from urllib.parse import quote  # noqa: E402

import webui.server as webui_server  # noqa: E402
from webui.server import make_server, serve  # noqa: E402


def cryptographic_magic(text):
    return text.encode()


BOUNDARY = "----forjiangtestboundary"


def build_multipart(fields, file_parts):
    """fields: {名: 值}; file_parts: [(字段名, 文件名, 字节)]，可多个同名段。"""
    body = b""
    for name, value in fields.items():
        body += (
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
        ).encode() + value.encode() + b"\r\n"
    for name, filename, data in file_parts:
        body += (
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + b"\r\n"
    body += f"--{BOUNDARY}--\r\n".encode()
    return body, f"multipart/form-data; boundary={BOUNDARY}"


class WebUIBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = make_server("127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)
        cls.tmp = tempfile.mkdtemp(prefix="forjiang-webui-test-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def conn(self):
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)

    def get(self, path):
        c = self.conn()
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, body

    def post_json(self, path, obj):
        c = self.conn()
        payload = json.dumps(obj).encode()
        c.request("POST", path, body=payload,
                  headers={"Content-Type": "application/json"})
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, json.loads(body.decode("utf-8"))

    def post_files(self, path, fields, file_parts):
        body, ctype = build_multipart(fields, file_parts)
        c = self.conn()
        c.request("POST", path, body=body,
                  headers={"Content-Type": ctype, "Content-Length": str(len(body))})
        r = c.getresponse()
        raw = r.read()
        c.close()
        return r.status, json.loads(raw.decode("utf-8"))

    def path(self, *p):
        return os.path.join(self.tmp, *p)


class TestWebUI(WebUIBase):
    def test_index_page(self):
        # 默认落地页是简版；完整版在 /full
        status, body = self.get("/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn("forjiang-crypto 加密系统", html)
        self.assertIn("/api/simple/encrypt", html)
        self.assertIn("/api/simple/decrypt", html)
        self.assertIn('href="/full"', html)
        self.assertIn("prefers-color-scheme: dark", html)  # 简版同样支持深浅色

        status, body = self.get("/full")
        self.assertEqual(status, 200)
        self.assertIn("forjiang-crypto", body.decode("utf-8"))
        status, body = self.get("/index.html")
        self.assertEqual(status, 200)
        # 防回归：完整版页面的接口地址必须和服务端路由一致
        # （曾出现把 "/api/" + "enc" 拼成 /api/enc 导致界面按钮全部 404）
        full = body.decode("utf-8")
        for endpoint in ("/api/keygen", "/api/encrypt", "/api/decrypt", "/api/config"):
            self.assertIn(endpoint, full)
        self.assertNotIn('"/api/" + ', full)
        self.assertNotIn("getElementById(\"btn-\" + ", full)
        self.assertIn('href="/simple"', full)  # 完整版要能回到简版

    def test_full_page_does_not_prefill_paths(self):
        """完整版路径一律不预填，由用户自己选；只有按钮能一键填入。"""
        status, body = self.get("/full")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        for fid in ("keydir", "enc-pub", "enc-out", "dec-priv", "dec-out"):
            self.assertIn(f'id="{fid}"', html)
            self.assertNotIn(f'id="{fid}" value', html)   # 不预填
            self.assertIn(f'id="{fid}" placeholder', html)  # 有“未选择”提示
        self.assertIn("填入默认路径", html)
        # 页面加载时不得自动填默认（fillDefaults 只能由按钮触发）
        self.assertIn("fillDefaults", html)
        self.assertNotIn("applyDefaults", html)

    def test_full_api_requires_explicit_outdir(self):
        """完整版接口：outdir 为空必须报错，不能默认写到服务根目录。"""
        payload = b"x" * 32
        body, ctype = build_multipart(
            {"pub": "/nonexistent.pem", "outdir": ""},
            [("files", "a.txt", payload)],
        )
        c = self.conn()
        c.request("POST", "/api/encrypt", body=body,
                  headers={"Content-Type": ctype, "Content-Length": str(len(body))})
        r = c.getresponse()
        raw = r.read()
        c.close()
        self.assertEqual(r.status, 400)
        self.assertIn("输出目录", json.loads(raw.decode())["error"])

    def test_buttons_are_grouped_not_adjacent(self):
        """成排按钮必须包在 flex 容器里。

        HTML 标签间的换行会被渲染成一个空格（约 6px 间隙），直接相邻的两个
        button 因此看起来比别的方块间距小；包进 .btnrow（display:flex; gap:
        var(--gap)）后空白文本节点被忽略，间距才和别人一致。
        """
        import re
        for url in ("/", "/full"):
            status, body = self.get(url)
            self.assertEqual(status, 200)
            self.assertIn(".btnrow", body.decode("utf-8"))
        # 完整版的“生成密钥对/填入默认路径”必须在同一个 .btnrow 里
        status, body = self.get("/full")
        m = re.search(r'<div class="btnrow">(.*?)</div>', body.decode("utf-8"), re.S)
        self.assertIsNotNone(m, "操作按钮应包在 .btnrow 里")
        self.assertIn("btn-keygen", m.group(1))
        self.assertIn("btn-reset", m.group(1))

    def test_controls_share_uniform_height_and_gap(self):
        """所有控件等高、横向间距统一（用户明确要求的整齐度）。"""
        for url in ("/", "/full"):
            status, body = self.get(url)
            self.assertEqual(status, 200)
            html = body.decode("utf-8")
            self.assertIn("--ctrl-h:", html)
            self.assertIn("--gap:", html)
            self.assertIn("height: var(--ctrl-h)", html)
            # 行内间距不许再出现写死的 8px
            self.assertNotIn("gap: 8px", html)

    def test_config(self):
        status, body = self.get("/api/config")
        self.assertEqual(status, 200)
        cfg = json.loads(body.decode())
        self.assertIn("root", cfg)
        # 默认数据目录：绝对路径，用于把密钥/密文引出代码仓库
        self.assertTrue(os.path.isabs(cfg["dataDir"]), cfg)
        # 是否支持系统原生选择框（供前端决定显示“浏览…”按钮）
        self.assertIn("canPick", cfg)

    def test_server_never_imports_tkinter(self):
        """服务进程内绝不能 import tkinter。

        macOS 上在工作线程里 import tkinter 会触发 Tk 初始化，
        抛 NSInternalInconsistencyException 直接 abort 整个服务进程。
        选择框一律走子进程实现。
        """
        import webui.server  # noqa: F401
        self.assertNotIn("tkinter", sys.modules)
        self.assertNotIn("_tkinter", sys.modules)

    def test_pick_probe_does_not_open_dialog(self):
        """probe 模式只探测、绝不弹框——弹框会阻塞请求，测试里绝不能触发。"""
        status, result = self.post_json("/api/pick", {"kind": "dir", "probe": True})
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"])
        self.assertIn("canPick", result)
        # 探测走了子进程，服务进程依然干净
        self.assertNotIn("tkinter", sys.modules)

    def test_pick_bad_kind(self):
        status, result = self.post_json("/api/pick", {"kind": "weird"})
        self.assertEqual(status, 400)
        self.assertIn("error", result)

    def test_index_has_pickers(self):
        status, body = self.get("/full")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn("/api/pick", html)
        # 五个路径字段都要有浏览按钮
        self.assertEqual(html.count('class="browse"'), 5)
        for field in ("keydir", "enc-pub", "enc-out", "dec-priv", "dec-out"):
            self.assertIn(f'data-for="{field}"', html)
        # 加密区支持整个文件夹输入
        self.assertIn("enc-dirmode", html)
        self.assertIn("webkitdirectory", html)

    def test_index_supports_dark_mode(self):
        """深浅色自适应：prefers-color-scheme + 变量化配色，且没有写死的浅色值。"""
        status, body = self.get("/full")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn("prefers-color-scheme: dark", html)
        self.assertIn("color-scheme: light dark", html)
        for var in ("--bg", "--fg", "--border", "--panel-bg", "--btn-bg"):
            self.assertIn(var, html)
        # 样式里不应再出现写死的浅色背景/文字色（用变量替代）
        for stale in ("background: #fff;", "background: #f5f5f5;",
                      "background: #fafafa;", "color: #1a1a1a;", "color: #666;"):
            self.assertNotIn(stale, html)

    def test_unknown_path(self):
        status, body = self.get("/nope")
        self.assertEqual(status, 404)
        self.assertIn("error", json.loads(body.decode()))

    def test_keygen_and_roundtrip(self):
        keys = self.path("keys")
        status, data = self.post_json("/api/keygen", {
            "bits": 2048, "outdir": keys, "name": "u",
        })
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"])
        self.assertTrue(os.path.isfile(os.path.join(keys, "u.pub.pem")))
        self.assertTrue(os.path.isfile(os.path.join(keys, "u.priv.pem")))

        uploads = self.path("uploads")
        vault = self.path("vault")
        back = self.path("back")
        os.makedirs(uploads)

        contents = {
            "note.txt": "你好，forjiang" * 100,
            "blob.dat": os.urandom(20000),
            "crlf.bin": b"\r\n--fake\r\nboundary-ish\r\n\r\n" * 50,
        }
        for name, content in contents.items():
            with open(os.path.join(uploads, name), "wb") as fh:
                fh.write(content.encode("utf-8") if isinstance(content, str) else content)

        parts = []
        for name in contents:
            content = contents[name]
            if isinstance(content, str):
                content = content.encode("utf-8")
            parts.append(("files", name, content))
        status, result = self.post_files(
            "/api/encrypt",
            {"pub": os.path.join(keys, "u.pub.pem"), "outdir": vault},
            parts,
        )
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["results"]), 3)
        for name in contents:
            self.assertTrue(os.path.isfile(os.path.join(vault, name + ".forjiang")), name)
        self.assertFalse(os.path.exists(os.path.join(vault, "note.txt.txt")))

        with open(os.path.join(vault, "blob.dat.forjiang"), "rb") as fh:
            blob_ct = fh.read()
        with open(os.path.join(vault, "note.txt.forjiang"), "rb") as fh:
            note_ct = fh.read()
        with open(os.path.join(vault, "crlf.bin.forjiang"), "rb") as fh:
            crlf_ct = fh.read()
        status, result = self.post_files(
            "/api/decrypt",
            {"priv": os.path.join(keys, "u.priv.pem"), "outdir": back},
            [("files", "note.txt.forjiang", note_ct),
             ("files", "blob.dat.forjiang", blob_ct),
             ("files", "crlf.bin.forjiang", crlf_ct)],
        )
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"], result)
        for name in contents:
            with open(os.path.join(uploads, name), "rb") as f1:
                with open(os.path.join(back, name), "rb") as f2:
                    self.assertEqual(f1.read(), f2.read(), name)

    def test_decrypt_with_password(self):
        keys = self.path("keys2")
        st, data = self.post_json("/api/keygen", {
            "bits": 2048, "outdir": keys, "name": "p", "password": "pw-123456",
        })
        self.assertTrue(data.get("encrypted"))

        vault = self.path("vault2")
        os.makedirs(vault)
        payload = b"secret payload"
        status, result = self.post_files(
            "/api/encrypt",
            {"pub": os.path.join(keys, "p.pub.pem"), "outdir": vault},
            [("files", "plain2.bin", payload)],
        )
        self.assertTrue(result["ok"], result)
        with open(os.path.join(vault, "plain2.bin.forjiang"), "rb") as fh:
            ct = fh.read()

        # 口令错误：私钥加载阶段整体报错，服务不挂，也不写任何文件
        status, result = self.post_files(
            "/api/decrypt",
            {"priv": os.path.join(keys, "p.priv.pem"),
             "outdir": self.path("back2a"), "password": "wrong"},
            [("files", "plain2.bin.forjiang", ct)],
        )
        self.assertFalse(result["ok"])
        self.assertIn("口令", result["error"])
        self.assertFalse(os.path.exists(self.path("back2a")))

        # 口令正确
        status, result = self.post_files(
            "/api/decrypt",
            {"priv": os.path.join(keys, "p.priv.pem"),
             "outdir": self.path("back2b"), "password": "pw-123456"},
            [("files", "plain2.bin.forjiang", ct)],
        )
        self.assertTrue(result["ok"], result)
        with open(self.path("back2b", "plain2.bin"), "rb") as fh:
            self.assertEqual(fh.read(), payload)

    def test_keep_txt_flag(self):
        keys = self.path("keys3")
        self.post_json("/api/keygen", {"bits": 2048, "outdir": keys, "name": "k"})
        vault = self.path("vault3")
        os.makedirs(vault)
        status, result = self.post_files(
            "/api/encrypt",
            {"pub": os.path.join(keys, "k.pub.pem"), "outdir": vault, "keep_txt": "1"},
            [("files", "keepme.png", os.urandom(3000))],
        )
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["results"][0].get("txt"))
        self.assertTrue(os.path.isfile(os.path.join(vault, "keepme.png.txt")))

    def test_port_in_use_auto_moves_to_next_free(self):
        """端口被占用时自动往后找空闲端口，服务照样能起来（双击启动器不该因此打不开）。"""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        try:
            httpd = make_server("127.0.0.1", port)
        finally:
            blocker.close()
        try:
            bound = httpd.server_address[1]
            self.assertNotEqual(bound, port)
            # 必须在 port .. port+PORT_SEARCH_SPAN-1 之间，且确实是空闲的那个
            self.assertLessEqual(bound, port + webui_server.PORT_SEARCH_SPAN - 1)
            self.assertGreater(bound, port)
            # 起得来的服务要真的能回话
            t = threading.Thread(target=httpd.serve_forever, daemon=True)
            t.start()
            conn = http.client.HTTPConnection("127.0.0.1", bound, timeout=5)
            conn.request("GET", "/api/config")
            body = json.loads(conn.getresponse().read().decode())
            conn.close()
            self.assertIn("version", body)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_port_swap_message_printed(self):
        """自动换端口时要明确告诉用户用了哪个端口，否则用户会连不上。"""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        buf = io.StringIO()
        real_forever = webui_server.ThreadingHTTPServer.serve_forever
        try:
            with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
                webui_server.ThreadingHTTPServer.serve_forever = \
                    lambda self: (_ for _ in ()).throw(KeyboardInterrupt())
                try:
                    rc = serve("127.0.0.1", port)
                finally:
                    webui_server.ThreadingHTTPServer.serve_forever = real_forever
        finally:
            blocker.close()
        self.assertEqual(rc, 0)
        msg = buf.getvalue()
        self.assertIn("已自动改用", msg)
        self.assertIn(f"端口 {port} 已被其他程序占用", msg)
        # 换用的端口也必须出现在输出里
        m = re.search(r"已自动改用 (\d+)", msg)
        self.assertIsNotNone(m)
        self.assertGreater(int(m.group(1)), port)

    def test_all_ports_taken_still_friendly_error(self):
        """整段端口都被占满时仍然是友好提示返回 2，不是裸 traceback。"""
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                real_span = webui_server.PORT_SEARCH_SPAN
                webui_server.PORT_SEARCH_SPAN = 1
                try:
                    rc = serve("127.0.0.1", port)
                finally:
                    webui_server.PORT_SEARCH_SPAN = real_span
        finally:
            blocker.close()
        self.assertEqual(rc, 2)
        msg = buf.getvalue()
        self.assertIn("已被占用", msg)
        self.assertIn(str(port), msg)

    def test_simple_encrypt_decrypt_roundtrip(self):
        """简版界面全流程：加密 -> 下载 -> 解密 -> 内容一致。"""
        data = os.urandom(3000) + "中文内容测试".encode()
        status, result = self.post_files(
            "/api/simple/encrypt",
            {"password": "pw-123456"},
            [("files", "简版测试.txt", data)],
        )
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"], result)
        out = result["results"][0]["output"]
        self.assertTrue(out.endswith("简版测试.txt.forjiang"))
        self.assertIn(cryptographic_magic("FJGPASS1"), open(out, "rb").read(8))

        # /api/download 只服务本次会话登记的产物
        c = self.conn()
        c.request("GET", "/api/download?path=" + quote(out))
        r = c.getresponse()
        body = r.read()
        c.close()
        self.assertEqual(r.status, 200)
        self.assertEqual(len(body), os.path.getsize(out))

        c = self.conn()
        c.request("GET", "/api/download?path=/etc/passwd")
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 404, "不得下发未登记的任意文件")

        status, result = self.post_files(
            "/api/simple/decrypt",
            {"password": "pw-123456"},
            [("files", "简版测试.txt.forjiang", open(out, "rb").read())],
        )
        self.assertEqual(status, 200, result)
        restored = result["results"][0]["output"]
        self.assertEqual(os.path.basename(restored), "简版测试.txt")
        with open(restored, "rb") as fh:
            self.assertEqual(fh.read(), data)

    def test_simple_wrong_password(self):
        data = b"secret payload " * 50
        status, result = self.post_files(
            "/api/simple/encrypt", {"password": "right-one"},
            [("files", "wp.bin", data)],
        )
        self.assertTrue(result["ok"], result)
        ct = open(result["results"][0]["output"], "rb").read()
        status, result = self.post_files(
            "/api/simple/decrypt", {"password": "wrong-one"},
            [("files", "wp.bin.forjiang", ct)],
        )
        self.assertEqual(status, 200)
        self.assertFalse(result["results"][0]["ok"])
        self.assertIn("密码", result["results"][0]["error"])

    def test_simple_password_too_short(self):
        status, result = self.post_files(
            "/api/simple/encrypt", {"password": "123"},
            [("files", "a.txt", b"data")],
        )
        self.assertEqual(status, 400)
        self.assertIn("至少", result["error"])

    def test_simple_rejects_second_encryption(self):
        status, result = self.post_files(
            "/api/simple/encrypt", {"password": "pw-123456"},
            [("files", "x.forjiang", b"already encrypted")],
        )
        self.assertEqual(status, 200)
        self.assertFalse(result["results"][0]["ok"])

    def test_simple_multiple_files_and_folder_flatten(self):
        """简版：一次多文件 + 文件夹扁平化命名（重名不互相覆盖）。"""
        payloads = {
            "a.txt": b"alpha " * 50,
            "b.bin": os.urandom(4000),
            "sub_c.txt": b"gamma " * 30,     # 模拟 子目录/c.txt 扁平化后的名字
        }
        status, result = self.post_files(
            "/api/simple/encrypt", {"password": "pw-123456"},
            [( "files", n, d) for n, d in payloads.items()],
        )
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"], result)
        self.assertEqual(len(result["results"]), 3)
        outs = {}
        for item in result["results"]:
            self.assertTrue(item["ok"], item)
            outs[item["file"]] = item["output"]

        # 解密回来，逐个核对
        status, result = self.post_files(
            "/api/simple/decrypt", {"password": "pw-123456"},
            [("files", n + ".forjiang", open(outs[n], "rb").read()) for n in payloads],
        )
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"], result)
        for item in result["results"]:
            name = item["output"].split("/")[-1]
            with open(item["output"], "rb") as fh:
                self.assertEqual(fh.read(), payloads[name], name)

    def test_simple_same_name_in_one_batch_does_not_overwrite(self):
        """同一批里两个同名文件：必须都保留（加后缀），不能静默互相覆盖。"""
        status, result = self.post_files(
            "/api/simple/encrypt", {"password": "pw-123456"},
            [("files", "dup.txt", "第一个".encode()),
             ("files", "dup.txt", "第二个，内容不同".encode())],
        )
        self.assertEqual(status, 200, result)
        outs = [r["output"] for r in result["results"]]
        self.assertEqual(len(set(outs)), 2, f"两个同名文件应产生两个不同产物: {outs}")
        self.assertTrue(all(os.path.isfile(p) for p in outs))

        status, result = self.post_files(
            "/api/simple/decrypt", {"password": "pw-123456"},
            [("files", os.path.basename(p), open(p, "rb").read()) for p in outs],
        )
        self.assertEqual(status, 200, result)
        restored = {}
        for item in result["results"]:
            with open(item["output"], "rb") as fh:
                restored[os.path.basename(item["output"])] = fh.read()
        self.assertEqual(len(restored), 2, f"解密后也应是两个不同文件: {list(restored)}")
        self.assertIn("第一个".encode(), restored.values())
        self.assertIn("第二个，内容不同".encode(), restored.values())

    def test_simple_partial_failure_reported_per_file(self):
        """批量里混入非法文件：其他文件照常成功，失败项单独报告。"""
        status, result = self.post_files(
            "/api/simple/encrypt", {"password": "pw-123456"},
            [("files", "good.txt", b"good data"),
             ("files", "bad.forjiang", b"already encrypted")],
        )
        self.assertEqual(status, 200, result)
        self.assertFalse(result["ok"])
        by_name = {r["file"]: r for r in result["results"]}
        self.assertTrue(by_name["good.txt"]["ok"])
        self.assertFalse(by_name["bad.forjiang"]["ok"])
        self.assertIn("已经是", by_name["bad.forjiang"]["error"])

    def test_simple_folder_mode_encrypt_and_zip(self):
        """简版文件夹模式：服务端遍历目录批量加密，产物打成单个 zip。"""
        src = self.path("srcfolder")
        os.makedirs(os.path.join(src, "sub"), exist_ok=True)
        payloads = {
            "a.txt": b"alpha content",
            "b.bin": os.urandom(2000),
            os.path.join("sub", "a.txt"): "子目录里的 a".encode(),
            os.path.join("sub", "c.dat"): b"gamma " * 100,
            "already.forjiang": "已加密的应被跳过".encode(),
        }
        for rel, data in payloads.items():
            with open(os.path.join(src, rel), "wb") as fh:
                fh.write(data)

        status, result = self.post_json(
            "/api/simple/encrypt", {"password": "pw-123456", "folder": src})
        self.assertEqual(status, 200, result)
        self.assertTrue(result["ok"], result)
        names = [r["file"] for r in result["results"]]
        self.assertIn("a.txt", names)
        self.assertIn(os.path.join("sub", "a.txt"), names)
        self.assertNotIn("already.forjiang", names, "已加密文件应被跳过")
        self.assertIn("zip", result)
        self.assertTrue(os.path.isfile(result["zip"]))
        import zipfile as _zf
        with _zf.ZipFile(result["zip"]) as zf:
            self.assertGreaterEqual(len(zf.namelist()), 4)

        # 文件夹模式解密：zip 里应含还原后的原文件
        dec_dir = self.path("decfolder")
        os.makedirs(dec_dir)
        with open(os.path.join(dec_dir, "a.txt.forjiang"), "wb") as fh:
            fh.write(payloads["a.txt"])
        with open(os.path.join(dec_dir, "note.md"), "wb") as fh:
            fh.write("非 forjiang 应被忽略".encode())
        # 造一个真的密码模式密文放进去
        from forjiang_crypto import password_encrypt_file as _enc
        _enc(self.path("srcfolder", "b.bin"),
             os.path.join(dec_dir, "b.bin.forjiang"), "pw-123456")
        status, result = self.post_json(
            "/api/simple/decrypt", {"password": "pw-123456", "folder": dec_dir})
        self.assertEqual(status, 200, result)
        by_name = {r["file"]: r for r in result["results"]}
        # 只收集 .forjiang；a.txt.forjiang 是假密文，应逐文件报错而不影响其他
        self.assertEqual(set(by_name), {"a.txt.forjiang", "b.bin.forjiang"})
        self.assertNotIn("note.md", by_name)
        self.assertFalse(by_name["a.txt.forjiang"]["ok"])
        self.assertTrue(by_name["b.bin.forjiang"]["ok"], by_name)
        self.assertIn("zip", result)
        with open(by_name["b.bin.forjiang"]["output"], "rb") as fh:
            self.assertEqual(fh.read(), payloads["b.bin"])

    def test_simple_files_and_folder_are_exclusive(self):
        payload = b"x" * 32
        body, ctype = build_multipart(
            {"password": "pw-123456", "folder": "/tmp"},
            [("files", "a.txt", payload)],
        )
        c = self.conn()
        c.request("POST", "/api/simple/encrypt", body=body,
                  headers={"Content-Type": ctype, "Content-Length": str(len(body))})
        r = c.getresponse()
        raw = r.read()
        c.close()
        self.assertEqual(r.status, 400)
        self.assertIn("只能选一种", json.loads(raw.decode())["error"])

    def test_simple_folder_missing(self):
        status, result = self.post_json(
            "/api/simple/encrypt", {"password": "pw-123456", "folder": "/no/such/dir"})
        self.assertEqual(status, 400)
        self.assertIn("文件夹不存在", result["error"])

    def test_simple_page_has_folder_rows(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        html = body.decode("utf-8")
        self.assertIn('id="enc-folder"', html)
        self.assertIn('id="dec-folder"', html)
        self.assertIn('data-for="enc-folder"', html)
        self.assertIn('data-for="dec-folder"', html)
        self.assertNotIn("dirmode", html)  # 勾选方式已移除

    def test_bad_requests(self):
        c = self.conn()
        c.request("POST", "/api/encrypt", body=b"", headers={"Content-Length": "0"})
        r = c.getresponse()
        body = json.loads(r.read().decode())
        c.close()
        self.assertEqual(r.status, 400)
        self.assertIn("error", body)

        # 合法 multipart 但没有 files 字段 -> 业务错误，不挂
        status, result = self.post_files("/api/encrypt", {"pub": "x"}, [])
        self.assertEqual(status, 400)
        self.assertIn("files", result["error"])


class TestLaunchers(unittest.TestCase):
    """双击启动器的依赖安装兜底链。

    实测踩过的坑：用户的 Python 被 uv 接管后，`python3 -m pip install` 直接
    被拒（PEP 668 `externally-managed-environment`），启动器只会这一条命令，
    于是第一次双击就卡死在安装步骤。这里把逐级兜底锁进测试，防止回归。
    """

    def setUp(self):
        with open(os.path.join(ROOT, "打开网页界面.command"), encoding="utf-8") as fh:
            self.mac = fh.read()
        with open(os.path.join(ROOT, "start-webui.bat"), encoding="utf-8") as fh:
            self.win = fh.read()

    def test_mac_launcher_covers_pep668_environments(self):
        for step in (
            "uv pip install --system -r requirements.txt",
            "-m pip install -r requirements.txt",
            "-m pip install --user -r requirements.txt",
            "-m pip install --break-system-packages -r requirements.txt",
            "-m venv .venv",
            ".venv/bin/python",
        ):
            self.assertIn(step, self.mac, f"macOS 启动器缺少安装兜底步骤: {step}")

    def test_mac_launcher_verifies_each_attempt(self):
        # 每一步安装后都必须重新 import 验证，uv 退出码为 0 但环境没装上也不能算成功
        self.assertGreaterEqual(
            self.mac.count('import cryptography" >/dev/null 2>&1'), 5,
            "每次安装尝试后都要重新验证 import cryptography",
        )
        self.assertIn("install_deps", self.mac)

    def test_mac_launcher_last_resort_is_local_venv(self):
        # 全都失败时切到项目本地虚拟环境，并用它继续启动服务
        self.assertIn('PY_BIN="$(pwd)/.venv/bin/python"', self.mac)
        self.assertIn('"$PY_BIN" -u -m webui', self.mac)

    def test_windows_launcher_covers_pep668_environments(self):
        for step in (
            "uv pip install --system -r requirements.txt",
            "-m pip install -r requirements.txt",
            "-m pip install --user -r requirements.txt",
            "-m pip install --break-system-packages -r requirements.txt",
            ".venv\\Scripts\\python.exe",
        ):
            self.assertIn(step, self.win, f"Windows 启动器缺少安装兜底步骤: {step}")

    def test_both_launchers_reuse_existing_local_venv(self):
        # 建过 .venv 之后必须优先复用它，而不是每次重新探测系统 Python
        self.assertIn(".venv/bin/python", self.mac)
        self.assertIn(".venv\\Scripts\\python.exe", self.win)

    def test_failure_message_lists_manual_commands(self):
        self.assertIn("uv pip install --system", self.mac)
        self.assertIn("--break-system-packages", self.mac)
        self.assertIn("uv pip install --system", self.win)

    def test_launchers_force_utf8_output(self):
        """老机器的 locale 可能是 ASCII，中文路径和中文日志会 UnicodeEncodeError。"""
        self.assertIn("PYTHONUTF8=1", self.mac)
        self.assertIn("PYTHONUTF8=1", self.win)

    def test_launchers_run_python_unbuffered(self):
        """端口被自动换掉、服务已启动这些信息要立刻可见，不能被 stdout 缓冲吞掉。"""
        self.assertIn("-u -m webui", self.mac)
        self.assertIn("-u -m webui", self.win)


if __name__ == "__main__":
    unittest.main(verbosity=2)
