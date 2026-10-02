"""CLI 子进程测试：python3 -m forjiang_crypto 的真实调用。"""

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def run(*argv, env=None, input_text=None):
    e = dict(os.environ)
    e["PYTHONPATH"] = ROOT
    if env:
        e.update(env)
    return subprocess.run(
        [sys.executable, "-m", "forjiang_crypto", *argv],
        capture_output=True,
        text=True,
        input=input_text,
        env=e,
        timeout=120,
    )


class TestCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="forjiang-cli-")

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def test_full_flow_with_password(self):
        uploads = self.path("uploads")
        vault = self.path("vault")
        back = self.path("restored")
        os.makedirs(uploads)
        with open(self.path("uploads", "a.txt"), "w") as fh:
            fh.write("内容 A" * 1000)
        with open(self.path("uploads", "b.dat"), "wb") as fh:
            fh.write(os.urandom(5000))

        r = run("keygen", "--out", self.path("keys"), "--bits", "2048",
                "--password", "pw123")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(self.path("keys", "forjiang.priv.pem")))

        r = run("encrypt", uploads, "--pub", self.path("keys", "forjiang.pub.pem"),
                "--out", vault, "--quiet")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.isfile(self.path("vault", "a.txt.forjiang")))
        self.assertTrue(os.path.isfile(self.path("vault", "b.dat.forjiang")))
        self.assertFalse(os.path.exists(self.path("vault", "a.txt.txt")))

        # 无口令 -> 交互式提示; 非 tty 下读不到口令 -> 明确失败而非 traceback
        r = run("decrypt", vault, "--priv", self.path("keys", "forjiang.priv.pem"),
                "--out", back, input_text="")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("口令", r.stderr)

        r = run("decrypt", vault, "--priv", self.path("keys", "forjiang.priv.pem"),
                "--out", back, "--password-env", "FJ_PW",
                env={"FJ_PW": "pw123"})
        self.assertEqual(r.returncode, 0, r.stderr)
        for name in ("a.txt", "b.dat"):
            with open(self.path("uploads", name), "rb") as f1:
                with open(self.path("restored", name), "rb") as f2:
                    self.assertEqual(f1.read(), f2.read(), name)

    def test_decrypt_missing_file_clean_error(self):
        r = run("decrypt", self.path("nope.forjiang"), "--priv", "/dev/null")
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("错误", r.stderr)

    def test_decrypt_garbage_file(self):
        junk = self.path("junk.forjiang")
        with open(junk, "wb") as fh:
            fh.write(b"not a forjiang file" * 10)
        r0 = run("keygen", "--out", self.path("keys4"))
        self.assertEqual(r0.returncode, 0, r0.stderr)
        r = run("decrypt", junk, "--priv", self.path("keys4", "forjiang.priv.pem"))
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("魔数不匹配", r.stderr)

    def test_encrypt_duplicate_then_force(self):
        uploads = self.path("up2")
        vault = self.path("v2")
        os.makedirs(uploads)
        with open(self.path("up2", "x.bin"), "wb") as fh:
            fh.write(os.urandom(64))
        kp = run("keygen", "--out", self.path("keys2"))
        self.assertEqual(kp.returncode, 0, kp.stderr)
        pub = self.path("keys2", "forjiang.pub.pem")

        r1 = run("encrypt", uploads, "--pub", pub, "--out", vault, "--quiet")
        self.assertEqual(r1.returncode, 0, r1.stderr)
        r2 = run("encrypt", uploads, "--pub", pub, "--out", vault, "--quiet")
        self.assertEqual(r2.returncode, 1)  # 已存在, 拒绝覆盖
        r3 = run("encrypt", uploads, "--pub", pub, "--out", vault, "--quiet", "--force")
        self.assertEqual(r3.returncode, 0, r3.stderr)

    def test_keep_txt_flag(self):
        uploads = self.path("up3")
        vault = self.path("v3")
        os.makedirs(uploads)
        with open(self.path("up3", "p.png"), "wb") as fh:
            fh.write(os.urandom(32))
        r = run("keygen", "--out", self.path("keys3"))
        self.assertEqual(r.returncode, 0, r.stderr)
        pub = self.path("keys3", "forjiang.pub.pem")
        r = run("encrypt", uploads, "--pub", pub, "--out", vault, "--keep-txt", "--quiet")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(self.path("v3", "p.png.txt"), "rb") as fh:
            self.assertEqual(len(fh.read()), 32)

    def test_one_unreadable_file_does_not_abort_batch(self):
        """一个读不了的文件只能让它自己失败，其余文件必须照常处理。

        实测踩坑：早期 cmd_encrypt/cmd_decrypt 只捕 FileExistsError 与
        ForjiangCryptoError，权限/写盘类的 OSError 会抛穿到 main() 之外，
        整批中断——一个怪文件就毁掉一次批量加密。
        """
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root 下 chmod 000 仍可读，测不出权限失败")
        uploads = self.path("up4")
        vault = self.path("v4")
        os.makedirs(uploads)
        for name in ("a.txt", "b.txt", "c.txt"):
            with open(self.path("up4", name), "wb") as fh:
                fh.write(name.encode())
        locked = self.path("up4", "b.txt")
        os.chmod(locked, 0)
        try:
            kp = run("keygen", "--out", self.path("keys4"))
            self.assertEqual(kp.returncode, 0, kp.stderr)
            pub = self.path("keys4", "forjiang.pub.pem")
            r = run("encrypt", uploads, "--pub", pub, "--out", vault, "--quiet")
            # 有失败项时退出码非 0（诚实报告），但不能是裸 traceback
            self.assertNotEqual(r.returncode, 0)
            self.assertNotIn("Traceback", r.stderr)
            self.assertIn("b.txt", r.stderr)
            # 其余两个文件必须真的落盘
            self.assertTrue(os.path.exists(self.path("v4", "a.txt.forjiang")))
            self.assertTrue(os.path.exists(self.path("v4", "c.txt.forjiang")))
        finally:
            os.chmod(locked, 0o644)
            r2 = run("decrypt", vault, "--priv", self.path("keys4", "forjiang.priv.pem"),
                     "--out", self.path("back4"), "--quiet")
            # 解密同一批：跳过读不了的，好的两个照常还原
            self.assertNotIn("Traceback", r2.stderr)
            self.assertTrue(os.path.exists(self.path("back4", "a.txt")))
            self.assertTrue(os.path.exists(self.path("back4", "c.txt")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
