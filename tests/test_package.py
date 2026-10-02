"""package.py 打包脚本测试：版本规则与排除规则。

运行：python3 tests/test_package.py
"""

import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import package as pkg  # noqa: E402


def fake_tree(base):
    """造一棵含常见垃圾目录的临时项目树，返回其根目录。"""
    src = os.path.join(base, "src")
    os.makedirs(os.path.join(src, ".venv", "bin"))
    os.makedirs(os.path.join(src, "venv", "bin"))
    os.makedirs(os.path.join(src, "node_modules", "left-pad"))
    os.makedirs(os.path.join(src, "__pycache__"))
    os.makedirs(os.path.join(src, ".git"))
    os.makedirs(os.path.join(src, "forjiang_crypto"))
    with open(os.path.join(src, "forjiang_crypto", "__init__.py"), "w") as fh:
        fh.write("")
    with open(os.path.join(src, "requirements.txt"), "w") as fh:
        fh.write("")
    for junk in ((".venv/bin/big.so", 1024), ("venv/bin/libpython.so", 512),
                 ("node_modules/left-pad/index.js", 64),
                 ("__pycache__/x.pyc", 32), (".git/config", 16),
                 ("package.zip", 8)):
        with open(os.path.join(src, *junk[0].split("/")), "w") as fh:
            fh.write("x" * junk[1])
    return src


class TestPackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="forjiang-pkg-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        # 每个测试一棵独立的树，避免重复建目录
        self.src = fake_tree(tempfile.mkdtemp(prefix="forjiang-pkg-tree-",
                                              dir=self.tmp))
        self.old_root = pkg.ROOT
        pkg.ROOT = self.src

    def tearDown(self):
        pkg.ROOT = self.old_root

    def files(self):
        return [os.path.relpath(f, self.src)
                for f in pkg.iter_files()]

    def test_excludes_junk_directories(self):
        """启动器的 .venv 兜底会在项目里留一个几百 MB 的虚拟环境，
        不排除会把发布包撑爆。"""
        rels = self.files()
        for banned in ("node_modules", "__pycache__", ".git"):
            self.assertFalse(any(banned in r for r in rels),
                             f"打包带进了 {banned}: {rels}")
        self.assertTrue(all(not r.endswith(".zip") for r in rels), rels)
        self.assertIn("forjiang_crypto/__init__.py", rels)
        self.assertIn("requirements.txt", rels)

    def test_venv_excluded(self):
        rels = self.files()
        self.assertFalse(any(r.startswith(".venv") or r.startswith("venv")
                             for r in rels), rels)

    def test_bump_stays_in_series(self):
        """同系列第三位 +1，且永不小于已有包里的最大第三位。"""
        out = os.path.join(self.tmp, "out")
        os.makedirs(out, exist_ok=True)
        old_versions = pkg.read_versions
        try:
            pkg.read_versions = lambda: (1, 1, 0)
            self.assertEqual(pkg.bump(out), (1, 1, 1))       # 无同系列包
            open(os.path.join(out, "forjiang-crypto-1.1.5.zip"), "w").close()
            open(os.path.join(out, "forjiang-crypto-1.0.9.zip"), "w").close()
            self.assertEqual(pkg.bump(out), (1, 1, 6))       # 取同系列最大 +1
            pkg.read_versions = lambda: (1, 1, 3)
            self.assertEqual(pkg.bump(out), (1, 1, 6))       # 不会回退到 4
        finally:
            pkg.read_versions = old_versions

    def test_launcher_names_detected(self):
        self.assertTrue(pkg.name_is_launcher("打开网页界面.command"))
        self.assertTrue(pkg.name_is_launcher("start-webui.bat"))
        self.assertFalse(pkg.name_is_launcher("server.py"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
