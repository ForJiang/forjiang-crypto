"""forjiang-crypto 测试。运行：python3 tests/test_crypto.py"""

import io
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import serialization  # noqa: E402

from forjiang_crypto import (  # noqa: E402
    CHUNK_SIZE,
    SUFFIX,
    is_password_format,
    password_decrypt_file,
    password_encrypt_file,
    TamperError,
    decrypt_file,
    decrypt_forjiang,
    decrypt_stream,
    encrypt_file,
    encrypt_stream,
    encrypt_uploaded,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)
from forjiang_crypto.exceptions import (  # noqa: E402
    DecryptionError,
    HeaderError,
    KeyError_,
    KeyPasswordRequired,
)
from forjiang_crypto.keys import wrap_key  # noqa: E402


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keypair = generate_keypair(2048)
        cls.pub = cls.keypair.public_key
        cls.priv = cls.keypair.private_key
        cls.tmp = tempfile.mkdtemp(prefix="forjiang-test-")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.tmp, name)

    def write(self, name, data=b"hello forjiang"):
        p = self.path(name)
        with open(p, "wb") as fh:
            fh.write(data)
        return p


class TestStreamPrimitives(Base):
    def test_roundtrip_bytesio(self):
        src = io.BytesIO(os.urandom(5000))
        enc = io.BytesIO()
        encrypt_stream(src, enc, self.pub, origin="blob.bin", original_size=5000)
        enc.seek(0)
        dec = io.BytesIO()
        result = decrypt_stream(enc, dec, self.priv)
        self.assertEqual(result.original_size, 5000)
        self.assertEqual(result.origin, "blob.bin")
        src.seek(0)
        self.assertEqual(src.read(), dec.getvalue())

    def test_empty_file_roundtrip(self):
        src = io.BytesIO(b"")
        enc = io.BytesIO()
        encrypt_stream(src, enc, self.pub, origin="empty.dat", original_size=0)
        self.assertTrue(len(enc.getvalue()) > 0)
        enc.seek(0)
        dec = io.BytesIO()
        result = decrypt_stream(enc, dec, self.priv)
        self.assertEqual(result.original_size, 0)
        self.assertEqual(dec.getvalue(), b"")

    def test_big_file_roundtrip(self):
        size = CHUNK_SIZE * 2 + 12345
        data = os.urandom(size)
        src = io.BytesIO(data)
        enc = io.BytesIO()
        seen = []
        encrypt_stream(src, enc, self.pub, origin="big.bin", original_size=size,
                       progress=seen.append)
        self.assertTrue(seen, "进度回调应被调用")
        self.assertEqual(seen[-1], size)
        enc.seek(0)
        dec = io.BytesIO()
        decrypt_stream(enc, dec, self.priv)
        self.assertEqual(dec.getvalue(), data)

    def test_origin_sanitized(self):
        src = io.BytesIO(b"x")
        enc = io.BytesIO()
        r = encrypt_stream(src, enc, self.pub, origin="../../etc/passwd")
        self.assertEqual(r.origin, "passwd")
        enc.seek(0)
        dec = io.BytesIO()
        self.assertEqual(decrypt_stream(enc, dec, self.priv).origin, "passwd")

    def test_magic_mismatch(self):
        bogus = io.BytesIO(b"NOTFORJANG" + b"\x00" * 100)
        with self.assertRaises(HeaderError):
            decrypt_stream(bogus, io.BytesIO(), self.priv)

    def test_truncated_header(self):
        with self.assertRaises(HeaderError):
            decrypt_stream(io.BytesIO(b"FORJANG1"), io.BytesIO(), self.priv)

    def test_ciphertext_tamper(self):
        src = io.BytesIO(b"secret data" * 100)
        enc = io.BytesIO()
        encrypt_stream(src, enc, self.pub, origin="t.bin")
        raw = bytearray(enc.getvalue())
        raw[-20] ^= 0xFF  # 动密文
        with self.assertRaises(TamperError):
            decrypt_stream(io.BytesIO(bytes(raw)), io.BytesIO(), self.priv)

    def test_header_tamper(self):
        src = io.BytesIO(b"secret data" * 100)
        enc = io.BytesIO()
        encrypt_stream(src, enc, self.pub, origin="t.bin")
        raw = bytearray(enc.getvalue())
        raw[-1] ^= 0xFF  # 动 tag
        with self.assertRaises(TamperError):
            decrypt_stream(io.BytesIO(bytes(raw)), io.BytesIO(), self.priv)

    def test_wrong_private_key(self):
        other = generate_keypair(2048)
        src = io.BytesIO(b"secret")
        enc = io.BytesIO()
        encrypt_stream(src, enc, self.pub, origin="t.bin")
        enc.seek(0)
        with self.assertRaises(DecryptionError):
            decrypt_stream(enc, io.BytesIO(), other.private_key)


class TestUploadFlow(Base):
    def test_full_roundtrip_restores_original_name(self):
        data = os.urandom(3000) + b"\xe4\xb8\xad\xe6\x96\x87"
        src = self.write("report.pdf", data)
        result = encrypt_uploaded(src, self.tmp, self.pub)
        self.assertEqual(result.output_path, self.path("report.pdf.forjiang"))
        self.assertTrue(os.path.exists(self.path("report.pdf.forjiang")))
        # 默认不保留 .txt 中转件
        self.assertFalse(os.path.exists(self.path("report.pdf.txt")))
        self.assertEqual(result.origin, "report.pdf")

        back = decrypt_forjiang(self.path("report.pdf.forjiang"), self.tmp, self.priv)
        self.assertEqual(back.restored_path, self.path("report.pdf"))
        with open(back.restored_path, "rb") as fh:
            self.assertEqual(fh.read(), data)
        self.assertFalse(os.path.exists(self.path("report.pdf.txt")))

    def test_keep_txt(self):
        src = self.write("song.mp3", b"audio" * 500)
        r = encrypt_uploaded(src, self.tmp, self.pub, keep_txt=True)
        self.assertTrue(os.path.exists(r.txt_path))
        with open(r.txt_path, "rb") as fh:
            self.assertEqual(fh.read(), b"audio" * 500)
        os.unlink(r.txt_path)

        back = decrypt_forjiang(self.path("song.mp3.forjiang"), self.tmp, self.priv, keep_txt=True)
        self.assertTrue(os.path.exists(back.restored_path))
        self.assertTrue(os.path.exists(self.path("song.mp3.txt")))
        os.unlink(self.path("song.mp3.txt"))

    def test_input_already_txt_not_overwritten(self):
        data = b"already txt"
        src = self.write("note.txt", data)
        r = encrypt_uploaded(src, self.tmp, self.pub)
        # 原文件必须还在且内容不变
        self.assertTrue(os.path.exists(src))
        with open(src, "rb") as fh:
            self.assertEqual(fh.read(), data)
        self.assertEqual(r.output_path, self.path("note.txt.forjiang"))
        back = decrypt_forjiang(self.path("note.txt.forjiang"), self.tmp, self.priv)
        self.assertEqual(back.restored_path, self.path("note.txt"))
        with open(back.restored_path, "rb") as fh:
            self.assertEqual(fh.read(), data)

    def test_unicode_filename(self):
        data = b"unicode"
        src = self.write("\u6587\u6863 \u2014 \u6d4b\u8bd5.docx", data)
        r = encrypt_uploaded(src, self.tmp, self.pub)
        back = decrypt_forjiang(r.output_path, self.tmp, self.priv)
        self.assertEqual(back.origin, "\u6587\u6863 \u2014 \u6d4b\u8bd5.docx")
        with open(back.restored_path, "rb") as fh:
            self.assertEqual(fh.read(), data)

    def test_original_name_ends_with_txt(self):
        data = b"note content"
        src = self.write("plain.txt", data)
        r = encrypt_uploaded(src, self.tmp, self.pub)
        os.unlink(src)  # 模拟"上传后原件已删"
        out_dir = tempfile.mkdtemp(dir=self.tmp)
        try:
            back = decrypt_forjiang(r.output_path, out_dir, self.priv)
            self.assertEqual(back.restored_path, os.path.join(out_dir, "plain.txt"))
            with open(back.restored_path, "rb") as fh:
                self.assertEqual(fh.read(), data)
            self.assertFalse(os.path.exists(os.path.join(out_dir, "plain.txt.txt")))
        finally:
            shutil.rmtree(out_dir)

    def test_encrypt_rejects_forjiang_input(self):
        src = self.write("x.forjiang", b"junk")
        with self.assertRaises(HeaderError):
            encrypt_uploaded(src, self.tmp, self.pub)

    def test_output_exists_needs_force(self):
        src = self.write("dup.bin", b"x" * 100)
        encrypt_uploaded(src, self.tmp, self.pub)
        with self.assertRaises(FileExistsError):
            encrypt_uploaded(src, self.tmp, self.pub)
        encrypt_uploaded(src, self.tmp, self.pub, force=True)  # force 应成功

    def test_decrypt_output_exists_needs_force(self):
        src = self.write("exist.doc", b"content")
        r = encrypt_uploaded(src, self.tmp, self.pub)
        out = decrypt_forjiang(r.output_path, self.tmp, self.priv)
        self.assertTrue(os.path.exists(out.restored_path))
        # 解密回原位且原文件内容未变 -> 允许(静默覆盖)
        out_again = decrypt_forjiang(r.output_path, self.tmp, self.priv)
        with open(out_again.restored_path, "rb") as fh:
            self.assertEqual(fh.read(), b"content")
        # 原位文件被人改过 -> 必须显式 force
        with open(self.path("exist.doc"), "wb") as fh:
            fh.write(b"modified by someone else")
        with self.assertRaises(FileExistsError):
            decrypt_forjiang(r.output_path, self.tmp, self.priv)
        self.assertFalse(os.path.exists(self.path("exist.doc.txt")), "失败后不得留下 .txt 中转件")
        with open(self.path("exist.doc"), "rb") as fh:
            self.assertEqual(fh.read(), b"modified by someone else")
        out2 = decrypt_forjiang(r.output_path, self.tmp, self.priv, force=True)
        with open(out2.restored_path, "rb") as fh:
            self.assertEqual(fh.read(), b"content")
        self.assertFalse(os.path.exists(self.path("exist.doc.txt")))

    def test_out_dir_separate_from_input(self):
        inbox = tempfile.mkdtemp(dir=self.tmp)
        outbox = tempfile.mkdtemp(dir=self.tmp)
        try:
            src = os.path.join(inbox, "move.zip")
            with open(src, "wb") as fh:
                fh.write(os.urandom(2048))
            r = encrypt_uploaded(src, outbox, self.pub)
            self.assertTrue(os.path.isfile(r.output_path))
            self.assertFalse(os.path.exists(os.path.join(inbox, "move.zip.txt")))
            back = decrypt_forjiang(r.output_path, outbox, self.priv)
            self.assertTrue(os.path.isfile(back.restored_path))
        finally:
            shutil.rmtree(inbox)
            shutil.rmtree(outbox)


class TestKeys(Base):
    def test_generate_and_load(self):
        kp = generate_keypair(2048)
        pub_path, priv_path = save_keypair(kp, self.path("k1"), name="u")
        self.assertTrue(os.path.isfile(pub_path))
        self.assertTrue(os.path.isfile(priv_path))
        mode = stat.S_IMODE(os.stat(priv_path).st_mode)
        self.assertEqual(mode, 0o600, "私钥应为 0600")
        pub = load_public_key(pub_path)
        priv = load_private_key(priv_path)
        blob = b"payload"
        wrapped = wrap_key(b"\x01" * 32, pub)
        self.assertEqual(len(wrapped), 256)  # 2048-bit RSA -> 256 字节
        from forjiang_crypto.keys import unwrap_key

        self.assertEqual(unwrap_key(wrapped, priv), b"\x01" * 32)

    def test_encrypted_private_key(self):
        kp = generate_keypair(2048)
        pub_path, priv_path = save_keypair(kp, self.path("k2"), name="u", password="s3cret")
        with self.assertRaises(KeyPasswordRequired):
            load_private_key(priv_path)  # 无口令: 明确归类为"需要口令"
        priv = load_private_key(priv_path, password="s3cret")
        self.assertIsNotNone(priv)
        with self.assertRaises(KeyError_) as ctx:
            load_private_key(priv_path, password="bad")
        # 口令错误不应该被误报成"需要口令"(否则 CLI 会反复交互式追问)
        self.assertNotIsInstance(ctx.exception, KeyPasswordRequired)

    def test_min_bits_enforced(self):
        with self.assertRaises(KeyError_):
            generate_keypair(1024)

    def test_missing_file(self):
        with self.assertRaises(KeyError_):
            load_public_key(self.path("nope.pem"))
        with self.assertRaises(KeyError_):
            load_private_key(self.path("nope.pem"))

    def test_only_public_key_needed_to_encrypt(self):
        """API 层面只需要公钥对象即可加密（私钥全程不参与）。"""
        src = self.write("pub-only.txt", b"data")
        out = encrypt_file(src, self.path("pub-only.txt.forjiang"), self.pub)
        self.assertTrue(os.path.isfile(out.output_path))
        plain = decrypt_file(out.output_path, self.path("pub-only.out"), self.priv)
        self.assertEqual(plain.origin, "pub-only.txt")


class TestPasswordMode(Base):
    """密码模式：PBKDF2 派生密钥 + 分块 AES-GCM。"""

    def test_roundtrip_sizes(self):
        for size in (0, 1, 100, CHUNK_SIZE, CHUNK_SIZE + 7, CHUNK_SIZE * 2 + 123):
            data = os.urandom(size)
            src = self.write(f"p-{size}.bin", data)
            out = self.path(f"p-{size}.bin.forjiang")
            back = self.path(f"p-{size}.out")
            password_encrypt_file(src, out, "correct horse")
            self.assertTrue(os.path.isfile(out))
            password_decrypt_file(out, back, "correct horse")
            with open(back, "rb") as fh:
                self.assertEqual(fh.read(), data, f"size={size}")

    def test_wrong_password(self):
        src = self.write("secret.txt", b"top secret" * 100)
        out = self.path("secret.txt.forjiang")
        password_encrypt_file(src, out, "right-pass")
        with self.assertRaises(TamperError):
            password_decrypt_file(out, self.path("secret.out"), "wrong-pass")
        self.assertFalse(os.path.exists(self.path("secret.out")), "失败不得留半成品")

    def test_tampered_ciphertext(self):
        src = self.write("tamper.txt", b"x" * 5000)
        out = self.path("tamper.txt.forjiang")
        password_encrypt_file(src, out, "pw123456")
        with open(out, "r+b") as fh:
            fh.seek(120)
            b = fh.read(1)
            fh.seek(120)
            fh.write(bytes([b[0] ^ 0xFF]))
        with self.assertRaises(TamperError):
            password_decrypt_file(out, self.path("tamper.out"), "pw123456")

    def test_truncation_detected(self):
        src = self.write("trunc.txt", b"y" * 9000)
        out = self.path("trunc.txt.forjiang")
        password_encrypt_file(src, out, "pw123456")
        size = os.path.getsize(out)
        truncated = self.path("trunc.cut")
        with open(out, "rb") as fin, open(truncated, "wb") as fout:
            fout.write(fin.read(size - 50))  # 砍掉尾部
        with self.assertRaises((TamperError, HeaderError)):
            password_decrypt_file(truncated, self.path("trunc.out"), "pw123456")

    def test_header_records_original_name(self):
        src = self.write("报告 v2.docx", b"doc content")
        out = self.path("报告 v2.docx.forjiang")
        r = password_encrypt_file(src, out, "pw123456", origin="报告 v2.docx")
        self.assertEqual(r.origin, "报告 v2.docx")
        back = password_decrypt_file(out, self.path("restored.bin"), "pw123456")
        self.assertEqual(back.origin, "报告 v2.docx")

    def test_rejects_non_password_format(self):
        # 公钥模式的文件不能当密码模式解
        src = self.write("mixed.bin", b"data" * 100)
        r = encrypt_uploaded(src, self.tmp, self.pub)
        with self.assertRaises(HeaderError):
            password_decrypt_file(r.output_path, self.path("mixed.out"), "pw123456")

    def test_is_password_format_sniffer(self):
        src = self.write("sniff.txt", b"abc")
        a = self.path("sniff.txt.forjiang")
        password_encrypt_file(src, a, "pw123456")
        self.assertTrue(is_password_format(a))
        src2 = self.write("sniff2.txt", b"abc")
        r = encrypt_uploaded(src2, self.tmp, self.pub)
        self.assertFalse(is_password_format(r.output_path))

    def test_short_password_rejected_by_api(self):
        src = self.write("short.txt", b"abc")
        with self.assertRaises(ValueError):
            password_encrypt_file(src, self.path("short.txt.forjiang"), "")


class TestEncryptFailureCleanup(unittest.TestCase):
    """加密失败不能把 .txt 中转件留在输出目录里。"""

    def test_failed_encrypt_removes_txt_intermediate(self):
        tmp = tempfile.mkdtemp(prefix="forjiang-clean-")
        try:
            src = os.path.join(tmp, "report.png")
            with open(src, "wb") as fh:
                fh.write(b"payload")
            out = os.path.join(tmp, "vault")
            os.makedirs(out)
            pub = load_public_key(self._pub(tmp))
            # 传一个坏公钥对象：.txt 中转件已经落盘，随后的 wrap_key 必失败
            with self.assertRaises(Exception):
                encrypt_uploaded(src, out, "not-a-key", force=True)
            self.assertFalse(
                os.path.exists(os.path.join(out, "report.png.txt")),
                "加密失败后 .txt 中转件必须被清掉")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _pub(self, tmp):
        save_keypair(generate_keypair(2048), tmp, "k")
        return os.path.join(tmp, "k.pub.pem")


class TestOpenSSHPrivateKey(unittest.TestCase):
    """OpenSSH 格式私钥（ssh-keygen 默认产出的那种）要能直接用。"""

    def test_load_openssh_private_key(self):
        from forjiang_crypto.keys import load_private_key as load
        tmp = tempfile.mkdtemp(prefix="forjiang-ssh-")
        try:
            kp = generate_keypair(2048)
            pem = kp.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )
            path = os.path.join(tmp, "id_rsa")
            with open(path, "wb") as fh:
                fh.write(pem)
            key = load(path)
            self.assertEqual(key.key_size, 2048)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_encrypted_openssh_private_key_needs_password(self):
        from forjiang_crypto.exceptions import KeyPasswordRequired
        from forjiang_crypto.keys import load_private_key as load
        try:
            # cryptography 加密 OpenSSH 私钥需要 bcrypt 模块，没有就跳过
            generate_keypair(2048).private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.BestAvailableEncryption(b"x"))
        except Exception as exc:
            self.skipTest(f"本环境不支持加密 OpenSSH 序列化: {exc}")
        tmp = tempfile.mkdtemp(prefix="forjiang-ssh2-")
        try:
            kp = generate_keypair(2048)
            pem = kp.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.BestAvailableEncryption(b"pw-123456"),
            )
            path = os.path.join(tmp, "id_rsa")
            with open(path, "wb") as fh:
                fh.write(pem)
            with self.assertRaises(KeyPasswordRequired):
                load(path)
            key = load(path, password="pw-123456")
            self.assertEqual(key.key_size, 2048)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestNameCompatibility(unittest.TestCase):
    """文件名兼容性。

    实测踩坑：一个带非法 UTF-8 字节的文件名（Linux 上合法）会让
    name.encode("utf-8") 抛 UnicodeEncodeError——它不是 OSError，
    连 CLI 和服务器的兜底都拦不住，整批处理直接被一个怪名字打断。
    另外 Windows 上 : * ? 这类字符和超长名会让写盘失败，同样不该拖垮整批。
    """

    def _name(self):
        return os.fsdecode(b"bad\xffname.txt")

    def test_sanitize_surrogate_name_does_not_raise(self):
        from forjiang_crypto.codec import _sanitize_name
        cleaned = _sanitize_name(self._name())
        self.assertIsInstance(cleaned, str)
        self.assertNotIn("/", cleaned)

    def test_fs_encode_roundtrips_through_fs_decode(self):
        from forjiang_crypto.codec import _fs_decode, _fs_encode
        raw = self._name()
        self.assertEqual(_fs_decode(_fs_encode(raw)), raw)

    def test_encrypt_stream_with_surrogate_origin(self):
        """名字带非法字节时，文件头照样能写，不再 UnicodeEncodeError。"""
        from forjiang_crypto.codec import decrypt_stream, encrypt_stream
        kp = generate_keypair(2048)
        tmp = tempfile.mkdtemp(prefix="forjiang-name-")
        try:
            save_keypair(kp, tmp, "k")
            raw = self._name()
            buf = io.BytesIO()
            result = encrypt_stream(io.BytesIO(b"payload"), buf,
                                    load_public_key(os.path.join(tmp, "k.pub.pem")),
                                    origin=raw)
            self.assertEqual(result.origin, raw)
            buf.seek(0)
            out = io.BytesIO()
            decrypt_stream(buf, out, load_private_key(os.path.join(tmp, "k.priv.pem")))
            self.assertEqual(out.getvalue(), b"payload")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_control_characters_replaced(self):
        from forjiang_crypto.codec import _disk_name, _sanitize_name
        for bad in ("line\nbreak.txt", "tab\there.txt", "bell\x07.txt"):
            cleaned = _sanitize_name(bad)
            self.assertTrue(all(c >= " " and c != "\x7f" for c in cleaned), repr(cleaned))
            disk = _disk_name(bad, "/tmp", 0)
            self.assertTrue(all(c >= " " and c != "\x7f" for c in disk), repr(disk))

    def test_traversal_still_blocked(self):
        from forjiang_crypto.codec import _sanitize_name
        for bad in ("../../etc/passwd", "..", "/abs/path.txt", "."):
            cleaned = _sanitize_name(bad)
            self.assertNotIn("/", cleaned)
            self.assertNotIn("..", cleaned)

    def test_windows_illegal_chars_cleaned(self):
        """模拟 Windows：冒号/问号/保留设备名/结尾点空格都要处理掉。"""
        from forjiang_crypto.codec import _disk_name
        real = os.name
        try:
            os.name = "nt"
            self.assertEqual(_disk_name("报告:2026.txt", "/tmp", 0), "报告_2026.txt")
            self.assertEqual(_disk_name('q"uote?.txt', "/tmp", 0), "q_uote_.txt")
            self.assertEqual(_disk_name("trail . ", "/tmp", 0), "trail")
            for reserved in ("con", "nul.docx", "aux.log", "lpt1"):
                self.assertTrue(_disk_name(reserved, "/tmp", 0).startswith("_"),
                                f"{reserved} 应加前缀，实际 {_disk_name(reserved, '/tmp', 0)!r}")
        finally:
            os.name = real
        # macOS/Linux 上保持原名，不擅自改名
        if os.name == "nt":
            return
        self.assertEqual(_disk_name("报告:2026.txt", "/tmp", 0), "报告:2026.txt")

    def test_disk_name_truncated_with_extension_kept(self):
        """超过目录 NAME_MAX 时截断，但扩展名必须保住，否则文件打不开。"""
        from forjiang_crypto.codec import _disk_name, _fs_encode
        long_name = "L" * 300 + ".txt"
        disk = _disk_name(long_name, "/tmp", len(".forjiang"))
        self.assertLessEqual(len(_fs_encode(disk)), 255 - len(".forjiang"))
        self.assertTrue(disk.endswith(".txt"))

    def test_encrypt_uploaded_keeps_header_name_but_safe_disk_names(self):
        """加密端：文件头保留原始名，落盘的中转件/密文名按平台清洗。"""
        tmp = tempfile.mkdtemp(prefix="forjiang-name-")
        try:
            save_keypair(generate_keypair(2048), tmp, "k")
            pub = load_public_key(os.path.join(tmp, "k.pub.pem"))
            priv = load_private_key(os.path.join(tmp, "k.priv.pem"))
            vault = os.path.join(tmp, "vault")
            weird = "报告:2026.txt"          # Windows 上非法，macOS 上合法
            src = os.path.join(tmp, weird)
            with open(src, "wb") as fh:
                fh.write(b"data")
            result = encrypt_uploaded(src, vault, pub, force=True)
            self.assertTrue(result.output_path.endswith(SUFFIX))
            self.assertTrue(os.path.exists(result.output_path))
            head = decrypt_forjiang(result.output_path, os.path.join(tmp, "out"),
                                    priv, force=True)
            with open(head.restored_path, "rb") as fh:
                self.assertEqual(fh.read(), b"data")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_decrypt_restores_name_writable_on_current_platform(self):
        """解密端：头里的名字在当前平台写不下去时，改成能写的形式，而不是报错。"""
        tmp = tempfile.mkdtemp(prefix="forjiang-name-")
        try:
            save_keypair(generate_keypair(2048), tmp, "k")
            priv = load_private_key(os.path.join(tmp, "k.priv.pem"))
            pub = load_public_key(os.path.join(tmp, "k.pub.pem"))
            src = os.path.join(tmp, "plain.txt")
            with open(src, "wb") as fh:
                fh.write(b"hello")
            # origin 用 Windows 保留名：头里原样记，落盘时必须加前缀
            r = encrypt_uploaded(src, os.path.join(tmp, "vault"), pub, force=True,
                                 origin="con")
            result = decrypt_forjiang(r.output_path, os.path.join(tmp, "out"),
                                      priv, force=True)
            if os.name == "nt":
                self.assertTrue(os.path.basename(result.restored_path).startswith("_"))
            self.assertTrue(os.path.exists(result.restored_path))
            with open(result.restored_path, "rb") as fh:
                self.assertEqual(fh.read(), b"hello")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
