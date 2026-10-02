"""AES-256-GCM 流式加解密与 .forjiang 文件格式。

混合加密：每个文件一把随机 AES-256 会话密钥，文件内容用 GCM 流式加密；
会话密钥用接收方 RSA 公钥以 OAEP(SHA-256) 封装后写进文件头。
文件头整体作为 GCM 的附加认证数据（AAD），改动任何头部字段都会导致认证失败。

文件布局（大端）::

    magic            8 字节   b"FORJANG1"
    version          1 字节   = 1
    flags            1 字节   = 0
    nonce_len        1 字节   = 12
    tag_len          1 字节   = 16
    wrapped_key_len  2 字节
    orig_name_len    2 字节
    orig_size        8 字节   明文字节数
    wrapped_key      wrapped_key_len 字节
    nonce            nonce_len 字节（内联在头部，AAD 覆盖）
    orig_name        orig_name_len 字节（UTF-8）
    ciphertext       其余字节
    tag              末尾 16 字节

上传流程（encrypt_uploaded）：把文件先统一改成 .txt 中转，再加密，
产物后缀改为 .forjiang。解密（decrypt_forjiang）为相反操作。
"""

import contextlib
import filecmp
import os
import shutil
import struct
import tempfile
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .exceptions import DecryptionError, HeaderError, TamperError
from .keys import unwrap_key, wrap_key

MAGIC = b"FORJANG1"
FORMAT_VERSION = 1
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32  # AES-256
MAX_HEADER = 64 * 1024
MAX_NAME_BYTES = 512

# Windows 不允许出现在文件名里的字符，以及保留设备名（大小写不敏感）
_ILLEGAL_ON_WINDOWS = '<>:"|?*'
_WINDOWS_RESERVED = (
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

# 密码模式（简版界面用）：PBKDF2-SHA256 派生密钥 + 分块 AES-GCM
PASSWORD_MAGIC = b"FJGPASS1"
PBKDF2_ITERATIONS = 600_000   # OWASP 对 PBKDF2-HMAC-SHA256 的推荐量级
PASSWORD_SALT_LEN = 16
PASSWORD_KDF_PBKDF2 = 1
PASSWORD_MIN_LEN = 6

SUFFIX = ".forjiang"   # 加密产物后缀
TXT_SUFFIX = ".txt"    # 上传文件统一改成 .txt
CHUNK_SIZE = 1024 * 1024  # 流式加解密分块（1 MiB）

PREFIX_LEN = struct.calcsize("!8sBBBBHIQ")  # 8+1+1+1+1+2+2+8 = 24
_PREFIX = struct.Struct("!8sBBBBHIQ")


@dataclass
class Result:
    """一次加解密的结果摘要。encrypt_* / decrypt_* 均返回它。"""

    origin: str                       # 文件头记录的原始文件名
    original_size: int                # 明文字节数
    wrapped_key_len: int
    nonce_len: int
    tag_len: int = TAG_LEN
    input_path: str = ""
    output_path: str = ""
    txt_path: str = ""
    restored_path: str = ""
    header: bytes = field(default=b"", repr=False, compare=False)


# ---------------------------------------------------------------------------
# 文件头
# ---------------------------------------------------------------------------


def _aad(prefix, wrapped, nonce, origin_bytes):
    return prefix + wrapped + nonce + origin_bytes


def parse_header(fin):
    """从文件对象读取并校验文件头，返回 Result 与数据区起始偏移。"""
    prefix = fin.read(PREFIX_LEN)
    if len(prefix) < PREFIX_LEN:
        raise HeaderError("文件不足一个文件头长度，不是有效的 .forjiang 文件")
    magic, version, flags, nonce_len, tag_len, wrapped_len, name_len, orig_size = (
        _PREFIX.unpack(prefix)
    )
    if magic != MAGIC:
        raise HeaderError(f"文件头魔数不匹配（{magic!r}），不是本系统加密的文件")
    if version != FORMAT_VERSION:
        raise HeaderError(f"不支持的文件格式版本 {version}（本系统最高支持 {FORMAT_VERSION}）")
    if flags != 0:
        raise HeaderError(f"文件头 flags 字段非预期值 {flags}")
    if nonce_len != NONCE_LEN or tag_len != TAG_LEN:
        raise HeaderError("文件头声明的 nonce/tag 长度与本系统不符")
    if name_len > MAX_NAME_BYTES:
        raise HeaderError(f"文件头中的文件名长度异常（{name_len}）")
    if PREFIX_LEN + wrapped_len + nonce_len + name_len > MAX_HEADER:
        raise HeaderError("文件头过大，已超出上限")

    body = fin.read(wrapped_len + nonce_len + name_len)
    if len(body) != wrapped_len + nonce_len + name_len:
        raise HeaderError("文件头被截断")
    wrapped = body[:wrapped_len]
    nonce = body[wrapped_len : wrapped_len + nonce_len]
    name_bytes = body[wrapped_len + nonce_len :]
    try:
        original_name = _fs_decode(name_bytes)
    except UnicodeDecodeError as exc:
        raise HeaderError(f"文件头中的文件名不是合法 UTF-8：{exc}") from exc

    header = prefix + body
    result = Result(
        origin=original_name,
        original_size=orig_size,
        wrapped_key_len=wrapped_len,
        nonce_len=nonce_len,
        tag_len=tag_len,
        header=header,
    )
    return result, header, nonce, wrapped


# ---------------------------------------------------------------------------
# 流式加解密原语
# ---------------------------------------------------------------------------


def encrypt_stream(fin, fout, public_key, origin=None, original_size=None, progress=None):
    """把 fin 的内容加密后写入 fout，返回 Result。

    origin          写入文件头的原始文件名；缺省用 fin.name，再缺省 "unnamed"。
    original_size   明文字节数；缺省自动探测，无法探测时记 0。
    progress        回调 fn(已处理明文字节数)。
    """
    origin = _sanitize_name(origin if origin is not None else getattr(fin, "name", None))
    origin_bytes = _fs_encode(origin)

    if original_size is None:
        try:
            pos = fin.tell()
            fin.seek(0, os.SEEK_END)
            original_size = fin.tell()
            fin.seek(pos, os.SEEK_SET)
        except (OSError, AttributeError, ValueError):
            original_size = 0

    aes_key = os.urandom(KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    wrapped = wrap_key(aes_key, public_key)

    prefix = _PREFIX.pack(
        MAGIC,
        FORMAT_VERSION,
        0,
        NONCE_LEN,
        TAG_LEN,
        len(wrapped),
        len(origin_bytes),
        original_size,
    )
    fout.write(prefix + wrapped + nonce + origin_bytes)

    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(_aad(prefix, wrapped, nonce, origin_bytes))

    done = 0
    while True:
        chunk = fin.read(CHUNK_SIZE)
        if not chunk:
            break
        fout.write(encryptor.update(chunk))
        done += len(chunk)
        if progress is not None:
            progress(done)
    fout.write(encryptor.finalize())
    fout.write(encryptor.tag)

    return Result(
        origin=origin,
        original_size=original_size,
        wrapped_key_len=len(wrapped),
        nonce_len=NONCE_LEN,
        tag_len=TAG_LEN,
    )


def decrypt_stream(fin, fout, private_key, progress=None):
    """把 .forjiang 的 fin 解密写入 fout，返回 Result。

    注意：GCM 标签只在全部密文处理完后才能验证，所以调用方必须把明文写到
    临时文件并在本函数抛异常时丢弃（用 _atomic_output 包装即可）。
    """
    result, header, nonce, wrapped = parse_header(fin)

    try:
        aes_key = unwrap_key(wrapped, private_key)
    except Exception as exc:
        raise DecryptionError(f"会话密钥解封失败（私钥不匹配？）：{exc}") from exc
    if len(aes_key) not in (16, 24, 32):
        raise DecryptionError(f"会话密钥长度异常：{len(aes_key)} 字节")

    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce)).decryptor()
    decryptor.authenticate_additional_data(header)

    done = 0
    tail = b""
    while True:
        chunk = fin.read(CHUNK_SIZE)
        if not chunk:
            break
        data = tail + chunk
        if len(data) <= TAG_LEN:
            tail = data
            continue
        tail = data[-TAG_LEN:]
        fout.write(decryptor.update(data[: -TAG_LEN]))
        done += len(data) - TAG_LEN
        if progress is not None:
            progress(done)
    if len(tail) != TAG_LEN:
        raise HeaderError(f"文件末尾不足以容纳认证标签(需要 {TAG_LEN} 字节, 实际 {len(tail)})")
    try:
        fout.write(decryptor.finalize_with_tag(tail))
    except InvalidTag:
        raise TamperError(
            "认证失败: 密文或文件头被篡改, 或密钥不匹配"
        ) from None

    result.original_size = done
    return result


def _sanitize_name(name):
    """只保留纯文件名片段，杜绝路径穿越写进文件头；空名回退 unnamed。

    兼容性：名字可能含非法 UTF-8 字节（POSIX 允许任意字节做文件名，Python 用
    surrogateescape 表达），直接 encode("utf-8") 会抛 UnicodeEncodeError ——
    整批处理会被一个怪名字打断，所以这里走 _fs_encode 走本机文件系统编码。
    """
    if name is None:
        return "unnamed"
    name = str(name)
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in name):
        # 非法字节还原成本机看到的文本（macOS/Linux 上仍能原样写回磁盘）
        name = os.fsdecode(os.fsencode(name))
    name = name.replace("\\", "/")
    base = os.path.basename(name.rstrip("/"))
    base = base or str(name)
    # 全是斜杠的名字（如 "/"）：basename 出来还是它自己，若放行，
    # os.path.join(out_dir, "/") 会还原到根目录——必须按无名处理
    if not base or base in (".", "..") or not base.strip("/"):
        return "unnamed"
    base = _drop_control_chars(base) or "unnamed"
    encoded = _fs_encode(base)
    if len(encoded) > MAX_NAME_BYTES:
        base = encoded[:MAX_NAME_BYTES].decode("utf-8", "ignore") or "unnamed"
    return base


def _fs_encode(name):
    """名字 -> 字节：普通情况 UTF-8；含非法 UTF-8 字节时按本机文件系统编码编码，
    保证同一台机器上读到的怪名字还能原样写回磁盘，而不是抛异常。"""
    try:
        return name.encode("utf-8")
    except UnicodeEncodeError:
        return os.fsencode(name)


def _fs_decode(raw):
    """字节 -> 名字：严格 UTF-8 优先（跨机器解密），失败时按本机文件系统方式还原。"""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return os.fsdecode(raw)


def _drop_control_chars(name):
    """去掉控制字符（换行、回车等）：写进文件头会污染日志与 zip 列表，写盘也易踩坑。"""
    return "".join("_" if (ord(ch) < 0x20 or ord(ch) == 0x7F) else ch for ch in name)


def _name_max_bytes(directory):
    """目标目录下单个文件名的最大字节数（macOS/Linux/Windows 通常 255）。"""
    try:
        limit = os.pathconf(directory or ".", "PC_NAME_MAX")
    except (OSError, ValueError, AttributeError):
        limit = 255
    return int(limit) if limit and limit > 0 else 255


def _disk_name(stem, directory, extra_len=0):
    """把文件名改成当前平台能安全写盘的形态，用于我们自己的产物名与解密还原名。

    * 控制字符换成 _（跨平台都不该出现，尤其是换行）
    * Windows 上 < > : " | ? *、结尾的点/空格、保留设备名（CON/NUL/COM1...）换成 _
    * 超过目录 NAME_MAX - extra_len（要拼的后缀长度）时截断，保留扩展名，
      否则加密一个长名字文件会直接 ENAMETOOLONG 打断整批
    """
    name = _drop_control_chars(str(stem))
    if not name:
        return "unnamed"
    if os.name == "nt":
        name = "".join("_" if ch in _ILLEGAL_ON_WINDOWS else ch for ch in name)
        name = name.rstrip(" .")
        if name.upper() in _WINDOWS_RESERVED or os.path.splitext(name)[0].upper() in _WINDOWS_RESERVED:
            name = "_" + name
        if not name:
            return "unnamed"
    limit = max(_name_max_bytes(directory) - max(0, extra_len), 16)
    encoded = _fs_encode(name)
    if len(encoded) <= limit:
        return name
    root, ext = os.path.splitext(name)
    root_b, ext_b = _fs_encode(root), _fs_encode(ext)
    room = limit - len(ext_b)
    if room < 1:          # 扩展名本身就超长：连它一起截
        room, ext_b = limit, b""
    return (root_b[:room].decode("utf-8", "ignore") + ext_b.decode("utf-8", "ignore")) or "unnamed"


@contextlib.contextmanager
def _atomic_output(final_path):
    """在目标目录写隐藏临时文件，全部成功后原子替换目标，任何异常都会清除临时文件。"""
    directory = os.path.dirname(final_path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".forjiang-", dir=directory)
    os.close(fd)
    ok = False
    try:
        yield tmp
        ok = True
    finally:
        if ok:
            os.replace(tmp, final_path)
        else:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


# ---------------------------------------------------------------------------
# 单文件原子加解密
# ---------------------------------------------------------------------------


def encrypt_file(input_path, output_path, public_key, origin=None, progress=None):
    with open(input_path, "rb") as fin, _atomic_output(output_path) as tmp:
        with open(tmp, "wb") as fout:
            result = encrypt_stream(fin, fout, public_key, origin=origin, progress=progress)
    result.input_path = input_path
    result.output_path = output_path
    return result


def decrypt_file(input_path, output_path, private_key, progress=None):
    with open(input_path, "rb") as fin, _atomic_output(output_path) as tmp:
        with open(tmp, "wb") as fout:
            result = decrypt_stream(fin, fout, private_key, progress=progress)
    result.input_path = input_path
    result.output_path = output_path
    return result


# ---------------------------------------------------------------------------
# 上传流程：统一改 .txt -> 加密 -> 后缀 .forjiang（解密反之）
# ---------------------------------------------------------------------------


def txt_name(path):
    """给任意路径拼上 .txt 后缀后的文件名（不含目录）。"""
    base = os.path.basename(path)
    if base.endswith(TXT_SUFFIX):
        return base
    return base + TXT_SUFFIX


def strip_forjiang(path):
    """去掉 .forjiang 后缀得到主干。"""
    base = os.path.basename(path)
    if base.endswith(SUFFIX):
        return base[: -len(SUFFIX)]
    return base


def encrypt_uploaded(input_path, out_dir, public_key, keep_txt=False, force=False,
                     origin=None, progress=None):
    """加密一个"上传"的文件。

    origin  覆盖用于命名/写头的原始文件名；缺省取 input_path 的文件名。
            （Web 上传等场景里 input 是服务端临时文件，必须显式传真实文件名。）

    1) 先把文件按统一命名复制为 <origin>.txt（中转件）；
    2) 加密生成 <origin>.forjiang；
    3) keep_txt=False 时删除 .txt 中转件。
       若输入本身就是那个 .txt，则原文件保留，绝不删除用户输入。
    """
    input_path = os.path.abspath(input_path)
    out_dir = os.path.abspath(out_dir or os.path.dirname(input_path))
    os.makedirs(out_dir, exist_ok=True)
    base = _sanitize_name(origin if origin is not None else os.path.basename(input_path))
    if base.endswith(SUFFIX):
        raise HeaderError(f"{base} 已经是 .forjiang 加密文件")

    # 文件头里的名字保持原样（解密还原用它），落盘的中转件/密文名按当前平台清洗：
    # Windows 上带 : * ? 这类字符的名字、或超过目录 NAME_MAX 的长名字会写盘失败，
    # 一个怪名字不该让整批加密中断。
    txt_base = _disk_name(base, out_dir, len(TXT_SUFFIX))
    for_base = _disk_name(base, out_dir, len(SUFFIX))
    txt_path = os.path.join(out_dir, txt_name(txt_base))
    for_path = os.path.join(out_dir, for_base + SUFFIX)
    txt_is_input = txt_path == input_path
    if for_path == input_path:
        raise FileExistsError(f"加密产物会覆盖输入文件本身: {for_path}")
    if not txt_is_input and os.path.exists(txt_path) and not force:
        raise FileExistsError(f"输出已存在: {txt_path} (force=True 可覆盖)")
    if os.path.exists(for_path) and not force:
        raise FileExistsError(f"输出已存在: {for_path} (force=True 可覆盖)")

    if not txt_is_input:
        with open(input_path, "rb") as src, open(txt_path, "wb") as dst:
            shutil.copyfileobj(src, dst, CHUNK_SIZE)

    try:
        result = encrypt_file(txt_path, for_path, public_key, origin=base,
                              progress=progress)
    except Exception:
        # 加密失败不能在中转件上留垃圾：.txt 是中间产物，密文没出来就该清掉
        if not txt_is_input:
            with contextlib.suppress(OSError):
                os.unlink(txt_path)
        raise
    result.txt_path = txt_path
    if not keep_txt and not txt_is_input:
        try:
            os.unlink(txt_path)
        except OSError:
            pass
        result.txt_path = ""
    return result


def decrypt_forjiang(input_path, out_dir, private_key, keep_txt=False, force=False,
                     original_name=None, progress=None):
    """解密一个 .forjiang 文件，是 encrypt_uploaded 的逆操作。

    original_name=None: 恢复文件头记录的原始文件名(例如 report.pdf)；
    传入名字则恢复成该名字对应的文件(用于只验证/预览)。

    解密出的明文先落到隐藏中转文件，再与目标比对：
      目标不存在            -> 直接安置；
      目标存在且内容一致    -> 视为解密回原位，静默安置；
      目标存在且内容不同    -> 拒绝(除非 force)，且不留下任何中间文件。
    """
    input_path = os.path.abspath(input_path)
    out_dir = os.path.abspath(out_dir or os.path.dirname(input_path))
    os.makedirs(out_dir, exist_ok=True)

    base = strip_forjiang(input_path)
    with open(input_path, "rb") as fin:
        head_result, _header, _nonce, _wrapped = parse_header(fin)

    # .txt 中转件的名字优先用文件头记录的原始名，与加密端的中转件对应；
    # 密文被改名过时回退到去掉 .forjiang 后的名字。
    # 还原名按当前平台清洗：文件头可能是另一台机器写的（比如 mac 上带 : 的名字），
    # 原样写盘在 Windows 上会失败，跨平台解密不该被名字卡住。
    header_name = _sanitize_name(head_result.origin or base)
    txt_base = _disk_name(header_name, out_dir, len(TXT_SUFFIX))
    txt_path = os.path.join(out_dir, txt_name(txt_base))
    restored_name = _disk_name(
        _sanitize_name(original_name or head_result.origin or base), out_dir)
    restored_path = os.path.join(out_dir, restored_name)

    def _occupied(path):
        """目标名是否被占：只有“文件已存在、内容与新解出的明文不同、
        且没有 force”时才算占住（此时调用方要报错）；不存在、内容一致、
        或 force=True 都返回 False，允许安置。"""
        if not os.path.exists(path):
            return False
        if force:
            return False
        return not filecmp.cmp(path, staging, shallow=False)

    fd, staging = tempfile.mkstemp(prefix=".forjiang-plain-", dir=out_dir)
    os.close(fd)
    try:
        result = decrypt_file(input_path, staging, private_key, progress=progress)

        if restored_path != txt_path and _occupied(restored_path):
            raise FileExistsError(f"输出已存在且内容不同: {restored_path} (force=True 可覆盖)")

        if _occupied(txt_path):
            raise FileExistsError(f"输出已存在且内容不同: {txt_path} (force=True 可覆盖)")
        if os.path.exists(txt_path) and filecmp.cmp(txt_path, staging, shallow=False):
            # 中转件已在位且内容一致（“解密回原位”场景），无需替换；
            # 注意 force=True 且内容不同时必须用新明文替换，不能沿用旧件
            os.unlink(staging)
        else:
            os.replace(staging, txt_path)

        if restored_path == txt_path:
            result.restored_path = txt_path
            return result

        if keep_txt:
            shutil.copyfile(txt_path, restored_path)
        else:
            os.replace(txt_path, restored_path)
            result.txt_path = ""
        result.restored_path = restored_path
        return result
    finally:
        with contextlib.suppress(OSError):
            if os.path.exists(staging):
                os.unlink(staging)


# ---------------------------------------------------------------------------
# 密码模式（简版界面 / CLI --password）：PBKDF2-SHA256 派生 AES-256 密钥，
# 分块 AES-GCM 流式加解密，每块 AAD 绑定文件头与块序号（防重排/截断），
# 末尾追加一个认证过的空块作为"结束标记"，截断的文件无法通过认证。
#
# 布局：
#   magic         8  B   b"FJGPASS1"
#   version       1  B   = 1
#   kdf           1  B   = 1 (PBKDF2-HMAC-SHA256)
#   iterations    4  B   大端
#   salt_len      1  B
#   salt          salt_len B
#   name_len      2  B   大端
#   orig_name     name_len B（UTF-8）
#   之后每块：iv(12) + ct_len(4, 大端) + ct(明文 + 16 B tag)
#   最后是一个明文字节数为 0 的结束块（tag 认证，防截断）
# ---------------------------------------------------------------------------

_PASSWORD_PREFIX = struct.Struct("!8sBBI")
_SALT_AND_NAME = struct.Struct("!BH")


def _derive_key(password, salt, iterations):
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not password:
        raise ValueError("密码不能为空")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


def password_encrypt_file(input_path, output_path, password, iterations=PBKDF2_ITERATIONS,
                          origin=None, progress=None):
    """用密码加密单个文件（原子落盘）。

    iterations 写进文件头，以后调大默认值不影响旧文件解密。
    """
    if not password:
        raise ValueError("密码不能为空")
    origin = _sanitize_name(origin if origin is not None else os.path.basename(input_path))
    name_bytes = _fs_encode(origin)
    if len(name_bytes) > MAX_NAME_BYTES:
        raise HeaderError(f"文件名过长（{len(name_bytes)} 字节，上限 {MAX_NAME_BYTES}）")

    salt = os.urandom(PASSWORD_SALT_LEN)
    key = _derive_key(password, salt, iterations)
    header = (
        _PASSWORD_PREFIX.pack(PASSWORD_MAGIC, FORMAT_VERSION, PASSWORD_KDF_PBKDF2, iterations)
        + _SALT_AND_NAME.pack(len(salt), len(name_bytes))
        + salt
        + name_bytes
    )

    def _seal_chunk(index, plaintext):
        """加密一块：AAD 绑定整个文件头与块序号，块内 iv 随机。"""
        iv = os.urandom(NONCE_LEN)
        enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
        enc.authenticate_additional_data(header + struct.pack("!Q", index))
        ct = enc.update(plaintext) + enc.finalize() + enc.tag
        return iv + struct.pack("!I", len(ct)) + ct

    with open(input_path, "rb") as fin, _atomic_output(output_path) as tmp:
        with open(tmp, "wb") as fout:
            fout.write(header)
            index = 0
            done = 0
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(_seal_chunk(index, chunk))
                index += 1
                done += len(chunk)
                if progress is not None:
                    progress(done)
            # 结束块：明文为空但带认证 tag，缺了它说明文件被截断
            fout.write(_seal_chunk(index, b""))

    return Result(
        origin=origin,
        original_size=done,
        wrapped_key_len=0,
        nonce_len=NONCE_LEN,
        input_path=input_path,
        output_path=output_path,
    )


def password_decrypt_file(input_path, output_path, password, progress=None):
    """解密密码模式的 .forjiang 文件（原子落盘）。

    密码错误或任何篡改都抛 TamperError；文件被截断抛 HeaderError。
    """
    if not password:
        raise ValueError("密码不能为空")
    with open(input_path, "rb") as fin, _atomic_output(output_path) as tmp:
        with open(tmp, "wb") as fout:
            result = password_decrypt_stream(fin, fout, password, progress=progress)
    result.input_path = input_path
    result.output_path = output_path
    return result


def password_decrypt_stream(fin, fout, password, progress=None):
    prefix = fin.read(_PASSWORD_PREFIX.size)
    if len(prefix) < _PASSWORD_PREFIX.size:
        raise HeaderError("文件不足一个文件头长度，不是有效的 .forjiang 文件")
    magic, version, kdf, iterations = _PASSWORD_PREFIX.unpack(prefix)
    if magic != PASSWORD_MAGIC:
        raise HeaderError(f"不是密码模式加密的文件（魔数 {magic!r}）")
    if version != FORMAT_VERSION:
        raise HeaderError(f"不支持的文件格式版本 {version}")
    if kdf != PASSWORD_KDF_PBKDF2:
        raise HeaderError(f"不支持的密钥派生算法 {kdf}")
    if iterations < 1 or iterations > 50_000_000:
        raise HeaderError(f"文件头中的迭代次数异常：{iterations}")

    meta = fin.read(_SALT_AND_NAME.size)
    if len(meta) < _SALT_AND_NAME.size:
        raise HeaderError("文件头被截断")
    salt_len, name_len = _SALT_AND_NAME.unpack(meta)
    if salt_len != PASSWORD_SALT_LEN:
        raise HeaderError(f"盐长度异常：{salt_len}")
    if name_len > MAX_NAME_BYTES:
        raise HeaderError(f"文件头中的文件名长度异常（{name_len}）")
    salt = fin.read(salt_len)
    name_bytes = fin.read(name_len)
    if len(salt) != salt_len or len(name_bytes) != name_len:
        raise HeaderError("文件头被截断")
    try:
        original_name = _fs_decode(name_bytes)
    except UnicodeDecodeError as exc:
        raise HeaderError(f"文件头中的文件名不是合法 UTF-8：{exc}") from exc

    header = prefix + meta + salt + name_bytes
    key = _derive_key(password, salt, iterations)

    index = 0
    done = 0
    # 循环唯一出口是遇到结束块 break（其余路径全部抛错），所以走到这里
    # 必然已经验证过结束块的认证 tag，截断文件到不了这一行。
    while True:
        head = fin.read(NONCE_LEN + 4)
        if not head:
            raise HeaderError("文件在结束块之前就被截断")
        if len(head) < NONCE_LEN + 4:
            raise HeaderError("文件数据不完整（块头被截断）")
        iv = head[:NONCE_LEN]
        (ct_len,) = struct.unpack("!I", head[NONCE_LEN:])
        if ct_len > CHUNK_SIZE + TAG_LEN:
            raise HeaderError(f"块长度异常：{ct_len}")
        ct = fin.read(ct_len)
        if len(ct) != ct_len:
            raise HeaderError("文件数据不完整（密文被截断）")

        dec = Cipher(algorithms.AES(key), modes.GCM(iv)).decryptor()
        dec.authenticate_additional_data(header + struct.pack("!Q", index))
        try:
            plaintext = dec.update(ct[:-TAG_LEN]) + dec.finalize_with_tag(ct[-TAG_LEN:])
        except InvalidTag:
            raise TamperError("认证失败：密码错误，或文件已被篡改") from None

        index += 1
        if ct_len == TAG_LEN:  # 结束块：明文为空、只剩认证 tag
            break
        fout.write(plaintext)
        done += len(plaintext)
        if progress is not None:
            progress(done)

    return Result(
        origin=original_name,
        original_size=done,
        wrapped_key_len=0,
        nonce_len=NONCE_LEN,
    )


def is_password_format(path):
    """按魔数判断是否是密码模式的文件（用于 CLI 自动识别模式）。"""
    try:
        with open(path, "rb") as fh:
            return fh.read(len(PASSWORD_MAGIC)) == PASSWORD_MAGIC
    except OSError:
        return False
