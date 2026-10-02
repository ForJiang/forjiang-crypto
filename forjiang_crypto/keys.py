"""RSA 密钥对的生成、保存与加载。

加密只需要公钥；解密才需要私钥。
私钥默认以未加密 PKCS#8 PEM 落盘（权限 0600），可用 save_keypair(..., password=...)
或在 keygen 时加 --password 落盘为加密私钥。
"""

import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .exceptions import KeyError_, KeyPasswordRequired

MIN_RSA_BITS = 2048
DEFAULT_RSA_BITS = 3072


class KeyPair:
    """一对配套的密钥对象。"""

    __slots__ = ("private_key", "public_key", "bits")

    def __init__(self, private_key, public_key, bits):
        self.private_key = private_key
        self.public_key = public_key
        self.bits = bits


def generate_keypair(bits=DEFAULT_RSA_BITS):
    """生成 RSA 密钥对。"""
    if bits < MIN_RSA_BITS:
        raise KeyError_(f"RSA 模长至少 {MIN_RSA_BITS} 位，当前 {bits}")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return KeyPair(private_key, private_key.public_key(), bits)


def save_keypair(keypair, out_dir, name="forjiang", password=None):
    """把密钥对写入 out_dir，返回 (公钥文件, 私钥文件) 路径。

    公钥：X.509 SubjectPublicKeyInfo PEM（可直接分发）。
    私钥：PKCS#8 PEM；password 为 None 时未加密，否则用 PBES2 加密（如 AES-256-CBC）。
    """
    if password is not None:
        password = password.encode("utf-8") if isinstance(password, str) else password
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()

    os.makedirs(out_dir, exist_ok=True)
    pub_path = os.path.join(out_dir, name + ".pub.pem")
    priv_path = os.path.join(out_dir, name + ".priv.pem")

    pub_pem = keypair.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_pem = keypair.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )

    _write_private(pub_path, pub_pem, mode=0o644)
    _write_private(priv_path, priv_pem, mode=0o600)
    return pub_path, priv_path


def load_public_key(path):
    """从 PEM 文件加载公钥，支持 X.509 SubjectPublicKeyInfo / PKCS#1 / OpenSSH 格式。"""
    data = _read(path, is_public=True)
    key = None
    errors = []
    for loader in (
        serialization.load_pem_public_key,
        serialization.load_ssh_public_key,
        serialization.load_der_public_key,
    ):
        try:
            key = loader(data)
            break
        except Exception as exc:  # 三种格式逐个试
            errors.append(f"{loader.__name__}: {exc}")
    if key is None:
        raise KeyError_(f"无法解析公钥 {path}：{'；'.join(errors[:2])}")
    _require_rsa(key, path)
    return key


def load_private_key(path, password=None):
    """从 PEM/DER 文件加载私钥。

    加密私钥必须提供 password（未提供时会得到“需要口令”的报错）；
    未加密私钥给了 password 会被忽略。
    """
    data = _read(path, is_public=False)
    if isinstance(password, str):
        password = password.encode("utf-8")

    key = None
    last_error = None
    for loader in (serialization.load_pem_private_key, serialization.load_der_private_key):
        try:
            key = loader(data, password=password)
            break
        except TypeError as exc:
            # cryptography 对“未给口令但密钥已加密”抛的是 TypeError，单独归类
            raise KeyPasswordRequired(
                f"私钥 {path} 已加密，需要口令；请用 --password / --password-env 提供"
            ) from exc
        except ValueError as exc:
            last_error = exc
    if key is None:
        raise KeyError_(f"私钥 {path} 口令错误或数据损坏：{last_error}")
    _require_rsa(key, path)
    return key


def public_key_from_private(private_key):
    return private_key.public_key()


def wrap_key(aes_key, public_key):
    """用 RSA-OAEP(SHA-256) 封装 AES 会话密钥。"""
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_key(wrapped, private_key):
    """用 RSA-OAEP(SHA-256) 解封会话密钥。"""
    return private_key.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _require_rsa(key, path):
    if not isinstance(key, rsa.RSAPrivateKey) and not isinstance(key, rsa.RSAPublicKey):
        raise KeyError_(f"{path} 不是 RSA 密钥（当前系统只支持 RSA 公钥封装）")
    if key.key_size < MIN_RSA_BITS:
        raise KeyError_(f"{path} 模长 {key.key_size} 位，低于安全下限 {MIN_RSA_BITS} 位")


def _read(path, is_public):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        kind = "公钥" if is_public else "私钥"
        raise KeyError_(f"{kind}文件不存在：{path}") from None


def _write_private(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    # umask 可能把权限收得更紧，按传入 mode 校准一次
    try:
        os.chmod(path, mode)
    except OSError:
        pass
