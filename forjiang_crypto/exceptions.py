"""异常层级。"""


class ForjiangCryptoError(Exception):
    """本系统所有异常的基类。"""


class KeyError_(ForjiangCryptoError):
    """密钥生成、加载、校验失败。"""


class KeyPasswordRequired(KeyError_):
    """私钥已加密但调用方没有提供口令。"""


class HeaderError(ForjiangCryptoError):
    """.forjiang 文件头损坏、不是本系统产物或缺少所需字段。"""


class TamperError(ForjiangCryptoError):
    """密文/文件头被篡改，认证标签校验失败。"""


class DecryptionError(ForjiangCryptoError):
    """解密失败（除篡改与文件头问题外：私钥不匹配、数据被截断等）。"""
