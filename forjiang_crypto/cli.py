"""命令行入口：python -m forjiang_crypto <keygen|encrypt|decrypt> ..."""

import argparse
import getpass
import os
import sys

from . import __version__
from .codec import (
    SUFFIX,
    _sanitize_name,
    decrypt_forjiang,
    encrypt_uploaded,
    is_password_format,
    password_decrypt_file,
    password_encrypt_file,
    strip_forjiang,
)
from .exceptions import (
    ForjiangCryptoError,
    HeaderError,
    KeyPasswordRequired,
)
from .keys import (
    DEFAULT_RSA_BITS,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_keypair,
)


def _human(n):
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} B"


def _progress_printer(label):
    last = -1

    def cb(done):
        nonlocal last
        pct = done // (8 * 1024 * 1024)
        if pct != last:
            last = pct
            print(f"    {label} 已处理 {_human(done)}", flush=True)

    return cb


def _collect(paths, recursive):
    """把传入的文件/目录展开成待处理文件列表（加密时跳过 .forjiang）。"""
    files = []
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, dirs, names in os.walk(p):
                    dirs.sort()
                    for name in sorted(names):
                        fp = os.path.join(root, name)
                        if name.endswith(SUFFIX):
                            continue
                        if name.startswith(".forjiang-"):
                            continue
                        files.append(fp)
            else:
                for name in sorted(os.listdir(p)):
                    fp = os.path.join(p, name)
                    if os.path.isfile(fp) and not name.endswith(SUFFIX):
                        files.append(fp)
        else:
            files.append(p)
    return files


def _collect_forjiang(paths, recursive):
    files = []
    for p in paths:
        if os.path.isdir(p):
            if recursive:
                for root, dirs, names in os.walk(p):
                    dirs.sort()
                    for name in sorted(names):
                        if name.endswith(SUFFIX):
                            files.append(os.path.join(root, name))
            else:
                for name in sorted(os.listdir(p)):
                    if name.endswith(SUFFIX):
                        files.append(os.path.join(p, name))
        else:
            files.append(p)
    return files


def cmd_keygen(args):
    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)
    print(f"生成 RSA-{args.bits} 密钥对 ...")
    keypair = generate_keypair(args.bits)
    pub_path, priv_path = save_keypair(keypair, out_dir, name=args.name, password=args.password)
    print(f"公钥：{pub_path}")
    print(f"私钥：{priv_path}（权限 0600，请妥善保管）")
    if args.password:
        print("私钥已用口令加密，解密时必须提供该口令。")
    return 0


def cmd_encrypt(args):
    password = getattr(args, "content_password", None)
    if password and args.pub:
        print("错误：--pub 与 --content-password 只能选一个（公钥模式 / 密码模式）。",
              file=sys.stderr)
        return 2
    if not password and not args.pub:
        print("错误：加密需要 --pub（公钥模式）或 --content-password（密码模式）之一。",
              file=sys.stderr)
        return 2
    pub = load_public_key(args.pub) if not password else None
    files = _collect(args.paths, args.recursive)
    if not files:
        print("没有待加密的文件。", file=sys.stderr)
        return 1
    out_dir = args.out or os.path.dirname(os.path.abspath(files[0]))
    failures = 0
    for path in files:
        try:
            if password:
                base = os.path.basename(path)
                if base.endswith(SUFFIX):
                    raise HeaderError(f"{base} 已经是 .forjiang 加密文件")
                out_path = os.path.join(out_dir, strip_forjiang(base) + SUFFIX)
                if os.path.exists(out_path) and not args.force:
                    raise FileExistsError(f"输出已存在: {out_path} (--force 可覆盖)")
                result = password_encrypt_file(
                    path, out_path, password, origin=base,
                    progress=None if args.quiet else _progress_printer(base),
                )
            else:
                result = encrypt_uploaded(
                    path,
                    out_dir,
                    pub,
                    keep_txt=args.keep_txt,
                    force=args.force,
                    progress=None if args.quiet else _progress_printer(os.path.basename(path)),
                )
        except FileExistsError as exc:
            print(f"跳过：{exc}", file=sys.stderr)
            failures += 1
            continue
        except (ForjiangCryptoError, OSError) as exc:
            # 加密侧单独的 OSError 多为写盘问题（权限、磁盘满、目录名超长、
            # 名字里有当前平台不接受的字符）：跳过这个文件，别让整批中断。
            print(f"失败：{path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        extra = "（保留 .txt 中转件）" if args.keep_txt else ""
        mode = "密码模式" if password else "公钥模式"
        print(
            f"加密[{mode}] {path} -> {result.output_path} "
            f"[{_human(result.original_size)} -> {_human(os.path.getsize(result.output_path))}]{extra}"
        )
    if failures:
        print(f"{failures} 个文件未处理。", file=sys.stderr)
        return 1
    return 0


def _load_private_with_prompt(path, password, password_env):
    if password is None and password_env:
        password = os.environ.get(password_env)
        if password is None:
            raise SystemExit(f"环境变量 {password_env} 未设置。")
    if password:
        return load_private_key(path, password=password)
    try:
        return load_private_key(path)
    except KeyPasswordRequired:
        # 只有“已加密但没给口令”才值得交互式追问；格式错误/口令错误直接抛出
        try:
            password = getpass.getpass(f"私钥 {path} 已加密，请输入口令：")
        except EOFError:
            raise KeyPasswordRequired(
                f"无法读取口令（当前环境不可交互）；"
                f"请用 --password 或 --password-env 提供私钥 {path} 的口令"
            ) from None
        if not password:
            raise KeyPasswordRequired(f"未输入口令，无法加载私钥 {path}。") from None
        return load_private_key(path, password=password)


def cmd_decrypt(args):
    password = getattr(args, "content_password", None)
    if not password and not args.priv:
        print("错误：解密需要 --priv（私钥模式）或 --content-password（密码模式）之一。",
              file=sys.stderr)
        return 2
    # 两个凭证各自独立加载：混合目录里公钥/密码两种文件可以一起解
    priv = None
    if args.priv:
        priv = _load_private_with_prompt(args.priv, args.password, args.password_env)
    files = _collect_forjiang(args.paths, args.recursive)
    if not files:
        print("没有待解密的 .forjiang 文件。", file=sys.stderr)
        return 1
    out_dir = args.out or os.path.dirname(os.path.abspath(files[0]))
    failures = 0
    for path in files:
        try:
            if is_password_format(path):
                if not password:
                    raise HeaderError("这是密码模式加密的文件，请用 --password 解密")
                staging = os.path.join(out_dir, ".forjiang-staging-" + os.path.basename(path))
                try:
                    r = password_decrypt_file(
                        path, staging, password,
                        progress=None if args.quiet else _progress_printer(os.path.basename(path)),
                    )
                finally:
                    pass
                restored = os.path.join(out_dir, _sanitize_name(r.origin or strip_forjiang(path)))
                if os.path.exists(restored) and not args.force:
                    os.unlink(staging)
                    raise FileExistsError(f"输出已存在: {restored} (--force 可覆盖)")
                os.replace(staging, restored)
                result_output = restored
            else:
                if priv is None:
                    raise HeaderError("这是公钥模式加密的文件，请用 --priv 解密")
                result = decrypt_forjiang(
                    path,
                    out_dir,
                    priv,
                    keep_txt=args.keep_txt,
                    force=args.force,
                    progress=None if args.quiet else _progress_printer(os.path.basename(path)),
                )
                result_output = result.restored_path or result.output_path
        except FileExistsError as exc:
            print(f"跳过：{exc}", file=sys.stderr)
            failures += 1
            continue
        except (ForjiangCryptoError, OSError) as exc:
            # 解密侧单独的 OSError 多为还原名在当前平台写不下去（比如文件头是
            # 另一台机器写的，名字带 : * ? 这类字符）：跳过这个文件继续，
            # 别让一个怪名字带走整批。
            print(f"失败：{path}: {exc}", file=sys.stderr)
            failures += 1
            continue
        mode = "密码模式" if is_password_format(path) else "公钥模式"
        print(f"解密[{mode}] {path} -> {result_output}")
    if failures:
        print(f"{failures} 个文件未处理。", file=sys.stderr)
        return 1
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="forjiang_crypto",
        description="AES-256-GCM 文件加密系统：公钥封装会话密钥，上传文件统一改 .txt 后加密为 .forjiang",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="生成 RSA 密钥对")
    p.add_argument("--out", default=".", help="输出目录（默认当前目录）")
    p.add_argument("--name", default="forjiang", help="密钥文件名前缀")
    p.add_argument("--bits", type=int, default=DEFAULT_RSA_BITS, help="RSA 模长（默认 3072）")
    p.add_argument("--password", help="加密私钥的口令（不给则私钥不加密）")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("encrypt", help="加密文件/目录（--pub 公钥模式或 --password 密码模式）")
    p.add_argument("paths", nargs="+", help="待加密的文件或目录")
    p.add_argument("--pub", help="公钥 PEM 路径（公钥模式必填）")
    p.add_argument("--content-password", help="内容密码（密码模式；与 --pub 二选一）")
    p.add_argument("--out", help="输出目录（默认与输入同目录）")
    p.add_argument("-r", "--recursive", action="store_true", help="递归处理目录")
    p.add_argument("--keep-txt", action="store_true", help="保留 .txt 中转件")
    p.add_argument("--force", action="store_true", help="覆盖已存在的输出")
    p.add_argument("--quiet", action="store_true", help="不打印进度")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="解密 .forjiang 文件/目录（按文件头自动识别模式）")
    p.add_argument("paths", nargs="+", help="待解密的 .forjiang 文件或目录")
    p.add_argument("--priv", help="私钥 PEM 路径（公钥模式必填）")
    p.add_argument("--content-password", help="内容密码（密码模式；与 --priv 二选一）")
    p.add_argument("--out", help="输出目录（默认与输入同目录）")
    p.add_argument("-r", "--recursive", action="store_true", help="递归处理目录")
    p.add_argument("--keep-txt", action="store_true", help="保留 .txt 中转件")
    p.add_argument("--force", action="store_true", help="覆盖已存在的输出")
    p.add_argument("--password", help="私钥口令")
    p.add_argument("--password-env", help="从该环境变量读取私钥口令")
    p.add_argument("--quiet", action="store_true", help="不打印进度")
    p.set_defaults(func=cmd_decrypt)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except ForjiangCryptoError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"错误：文件操作失败：{exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
