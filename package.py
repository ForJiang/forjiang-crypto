#!/usr/bin/env python3
"""打包脚本：每次打包版本号第三位 +1，生成新 zip，旧包一律保留。

用法（在项目根目录）：
    python3 package.py            # 打包到项目目录旁边
    python3 package.py --out 目录 # 指定输出目录

规则：
1. 版本号在同一个 x.y 系列里“前进一位”= 第三位 +1，
   例如 1.1.0 -> 1.1.1 -> 1.1.2；因此永远不会覆盖已有 zip。
2. pyproject.toml 与 forjiang_crypto/__init__.py 的版本号同步改为新版本，
   保证 zip 文件名和代码里的 __version__ 一致。
3. 排除 __pycache__/.pyc/.DS_Store；.command 启动器强制带可执行位。
"""

import argparse
import os
import re
import sys
import zipfile

ROOT = os.path.dirname(os.path.abspath(__file__))
NAME = "forjiang-crypto"
PYPROJECT = os.path.join(ROOT, "pyproject.toml")
INIT_PY = os.path.join(ROOT, "forjiang_crypto", "__init__.py")

EXCLUDE_DIRS = {"__pycache__", ".git", ".pytest_cache"}
EXCLUDE_SUFFIX = (".pyc", ".pyo", ".zip")
EXCLUDE_NAMES = {".DS_Store"}

VERSION_RE = re.compile(r'^(\s*version\s*=\s*")(\d+)\.(\d+)\.(\d+)(")', re.M)
INIT_VERSION_RE = re.compile(r'(__version__\s*=\s*")(\d+)\.(\d+)\.(\d+)(")')


def read_versions():
    """返回 pyproject 与 __init__.py 里的版本三元组。"""
    def grab(pattern, text):
        m = pattern.search(text)
        if not m:
            raise SystemExit(f"版本号解析失败: {pattern.pattern!r}")
        return tuple(int(m.group(i)) for i in (2, 3, 4))

    with open(PYPROJECT, encoding="utf-8") as fh:
        pyproject_v = grab(VERSION_RE, fh.read())
    with open(INIT_PY, encoding="utf-8") as fh:
        init_v = grab(INIT_VERSION_RE, fh.read())
    if pyproject_v != init_v:
        raise SystemExit(
            f"版本号不一致：pyproject.toml={'.'.join(map(str, pyproject_v))} "
            f"vs __init__.py={'.'.join(map(str, init_v))}，请先手工对齐"
        )
    return pyproject_v


def existing_patches(out_dir, major, minor):
    """输出目录里已有的 forjiang-crypto-x.y.z.zip 中，同一个 x.y 系列下的最大第三位。"""
    best = 0
    pattern = re.compile(rf"^{re.escape(NAME)}-(\d+)\.(\d+)\.(\d+)\.zip$")
    if os.path.isdir(out_dir):
        for name in os.listdir(out_dir):
            m = pattern.match(name)
            if m and int(m.group(1)) == major and int(m.group(2)) == minor:
                best = max(best, int(m.group(3)))
    return best


def bump(out_dir):
    """版本号在同一个 x.y 系列里前进一位：第三位 +1。

    例如 1.1.0 -> 1.1.1 -> 1.1.2。取 max(当前第三位, 已有包的最大第三位)+1，
    并检查目标 zip 未占用，保证绝不覆盖旧包。
    """
    major, minor, patch = read_versions()
    return major, minor, max(patch, existing_patches(out_dir, major, minor)) + 1


def write_version(version):
    text_v = ".".join(map(str, version))
    for path, pattern in ((PYPROJECT, VERSION_RE), (INIT_PY, INIT_VERSION_RE)):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        new_text, n = pattern.subn(lambda m: m.group(1) + text_v + m.group(5), text, count=1)
        if n != 1:
            raise SystemExit(f"无法写回版本号: {path}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(new_text)
    return text_v


def iter_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS)
        for name in sorted(filenames):
            if name in EXCLUDE_NAMES or name.endswith(EXCLUDE_SUFFIX):
                continue
            full = os.path.join(dirpath, name)
            yield full


def build_zip(zip_path):
    count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for full in iter_files():
            arc = os.path.join(NAME, os.path.relpath(full, ROOT))
            info = zipfile.ZipInfo.from_file(full, arc)
            info.compress_type = zipfile.ZIP_DEFLATED
            if name_is_launcher(os.path.basename(full)):
                # .command 必须是可执行的，否则 macOS 双击无效
                info.external_attr = (0o755 & 0xFFFF) << 16
            with open(full, "rb") as fh:
                zf.writestr(info, fh.read())
            count += 1
    return count


def name_is_launcher(name):
    return name.endswith(".command") or name.endswith(".bat")


def main(argv=None):
    parser = argparse.ArgumentParser(description="打包 forjiang-crypto（版本第三位 +1，不覆盖旧包）")
    parser.add_argument("--out", default=os.path.dirname(ROOT),
                        help="输出目录（默认项目目录旁边）")
    parser.add_argument("--dry-run", action="store_true", help="只显示将要生成的版本号")
    args = parser.parse_args(argv)

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    version = bump(out_dir)
    text_v = ".".join(map(str, version))
    zip_path = os.path.join(out_dir, f"{NAME}-{text_v}.zip")

    if args.dry_run:
        print(f"新版本将是: {text_v} -> {zip_path}")
        return 0
    if os.path.exists(zip_path):
        raise SystemExit(f"目标已存在（不应发生，说明探测逻辑有误）：{zip_path}")

    write_version(version)
    count = build_zip(zip_path)
    size = os.path.getsize(zip_path)
    print(f"已生成: {zip_path}")
    print(f"  版本 {text_v}，{count} 个文件，{size / 1024:.1f} KiB")
    print(f"  pyproject.toml 与 __init__.py 的版本号已同步为 {text_v}")
    print("  旧版本 zip 未做任何改动。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
