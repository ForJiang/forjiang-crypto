# forjiang-crypto

AES-256-GCM 文件加密系统。上传的文件先统一改成 `.txt`，加密后把后缀改为 `.forjiang`；解密是相反的过程，按文件头记录的原始名恢复原名。

两种用法，文件格式完全互通：

- **浏览器版（本仓库的在线页面）**：<https://forjiang.github.io/forjiang-crypto/> —— 打开即用，纯前端实现（WebCrypto），文件不离开本机，不需要安装任何东西。
- **桌面版（本仓库的 Python 源码）**：命令行 + 本地网页界面，额外支持 RSA 公钥加密（加密只需公钥）、目录批量、原生目录选择框。

## 在线页面能做什么

选文件（可多选）、设密码、点按钮，加解密全在浏览器的 WebCrypto 里完成：

1. **加密**：每个文件单独派生一把 256 位密钥（PBKDF2-HMAC-SHA256，60 万次迭代），内容用 AES-256-GCM 分块加密，产物后缀 `.forjiang`，自动下载。
2. **解密**：选 `.forjiang` 文件、输入密码，按文件头里的原始名恢复文件并下载；密码错误或文件被改动会明确报错。

页面只监听你自己的机器，不向任何服务器上传内容；`FJGPASS1` 格式的文件在浏览器版和桌面版之间可以互相解密（下面有实测说明）。

## 桌面版安装

```bash
pip install -r requirements.txt        # 只有一个第三方依赖：cryptography>=3.4
```

不安装也能用：`cd` 进仓库根目录后 `python3 -m forjiang_crypto ...`（或设置 `PYTHONPATH` 指向仓库根目录）。

## 快速开始（命令行）

```bash
# 1) 生成 RSA 密钥对（默认 RSA-3072，私钥权限 0600）
python3 -m forjiang_crypto keygen --out ./keys

# 2) 公钥加密：uploads/ 下所有文件 -> vault/ 下对应的 .forjiang
python3 -m forjiang_crypto encrypt ./uploads \
    --pub ./keys/forjiang.pub.pem --out ./vault -r

# 3) 解密（按文件头魔数自动识别公钥模式还是密码模式）
python3 -m forjiang_crypto decrypt ./vault \
    --priv ./keys/forjiang.priv.pem --out ./restored -r
```

密码模式（不生成密钥，用口令直接加密，格式与浏览器版一致）：

```bash
python3 -m forjiang_crypto encrypt ./photo.png --password-mode \
    --content-password "my-passphrase" --out ./vault
python3 -m forjiang_crypto decrypt ./photo.png.forjiang \
    --content-password "my-passphrase" --out ./restored
```

注意 `decrypt` 的 `--password` 是私钥口令（私钥加密过时用），内容密码用 `--content-password`，别混。

## 本地网页界面

```bash
python3 -m webui --port 8765 --open     # 只监听 127.0.0.1，界面分简版/完整版
```

仓库里带了两个双击即用的启动器：macOS 双击 `打开网页界面.command`，Windows 双击 `start-webui.bat`。启动器会自动找 Python、装依赖（uv 管理的 Python 会走 `uv pip install`，PEP 668 下普通 `pip install` 会被拒，有逐级兜底）、起服务并打开浏览器；端口被别的程序占用时自动换到最近的空闲端口。

界面上的路径都由你自己选（密钥目录、公钥/私钥、输出目录都有"浏览…"按钮弹系统原生选择框），也可以勾选"选择整个文件夹"整目录批量处理。

## 文件格式

### 密码模式 `FJGPASS1`（浏览器版与桌面版 `--content-password` 共用）

```
magic         8  B   b"FJGPASS1"
version       1  B   = 1
kdf           1  B   = 1 (PBKDF2-HMAC-SHA256)
iterations    4  B   大端（默认 600000）
salt_len      1  B   = 16
salt          16 B
name_len      2  B   大端
orig_name     name_len B（UTF-8）
每块：iv(12) + ct_len(4, 大端) + ct（明文 + 16 B GCM tag）
末尾：一个认证过的空块（明文字节数为 0）作为结束标记，截断的文件无法通过认证
```

每块的附加认证数据（AAD）是"整个文件头 + 块序号（8 字节大端）"，所以块被重排、替换或删除都会被发现。

### 公钥模式 `FORJANG1`（桌面版）

混合加密：每个文件一把随机 AES-256 会话密钥加密内容，会话密钥用 RSA-OAEP(SHA-256) 封装后写进文件头；加密只需要公钥，解密必须对应私钥。完整布局见 `forjiang_crypto/codec.py` 顶部注释。

## 安全设计

- **算法**：AES-256-GCM（认证加密）+ 随机 96-bit nonce；相同明文两次加密产物不同。
- **口令派生**：PBKDF2-HMAC-SHA256 60 万次迭代（OWASP 对 PBKDF2-SHA256 的推荐量级），迭代次数写进文件头，以后调大默认值不影响旧文件解密。
- **私钥**：默认未加密 PKCS#8 PEM 落盘（权限 0600），可用 `keygen --password` 加密成 PBES2。
- **完整性**：GCM tag 绑定文件头与块序号；篡改任何一个字节都会在解密时报"认证失败"。
- **原子落盘**：先写隐藏临时文件、校验通过再替换目标，失败不留残留；同名不同内容拒绝覆盖（`--force` 才覆盖）。
- **不泄露路径**：上传文件的原始名显式记录在文件头，服务端临时文件名不会变成产物名。

## 兼容性

- **奇怪的文件名不会毁掉整批**：非法 UTF-8 字节的名字用 `os.fsencode/fsdecode` 处理，不再裸崩；控制字符替换成 `_`；路径穿越被拦。
- **跨平台解密**：文件头保留忠实原名，落盘时按当前平台清洗（Windows 的 `: * ? " < > |`、保留设备名、超长名截断但保扩展名）。
- **批量容错**：一个文件失败只报自己，其余照常处理。
- 依赖只有 `cryptography`，Python 3.8+，无 pytest（stdlib unittest）。

## 测试

```bash
python3 tests/test_crypto.py      # 往返、篡改、大文件、空文件、文件名兼容性等
python3 tests/test_cli.py         # 子进程真实调用 CLI，覆盖口令/--force/--keep-txt/错误路径
python3 tests/test_webui.py       # 真实起 HTTP 服务走完整流程，含端口自动切换与启动器兜底链守门
```

## 目录结构

```
index.html                 浏览器版在线页面（GitHub Pages 打开即用）
forjiang_crypto/           桌面版库：codec / keys / cli
webui/                     桌面版网页界面源码（index.html 完整版 + simple.html 简版 + server.py）
打开网页界面.command        macOS 双击启动
start-webui.bat            Windows 双击启动
tests/                     三套测试
package.py                 打包脚本（同系列第三位 +1，不覆盖旧包）
```

## License

MIT，见 [LICENSE](LICENSE)。
