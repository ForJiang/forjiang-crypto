# forjiang-crypto

AES-256-GCM 文件加密系统。上传的文件先统一改成 `.txt`，加密后把后缀改为
`.forjiang`；解密是相反的流程。

公钥加密：加密只需要公钥（RSA），私钥从不参与加密端。采用混合加密——
每个文件一把随机 AES-256 会话密钥加密内容，会话密钥用 RSA-OAEP(SHA-256)
封装后写进文件头。解密必须有对应私钥。

## 安装

```bash
pip install -r requirements.txt   # 或 pip install .
```

`requirements.txt` 只列一个第三方依赖：`cryptography>=3.4`。
不安装也能用：把仓库放到任意位置，`cd` 进来后
`python3 -m forjiang_crypto ...` 即可（或设置 `PYTHONPATH` 指向仓库根目录）。
`pip install .` 后会得到 `forjiang-crypto` 命令。

如果你的 Python 是 uv 装的（`python3 -m pip install` 被拒，报
`error: externally-managed-environment`，提示“This Python installation is
managed by uv”），按下面顺序挑一条能用的即可；启动器会自动逐级尝试：

```bash
uv pip install --system -r requirements.txt          # uv 装的 Python 用这条
python3 -m pip install --user -r requirements.txt    # 不写系统目录
python3 -m pip install --break-system-packages -r requirements.txt  # 显式允许
```

## 快速开始

```bash
# 1) 生成密钥对（默认 RSA-3072，私钥权限 0600）
python3 -m forjiang_crypto keygen --out ./keys

# 2) 加密：uploads/ 下所有文件 -> vault/ 下对应的 .forjiang
python3 -m forjiang_crypto encrypt ./uploads \
    --pub ./keys/forjiang.pub.pem --out ./vault -r

# 3) 解密：vault/ 下所有 .forjiang -> restored/ 下恢复原名
python3 -m forjiang_crypto decrypt ./vault \
    --priv ./keys/forjiang.priv.pem --out ./restored -r
```

结果对照（`photo.png` 为例）：

| 步骤 | 文件 |
| --- | --- |
| 上传的原件 | `uploads/photo.png`（不动） |
| 统一改名中转 | `vault/photo.png.txt` |
| 加密产物 | `vault/photo.png.forjiang` |
| 解密中转件 | `restored/photo.png.txt` |
| 恢复原文件 | `restored/photo.png` |

`.txt` 中转件默认用完即删（加密后删、恢复原名后删），`--keep-txt` 可保留。
输入文件本身永远不会被修改或删除。

## 用法细节

### encrypt

```bash
python3 -m forjiang_crypto encrypt <文件或目录...> --pub <公钥.pem> \
    [--out 目录] [-r] [--keep-txt] [--force] [--quiet]
```

### decrypt

```bash
python3 -m forjiang_crypto decrypt <文件或目录...> --priv <私钥.pem> \
    [--out 目录] [-r] [--keep-txt] [--force] [--quiet] \
    [--password 口令 | --password-env 变量名]
```

- **两种加密模式二选一**：`--pub 公钥`（公钥模式，只需公钥）或
  `--content-password 密码`（密码模式，PBKDF2-SHA256 60 万次迭代派生
  AES-256 密钥）。两者不能同时给。解密时按文件头自动识别模式：
  ```bash
  # 密码模式加密
  python3 -m forjiang_crypto encrypt ./photo.png --content-password '你的密码' --out ./vault
  # 混合目录一起解（两种凭证都给它，按文件头自动分流）
  python3 -m forjiang_crypto decrypt ./vault --priv ./keys/forjiang.priv.pem \
      --content-password '你的密码' --out ./restored
  ```
- 公钥模式下加密**只需要公钥**；解密必须私钥。私钥有口令时用 `--password` 或
  `--password-env 变量名`；两者都不给时程序会交互式询问（stdin 不可交互的
  环境会得到明确报错，提示改用 `--password`/`--password-env`）。
- “没给口令”和“口令错误”是两种不同的报错，前者才会触发交互式追问。
- 输出已存在时不覆盖，报错退出；`--force` 强制覆盖。已存在**且内容一致**时
  （解密回原位的典型场景）视为无冲突。
- `.forjiang` 文件出现在 encrypt 的输入里会自动跳过。

### keygen

```bash
python3 -m forjiang_crypto keygen [--out 目录] [--name 前缀] \
    [--bits 2048|3072|4096] [--password 口令]
```

- 小于 2048 位的请求会被拒绝。
- 私钥落盘为 0600；加 `--password` 则以 PBES2 加密存储。
- 公钥是 X.509 SubjectPublicKeyInfo PEM，可以直接分发；也支持加载 OpenSSH
  格式公钥（`ssh-keygen` 生成的 `.pub`）。

## Web 界面

界面有两个版本，双击启动器后默认进入**简版**：

| | 简版（默认 `/`） | 完整版（`/full`） |
| --- | --- | --- |
| 加密方式 | 密码（PBKDF2 派生密钥） | RSA 公钥封装会话密钥 |
| 操作 | 多选文件、或选整个文件夹（输入框+“浏览...”选目录，产物打包成 zip 下载）、设密码、点按钮 | 生成密钥对、批量加密、目录选择 |
| 适合 | 单人快速加解密文件 | 需要公钥分发/批量/脚本化 |

两个版本共用同一套设计（配色/卡片/按钮/日志样式一致，都跟随系统深浅色），页面顶部/底部有互相切换的入口，产物格式互通、CLI 也能解
（解密时按文件头魔数自动识别是哪种模式）。

### 双击启动（推荐给不写代码的人）

项目里带了两个一键启动器，双击即用，不用记命令：

- **macOS**：双击 `打开网页界面.command`（首次使用如系统提示无法打开，右键
  选择“打开”，或在终端执行一次 `chmod +x "打开网页界面.command"`）。
- **Windows**：双击 `start-webui.bat`。

启动器会依次做四件事：找到 Python（找不到会提示去官网安装）、缺少
`cryptography` 时自动安装、启动网页服务、自动打开浏览器进入界面。
自动安装不是只试一条命令，而是按环境逐级兜底，每一步都以“真的能
import”为唯一成功标准：**有 `uv` 用 `uv`**（uv 管理的 Python 会按
PEP 668 拒绝 `pip install`，报 `externally-managed-environment`）→ 普通
`pip` → `pip install --user` → `pip install --break-system-packages`；
以上都失败时，最后在项目目录建一个与系统隔离的 `.venv`，之后都从这个虚拟
环境启动（第一次慢一点，之后零安装秒开）。**启动窗口要保持开着**——关掉
窗口服务就停了。想换端口：macOS 在终端先
`export PORT=9000` 再双击，Windows 先 `set PORT=9000` 再双击（或
`set PORT=9000 && start-webui.bat`）。

如果端口上已经有本系统的界面在运行（比如之前双击过、窗口还没关），启动器
不会去抢端口，而是检测到后直接打开浏览器用现成的那个，并提示“关闭那个
窗口才是真正停止服务”。

端口被**别的**程序占用时不再报错了事：服务会自动往后找最近的空闲端口
（默认从你给的端口起最多试 20 个）并明确打一行提示，浏览器跟着打开新端口，
所以“换个端口再试”这种手工操作基本不用做了。整段端口都被占满时才给友好的
换端口提示，依旧不甩堆栈。两个启动器都会用 `PYTHONUTF8=1` 跑 Python、
加 `-u` 关缓冲，老机器 ASCII locale 下中文路径和中文日志不会
`UnicodeEncodeError`，端口被换掉的信息也不会卡在缓冲区里看不见。
没有图形浏览器的环境（SSH、精简 Linux、容器）会显式打印地址让你手敲。

**路径都由你选，不用手打**：密钥目录、公钥/私钥文件、加密输出目录、解密
输出目录这五处，右边都有“浏览…”按钮，点它弹出系统原生的文件夹/文件选择框，
选中后真实绝对路径自动填回输入框（浏览器拿不到本机路径，所以由服务端弹
系统对话框来实现；没有 tkinter 或没有图形会话的环境会自动隐藏这些按钮，
退回手动输入）。加密区还可以勾选“选择整个文件夹”，一次对整个目录（含子
目录）批量加密，不同子目录里的重名文件会自动带上子目录名避免互相覆盖。

### 开发者方式启动

```bash
python3 -m webui [--host 127.0.0.1] [--port 8765] [--open]
```

然后在浏览器打开终端里打印的地址（默认 http://127.0.0.1:8765/）。
页面就是上面三步的图形版，没有额外概念：

1. **生成密钥对** —— 选模长、可设私钥口令，密钥落盘到指定目录；
2. **加密** —— 多选文件、填公钥路径和输出目录，可选保留 `.txt` 中转件 /
   覆盖已存在输出；
3. **解密** —— 多选 `.forjiang` 文件、填私钥路径和口令，恢复到输出目录。

**路径一律不预填**：五个路径框（密钥目录、公钥、加密输出目录、私钥、解密
输出目录）打开时都是空的，由你自己用“浏览...”按钮选或手动输入——不会偷偷
把密钥和密文写进代码仓库。懒得选时点“填入默认路径”一键填成默认数据目录
`~/forjiang-crypto` 下的 `keys/`、`vault/`、`restored/`（拿不到可用的主目录
时退回服务根目录；设了环境变量 `FORJIANG_CRYPTO_DATA_DIR` 则以它为准，
测试与多份数据分开存时用得上）。路径为空时点按钮会被拦下并提示，服务端同样
拒绝空
`outdir`，不会落到服务根目录。手动改过“密钥目录”后，已填的公钥/私钥路径会
跟着变，指向别处的自定义路径则保持不动。

界面只是 `forjiang_crypto` 库的一层壳，产物和 CLI 逐字节一致；每个文件的
成功/失败都会列出来，失败不影响同批其他文件。服务端按 1 MiB 流式解析上传
内容，大文件不吃内存。

界面跟随系统的浅色/深色模式自动切换（CSS 变量 + prefers-color-scheme，原生控件同样跟随），无需手动设置。

**安全边界**：服务默认只绑 `127.0.0.1`，只能本机访问——因为界面按你填的
路径直接读写本机文件。改成 `--host 0.0.0.0` 会把“按任意路径加解密”的能力
暴露给整个局域网，仅在可信网络里、且明白后果时使用。

```python
from forjiang_crypto import (
    generate_keypair, encrypt_uploaded, decrypt_forjiang,
)

kp = generate_keypair(2048)                 # 或 save_keypair 存盘后再 load_*

r = encrypt_uploaded("uploads/photo.png", "vault", kp.public_key)
# r.output_path == "vault/photo.png.forjiang"，r.origin == "photo.png"

back = decrypt_forjiang("vault/photo.png.forjiang", "restored",
                        kp.private_key)
# back.restored_path == "restored/photo.png"，内容与原件逐字节一致
```

底层原语 `encrypt_stream(fin, fout, pub)` / `decrypt_stream(fin, fout, priv)`
可直接操作文件对象，适合接入自己的上传下载流程，不必落地中间文件。

**密钥格式**：公钥支持 PEM（X.509 SubjectPublicKeyInfo / PKCS#1）、OpenSSH
公钥、DER；私钥支持 PKCS#8 PEM、DER 和 **OpenSSH 格式**（`ssh-keygen` 默认
产出的 `id_rsa`），加密私钥用 PBES2 或 SSH 的 bcrypt 加密（后者需要额外装
`bcrypt` 库才能生成，解密不需要）。只支持 RSA，且模长至少 2048 位。

## 兼容性（跨平台、跨机器、批量）

- **奇怪的文件名不会毁掉整批**：名字带非法 UTF-8 字节（Linux 文件系统允许
  Python 用 surrogateescape 表达）时，早期版本会 `UnicodeEncodeError` 裸崩——
  它不是 `OSError`，连兜底都拦不住。现在编码走 `os.fsencode/fsdecode`，同一台
  机器上加密解密照样原样往返。控制字符（换行、响铃等）统一替换成 `_`，
  因为它们会污染日志和 zip 列表。路径穿越（`../`）依旧被拦。
- **跨机器解密按目标平台清洗文件名**：文件头里记的是原始名（忠实保留），
  落盘时按当前平台处理：Windows 上 `: * ? " < > |`、结尾的点/空格、保留
  设备名（`CON`/`NUL`/`COM1`…）替换或加前缀；超过目录 `NAME_MAX`（通常 255
  字节）时截断但保住扩展名。所以在 mac 上加密的名字拿到 Windows 上解密，
  是“改名后成功还原”，而不是失败。
- **批量容错**：一个文件读不了、写不下、名字不合法，只让它自己失败并单独
  报告，其余文件照常处理；退出码照实反映“有失败项”，但不会中途退出或甩
  traceback。网页界面里每个文件的成败单独列一行。
- **服务端接口不回 HTML 错误页**：任何未预期异常都返回一行干净的 JSON 错误，
  堆栈只打到启动器控制台，页面显示可读的一句话而不是白屏或解析失败。
- **模式自动识别**：解密时按文件头魔数判断公钥模式还是密码模式；文件不存在、
  读不了、或两种魔数都不是时直接说清楚（“读取失败 / 不是本系统加密的文件”），
  不会误报成“这是公钥模式加密的文件，请用 --priv 解密”。
- **并发安全**：界面服务是多线程的，解密中转件名和文件夹打包的 zip 名都带本次
  请求的唯一后缀，两个同时进行的请求不会互相覆盖。
- **`--out` 指向不存在的目录会自动创建**（公钥模式和密码模式一致）。
- 界面只监听 `127.0.0.1` 回环，不对外暴露；依赖只有一个 `cryptography`，
  Python 3.8+ 可用，无 pytest 也能跑（stdlib unittest）。

## 安全设计

- **算法**：AES-256-GCM（认证加密）。每个文件独立的随机 96-bit nonce 和
  256-bit 会话密钥；GCM tag 16 字节。相同明文两次加密产物不同。
- **密钥封装**：RSA-OAEP with SHA-256（MGF1-SHA-256），模长 ≥2048，
  更大会自动带出更长的封装字段。
- **防篡改**：整个文件头（含封装密钥、nonce、原文件名）作为 GCM 的
  AAD。改文件名、改密文、截断文件、换错私钥，全部在 `finalize` 阶段被
  tag 拒绝，抛 `TamperError`，不会产出半个明文。
- **路径安全**：文件头里的原文件名只取最后一段（basename），
  `../../etc/passwd` 这类值写进头就会被剥成 `passwd`，解密恢复时不会
  写到目录外。
- **流式**：加解密按 1 MiB 分块进行，内存占用与文件大小无关，GB 级文件可用。
- **原子落盘**：加密/解密结果先写同目录的隐藏临时文件，全部成功后
  `os.replace` 到目标名；任何异常（含 Ctrl-C）都会清掉临时文件，
  不会留下半成品。
- **随机数**：nonce 与会话密钥均取自 `os.urandom`；每个文件一把新会话密钥，
  nonce 只与其绑定出现一次，重复概率可忽略。
- **已知限制**：
  - 只支持 RSA 公钥封装（不做 ECDH/Ed25519 变体）。
  - `os.walk` 默认不跟随符号链接，遇到链接成的目录会漏掉其中文件。
  - 私钥口令只在内存中传递，不做尝试次数限制（防爆破靠系统层）。

## 文件格式（.forjiang）

```
magic            8  B   b"FORJANG1"
version          1  B   = 1
flags            1  B   = 0
nonce_len        1  B   = 12
tag_len          1  B   = 16
wrapped_key_len  2  B
orig_name_len    2  B
orig_size        8  B   明文字节数
wrapped_key      wrapped_key_len B   RSA-OAEP(SHA-256) 封装的 AES 会话密钥
nonce            nonce_len B         随机，内联在头部
orig_name        orig_name_len B     原文件名（UTF-8，仅 basename）
ciphertext       其余 B               AES-256-GCM 流式加密
tag              末尾 16 B           GCM 认证标签
```

整个头部（prefix + wrapped_key + nonce + orig_name）作为 AAD 参与认证。
头部上限 64 KiB，文件名上限 512 字节。

## 打包发布

```bash
python3 package.py              # 默认：同一个 x.y 系列里第三位 +1（1.2.0 -> 1.2.1）
python3 package.py --minor      # 开新小系列：1.2.x -> 1.3.0
python3 package.py --major      # 开新大版本：1.2.x -> 2.0.0
python3 package.py --dry-run    # 只看会打成什么版本号
```

打包时 `pyproject.toml` 与
`forjiang_crypto/__init__.py` 里的版本号同步改成新值，新 zip 以
`forjiang-crypto-<版本>.zip` 命名，**已有的旧包一律保留、不做任何改动**。
同系列打包时新版本号取“已存在的最大第三位”与“当前版本号的第三位”中较大者
加一，即使手工改过版本号也不会覆盖或回退；`--minor/--major` 开新系列时，该
系列还没有打过包就原样采用新版本号（1.2.0 打 `--minor` 就是 1.3.0，不跳号）。
`--out 目录` 换输出位置。排除 `__pycache__`/`.pyc`/`.DS_Store`/`.venv`；
`.command` 启动器在包里强制带可执行位，解压后 macOS 可直接双击。

## 测试

```bash
python3 tests/test_crypto.py    # 库级：格式/流式加解密/密码模式/文件名兼容/
                                 # OpenSSH 私钥/块长度回归（网页版超大块拒解）
python3 tests/test_cli.py       # 子进程真实调用 CLI，覆盖口令/--force/
                                 # --keep-txt/错误路径/批量容错/超长密文名
python3 tests/test_webui.py     # 真实起 HTTP 服务走完整流程：简版/完整版
                                 # 路由、页面接口地址一致性、端口自动切换与
                                 # 换端口提示、启动器装依赖兜底链守门、原生
                                 # 选择框容错与诊断、数据目录隔离、zip 不互相覆盖等
python3 tests/test_package.py   # 打包脚本：排除 .venv/node_modules/__pycache__、
                                 # 同系列第三位 +1 且不回退、--minor/--major 不跳号
```

一共 118 项（缺 bcrypt 的环境会跳过一项加密 OpenSSH 测试），全绿即“可交付”。

## 目录结构

```
forjiang-crypto/
├── forjiang_crypto/
│   ├── __init__.py     公开 API 汇总
│   ├── __main__.py     入口
│   ├── cli.py          keygen/encrypt/decrypt 子命令
│   ├── codec.py        .forjiang 格式 + 流式加解密 + 上传改名流程
│   ├── keys.py         RSA 密钥生成/加载/封装
│   └── exceptions.py   异常层级(含 KeyPasswordRequired)
├── tests/
│   ├── test_crypto.py  库级测试
│   ├── test_cli.py     CLI 级测试
│   ├── test_webui.py   Web 界面端到端测试
│   └── test_package.py 打包脚本测试
├── webui/
│   ├── __init__.py
│   ├── __main__.py     python3 -m webui 入口
│   ├── server.py       本地 HTTP 服务 + 流式 multipart 解析
│   ├── simple.html     简版界面（默认落地页，密码模式）
│   └── index.html      完整版界面（公钥模式，在 /full）
├── 打开网页界面.command   macOS 双击启动（网页界面）
├── start-webui.bat       Windows 双击启动（网页界面）
├── package.py            打包脚本（版本第三位 +1，不覆盖旧包）
├── pyproject.toml
├── requirements.txt
└── README.md
```
