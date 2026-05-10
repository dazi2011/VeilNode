# VeilNode Suite 中文说明

> 离线信封加密：把密文藏进普通载体文件。
> 套件版本 **0.3.2** · 加密内核 **2.2** · 单元测试 107/107 通过。

[English README](README.md) · [技术细节](docs/TECHNICAL.zh-CN.md) · [平台矩阵](docs/PLATFORMS.zh-CN.md)

VeilNode Suite 把明文先加密，再把密文封装进看起来普通的载体文件
（zip / png / mp4 / pdf / wav 等），输出后会验证载体能否正常解析，并把
"加密内核"和"载体封装策略"明确分离。套件由这些部分组成：

- **`veil-core`** — Python 实现：crypto、消息格式、自适应信封策略、doctor、
  test vectors。是唯一的真实来源（single source of truth）。
- **CLI** — `veil-node` / `veil-factory`，由 `veil-core` 提供。
- **桌面 GUI** — macOS 原生 SwiftUI、Windows Tk 包装。
- **移动端伴侣 App** — iOS / iPadOS（SwiftUI）和 Android（Java）。
  它们是诚实的"伴侣 App"：负责导入载体、计算 SHA-256、显示匹配的 CLI 命令。
  **它们不内嵌 Python 加密内核，也不在设备上做解密**。

VeilNode 不承诺"不可检测"。我们使用更准确的工程表述：低固定特征、
元数据最小化、载体保真校验、本地工程风险评分。

## 加密内核边界

自适应策略层永远不发明也不修改密码学。以下内容**由内核固定**，任何
策略 / 模型都不能修改：

`root_vkp` · HKDF · Argon2id · AEAD · `msg_id` · `message_salt` ·
`file_hash` · root 派生的 `vkp_i` 和 `message_key` 派生。

策略层只能选择**封装/载体行为**：嵌入策略、chunk 切分、padding、
加密 metadata 布局、locator 策略、载体放置方式、候选排序。

`crypto_core_version = "2.2"` 是消息/内核兼容标记，**不是套件软件版本**。
v1/v2 读取兼容仍保留；`crypto_core_version = "1.0"` 不再是可选择的内核。

## 安装

```bash
python3 -m pip install -e .
veil-node --help
veil-node doctor
```

本地演示可以加快 KDF：

```bash
export VEIL_FAST_KDF=1
```

## 命令组织

命令按"对象 + 动作"组织：

```text
veil-node identity ...
veil-node contact ...
veil-node keypart root ...
veil-node seal INPUT CARRIER OUTPUT ...
veil-node open MESSAGE --out DIR ...
veil-node carrier audit | compare | profile ...
veil-node strategy features | generate | select | score | scan-signature ...
veil-node strategy collect | train | model | policy ...
veil-node package --release --out dist/release
```

新文档统一使用 `seal` / `open` / `strategy …`。旧式写法只作为兼容说明。

## 自适应信封快速开始

```bash
mkdir -p .demo

veil-node --home .demo/alice identity create \
  --name alice --password idpass --overwrite

veil-node --home .demo/alice identity export --out .demo/alice.vid
veil-node --home .demo/alice contact import .demo/alice.vid --alias alice

veil-node keypart root create \
  --out .demo/root.vkpseed --password rootpass --label alice-bob

echo "secret" > .demo/secret.txt
python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY

veil-node strategy select \
  --carrier .demo/cover.zip --payload .demo/secret.txt \
  --count 20 --json

veil-node --home .demo/alice seal \
  .demo/secret.txt .demo/cover.zip .demo/message.zip \
  --to alice --password msgpass \
  --root-keypart .demo/root.vkpseed --root-keypart-password rootpass \
  --crypto-core 2.2 --low-signature \
  --adaptive-policy --policy-candidates 20 \
  --policy-out .demo/selected.policy.json

veil-node carrier audit --input .demo/message.zip --json
veil-node carrier compare --before .demo/cover.zip --after .demo/message.zip --json
veil-node strategy scan-signature --input .demo/message.zip --json

veil-node --home .demo/alice open \
  .demo/message.zip --out .demo/out \
  --password msgpass --identity-password idpass \
  --root-keypart .demo/root.vkpseed --root-keypart-password rootpass
```

所有 open 失败统一返回一句话：

```text
Unable to open message.
```

这是有意为之 —— CLI 不会告诉调用方为什么打不开，避免泄露 key /
padding / carrier 信号。

## 自适应信封策略引擎

代码位于 `veil_core/strategy/`：

| 文件 | 职责 |
| --- | --- |
| `features.py` | 提取载体和明文的工程特征 |
| `policy.py` | 校验 `EnvelopePolicy`，拒绝看似密钥的字段 |
| `registry.py` | 注册合法的策略名称与约束 |
| `generator.py` | 从特征/容量生成候选策略 |
| `selector.py` | 候选 dry-run、verify-carrier、audit、compare、score、择优 |
| `scorer.py` | 大小 / 熵 / 结构 / 元数据 / 解析有效性 / 明文签名 |
| `dataset.py` | 写出不含密钥的 JSONL 训练数据 |
| `trainer.py` / `model.py` | 训练和检查可移植的启发式排序器 |

policy / dataset / model 一律不能含 root seed、`root_vkp`、`vkp_i`、
`message_key`、密码或私钥材料。模型只做候选排序，最终输出仍由本地
verify / audit / compare / score 决定。

```bash
veil-node strategy list --format zip
veil-node strategy policy inspect --in selected.policy.json
veil-node strategy score --before cover.zip --after message.zip \
  --policy selected.policy.json --json
veil-node strategy collect --samples-dir samples --payloads-dir payloads \
  --out dataset.jsonl --candidates-per-sample 30
veil-node strategy train --dataset dataset.jsonl --out model.json
veil-node strategy model inspect --in model.json
```

## 客户端

| 平台 | 路径 | 状态 | 构建产物 |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | 原生 SwiftUI 桌面 App，内嵌 `veil-core`。 | `VeilNode-macOS.dmg` |
| Windows | `clients/windows/` | Tk 桌面 GUI + zipapp + `BuildExe.bat`。 | `VeilNode-Windows.zip` |
| iOS / iPadOS | `clients/ios/` | SwiftUI 伴侣 App：导入、SHA-256、复制 CLI 命令。 | `VeilNode-iOS-iPadOS.ipa`（仅签名时） |
| Android | `clients/android/` | Java 伴侣 App：导入、SHA-256、复制 CLI 命令。 | `VeilNode-Android-debug.apk` |
| Linux | — | 仅 CLI。 | `veil-node` |
| NAS | — | 仅 CLI。 | `veil-node` |

移动端伴侣 App 故意不做加密栈：把 Python core 安全嵌入 iOS 是另一项
工程，与其做半吊子的 in-app 加密，不如把擅长的事做好 —— 通过 Files /
SAF 导入、用系统 crypto 计算哈希、把对应的 CLI 命令展示给用户去桌面跑。

## 一键构建脚本

Release bundle 同时打包所有平台的 helper，源树解开就能跑：

| 脚本 | 产出 | 依赖 |
| --- | --- | --- |
| `clients/windows/BuildExe.bat` | `veil-node.exe` | Windows + Python + PyInstaller |
| `clients/android/BuildApk.sh` | `VeilNode-Android-debug.apk` | macOS / Linux + JDK 17+ + Gradle + Android SDK |
| `clients/android/BuildApk.bat` | `VeilNode-Android-debug.apk` | Windows + JDK 17+ + Gradle + Android SDK |
| `clients/ios/BuildIpa.sh` | `VeilNode-iOS-iPadOS.ipa` | macOS + Xcode + `xcodegen` + `VEILNODE_DEVELOPMENT_TEAM` |

## Release 打包

```bash
veil-node package --release --out dist/release
```

manifest 会标明每个产物是 built 还是 blocked：

- `VeilNode-macOS.dmg` — 当 SwiftPM 与 `hdiutil` 可用时构建。
- `VeilNode-Windows.zip` — 跨平台便携包（GUI + zipapp + 全部 `Build*`
  helper + 源树）。在任何平台解开后都能用对应的 `Build*` 脚本本地构建。
- `VeilNode-Android-debug.apk` — 当 JDK + Gradle + Android SDK 齐全时
  生成 debug-signed APK。
- `VeilNode-iOS-iPadOS.ipa` — 仅当 `VEILNODE_DEVELOPMENT_TEAM` 设置
  且 Xcode 能创建或复用 provisioning profile 时生成。绝不伪造未签名 IPA。

构建产物只放在 `dist/` 或 GitHub Releases，不进源码仓库。`.gitignore`
已经排除。

## 验证

```bash
python3 -m unittest discover -s tests -v   # 107 个测试
python3 -m veil_core doctor
python3 -m veil_core test-vector
```
