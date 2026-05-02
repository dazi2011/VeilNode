# VeilNode Suite 中文说明

[English README](README.md)

技术细节见 [docs/TECHNICAL.zh-CN.md](docs/TECHNICAL.zh-CN.md)，英文版见 [docs/TECHNICAL.md](docs/TECHNICAL.md)。平台客户端状态见 [docs/PLATFORMS.zh-CN.md](docs/PLATFORMS.zh-CN.md) / [docs/PLATFORMS.md](docs/PLATFORMS.md)。

VeilNode Suite 是一个离线文件信封工具套件：把明文先加密，再封装进普通载体文件；输出后会验证载体能否正常解析，并把“加密内核”和“载体封装策略”分开。

当前离线信封内核是 `crypto_core_version = "2.2"`。它是消息/内核兼容标记，不是 VeilNode Suite 软件版本号。旧的 v1/v2 读取兼容仍保留，但 `crypto_core_version = "1.0"` 不再是可选择或支持的加密内核。

VeilNode 不承诺“不可检测”。项目只使用更准确的工程表述：低固定特征、元数据最小化、载体格式保真检查、本地工程风险评分。

## 加密边界

自适应策略层不能发明或修改密码学。以下内容固定：

- `root_vkp`
- HKDF
- Argon2id
- AEAD
- `msg_id`
- `message_salt`
- `file_hash`
- root 派生的 `vkp_i` 和 `message_key`

策略层只能选择封装和载体行为：嵌入策略、chunk 分布、padding 策略、加密 metadata 布局、locator 策略、载体放置方式和候选排序。

## 安装

```bash
python3 -m pip install -e .
veil-node --help
```

本地演示可以开启快速 KDF：

```bash
export VEIL_FAST_KDF=1
```

## 命令组织

命令按对象组织：

```text
veil-node identity ...
veil-node contact ...
veil-node keypart root ...
veil-node seal INPUT CARRIER OUTPUT ...
veil-node open MESSAGE --out DIR ...
veil-node carrier audit|compare|profile ...
veil-node strategy features|generate|select|score|collect|train|model|scan-signature ...
veil-node package --release --out dist/release
```

新文档和教程统一使用 `seal` / `open` / `strategy ...`。旧式命令写法只作为兼容说明，不再作为主教程。

## 自适应策略快速开始

```bash
mkdir -p .demo

veil-node --home .demo/alice identity create \
  --name alice \
  --password idpass \
  --overwrite

veil-node --home .demo/alice identity export \
  --out .demo/alice.vid

veil-node --home .demo/alice contact import \
  .demo/alice.vid \
  --alias alice

veil-node keypart root create \
  --out .demo/root.vkpseed \
  --password rootpass \
  --label alice-bob

echo "secret" > .demo/secret.txt

python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY

veil-node strategy features \
  --carrier .demo/cover.zip \
  --payload .demo/secret.txt \
  --json

veil-node strategy generate \
  --carrier .demo/cover.zip \
  --payload .demo/secret.txt \
  --count 20 \
  --json

veil-node strategy select \
  --carrier .demo/cover.zip \
  --payload .demo/secret.txt \
  --count 20 \
  --json

veil-node --home .demo/alice seal \
  .demo/secret.txt \
  .demo/cover.zip \
  .demo/message.zip \
  --to alice \
  --password msgpass \
  --root-keypart .demo/root.vkpseed \
  --root-keypart-password rootpass \
  --crypto-core 2.2 \
  --low-signature \
  --adaptive-policy \
  --policy-candidates 20 \
  --policy-out .demo/selected.policy.json

veil-node carrier audit \
  --input .demo/message.zip \
  --json

veil-node carrier compare \
  --before .demo/cover.zip \
  --after .demo/message.zip \
  --json

veil-node strategy scan-signature \
  --input .demo/message.zip \
  --json

veil-node --home .demo/alice open \
  .demo/message.zip \
  --root-keypart .demo/root.vkpseed \
  --root-keypart-password rootpass \
  --out .demo/out \
  --password msgpass \
  --identity-password idpass
```

所有默认打开失败统一输出：

```text
Unable to open message.
```

## Adaptive Envelope Policy Engine

新增模块在 `veil_core/strategy/`：

- `features.py`：提取 carrier 和 payload 工程特征。
- `policy.py`：定义并校验 `EnvelopePolicy`，拒绝密钥材料字段。
- `registry.py`：注册合法 embedding / padding / metadata / locator 策略。
- `generator.py`：根据特征和容量生成候选 policy。
- `selector.py`：候选 dry-run、verify-carrier、audit、compare、score，并选择最低工程风险 policy。
- `scorer.py`：评分 size、entropy、structure、metadata、parser validity、payload ratio、固定明文标识。
- `dataset.py`：写出不含密钥材料的 JSONL 训练数据。
- `trainer.py` / `model.py`：训练和检查可移植 heuristic ranker。

policy / dataset / model 都不能包含 root seed、`root_vkp`、`vkp_i`、`message_key`、password 或私钥材料。模型只负责策略排序，最终输出仍必须通过本地验证和评分。

## 策略命令

```bash
veil-node strategy list --format zip
veil-node strategy policy inspect --in selected.policy.json
veil-node strategy score --before cover.zip --after message.zip --policy selected.policy.json --json
veil-node strategy collect --samples-dir samples --payloads-dir payloads --out dataset.jsonl --candidates-per-sample 30
veil-node strategy train --dataset dataset.jsonl --out model.json
veil-node strategy model inspect --in model.json
```

`--policy-in` 会使用指定 policy，但仍会校验 policy 和 carrier。`--policy-model` 只用于候选排序，不能绕过 verifier 和 scorer。

## 客户端与打包

发行目标是 macOS DMG、Windows ZIP、Android SDK/Gradle/JDK 齐备时的 debug-signed APK，以及具备真实 Apple Developer 账号和 provisioning profile 时的 iOS/iPadOS IPA。Linux 和 NAS GUI/web 发行目标已经移除；这些系统使用共享 CLI。

Windows ZIP 包含 `VeilNodeGui.bat` 和 `BuildExe.bat`。后者可在 Windows 主机上通过 PyInstaller 本地生成 `veil-node.exe`。构建产物应放在 `dist/` 或 GitHub Releases，不应提交进源码仓库。

## 验证

```bash
python3 -m unittest discover -s tests -v
python3 -m veil_core doctor
python3 -m veil_core test-vector
```
