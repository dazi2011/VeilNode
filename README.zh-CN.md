# VeilNode Suite 中文说明

技术细节见 [docs/TECHNICAL.zh-CN.md](docs/TECHNICAL.zh-CN.md)，英文版见 [docs/TECHNICAL.md](docs/TECHNICAL.md)。平台客户端状态见 [docs/PLATFORMS.zh-CN.md](docs/PLATFORMS.zh-CN.md) / [docs/PLATFORMS.md](docs/PLATFORMS.md)。

VeilNode Suite 是一个离线、多平台的文件信封加密工具套件，用于通过普通载体文件传输加密内容，并保持跨端一致的恢复流程。它面向合法本地隐私保护场景，也考虑审查高压环境下的元数据最小化和固定工程特征降低。

系统包含三类角色：

- `veil-factory`：母程序 / 节点生成器，生成节点包装器和节点 Profile。
- `veil-node`：命令行节点客户端，负责身份、联系人、加密伪装、解密还原和本地状态。
- `veil-msg`：伪装消息协议，由可正常打开的载体文件、v1 独立 `.vkp` 或 v2 root keypart 派生元数据，以及一次性 `auth_state` 组成。

整个工具默认离线运行，不依赖服务器，也不需要联网交换身份。公钥身份文件可以通过任意离线方式传递。本工具不承诺绝对无法识别，也不承诺免于取证分析；文件大小、修改时间、保存位置和传输行为仍然可能带来风险。

## 安装与运行

在项目根目录运行：

```bash
python3 -m veil_core --help
```

安装所需依赖：

```bash
python3 -m veil_core --install-deps
```

只检查依赖、不安装：

```bash
python3 -m veil_core --check-deps
```

让工具在普通命令执行前自动修复依赖：

```bash
VEIL_AUTO_INSTALL=1 python3 -m veil_core --help
```

可选：以可编辑模式安装：

```bash
python3 -m pip install -e .
veil-node --help
veil-factory --help
```

## 快速开始

下面示例会创建身份，把一个文本文件加密伪装进正常 ZIP 载体，然后再恢复出来。示例默认已经执行过 `python3 -m pip install -e .`；如果没有安装，把 `veil-node` 换成 `python3 -m veil_core` 即可。

```bash
mkdir -p .demo
export VEIL_FAST_KDF=1  # 可选：本地演示加速模式
```

创建本地身份：

```bash
veil-node --home .demo/alice identity create \
  --name alice \
  --password idpass \
  --overwrite
```

导出公钥身份：

```bash
veil-node --home .demo/alice identity export \
  --out .demo/alice.vid
```

把公钥导入联系人：

```bash
veil-node --home .demo/alice contact import \
  .demo/alice.vid \
  --alias alice
```

准备待隐藏内容：

```bash
echo "secret" > .demo/secret.txt
python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY
```

加密并伪装进 ZIP：

```bash
veil-node --home .demo/alice seal \
  .demo/secret.txt \
  .demo/cover.zip \
  .demo/message.zip \
  --to alice \
  --password msgpass
```

生成的关键文件：

```text
.demo/message.zip    # 伪装载体，可按 ZIP 解压
.demo/message.vkp    # 解密资格的一部分，不是完整密钥
.demo/message.vauth  # 一次性认证状态
```

正式解密前，可以先做预验证。预验证不会写出文件，也不会消费一次性认证状态：

```bash
veil-node --home .demo/alice verify-only \
  --input .demo/message.zip \
  --keypart .demo/message.vkp \
  --auth-state .demo/message.vauth \
  --password msgpass \
  --identity-password idpass
```

解密恢复：

```bash
veil-node --home .demo/alice open \
  .demo/message.zip \
  --keypart .demo/message.vkp \
  --out .demo/out \
  --password msgpass \
  --identity-password idpass
```

恢复文件位于：

```text
.demo/out/secret.txt
```

注意：`open` / `receive` 成功后，对应的 `auth_state` 记录会被消费。同一套认证状态不能重复解密。

## 离线 root keypart 模式（v2）

v1 模式是“每条消息一个 `.vkp`”：载体负责伪装，`.vkp` 保存被密码密封的 locator 和恢复材料。

v2 模式改成“预共享一次 root_vkp”：双方先离线交换一个被密码保护的 `.vkpseed`，之后每条消息生成随机 `msg_id` 和 `message_salt`，用 HKDF 派生只存在内存中的 `vkp_i`，再和消息密码共同派生 `message_key`。v2 不再输出每条消息独立的 `.vkp`，但仍需要 `.vauth`、消息密码、接收方私钥和匹配身份。

不要把 `.vkpseed` 和载体放在同一个渠道传输。root seed 泄露会影响由它派生的消息，应定期 rotate。

```bash
mkdir -p .demo

veil-node --home .demo/alice identity create --name alice --password idpass --overwrite
veil-node --home .demo/alice identity export --out .demo/alice.vid
veil-node --home .demo/alice contact import .demo/alice.vid --alias alice

veil-node keypart root create \
  --out .demo/alice_bob.root.vkpseed \
  --password rootpass

echo "secret" > .demo/secret.txt
python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY

veil-node --home .demo/alice seal \
  .demo/secret.txt \
  .demo/cover.zip \
  .demo/message.zip \
  --to alice \
  --password msgpass \
  --root-keypart .demo/alice_bob.root.vkpseed \
  --root-keypart-password rootpass \
  --no-external-keypart

veil-node --home .demo/alice open \
  .demo/message.zip \
  --root-keypart .demo/alice_bob.root.vkpseed \
  --root-keypart-password rootpass \
  --out .demo/out \
  --password msgpass \
  --identity-password idpass
```

root keypart 管理命令：

```bash
veil-node keypart root inspect --in .demo/alice_bob.root.vkpseed
veil-node keypart root rotate --in old.vkpseed --out new.vkpseed --password rootpass
veil-node keypart root export-qr --in root.vkpseed --out root.txt --password rootpass
veil-node keypart root import --in root.txt --out imported.vkpseed --password rootpass
```

## Veil Offline Envelope Crypto Core v2.2

`crypto_core_version = "2.2"` 表示离线信封加密内核版本，不是 VeilNode Suite 整体版本，也不是 Python 包版本。本次不要、也没有把 Suite version 改成 2.2。

v2.2 新消息使用：

```json
{
  "protocol_family": "veil-offline-envelope",
  "crypto_core_version": "2.2"
}
```

协议区别：

- v1：每条消息一个外部 `.vkp`，另有 `.vauth`。
- v2：预共享 root `.vkpseed`，每条消息在内存中派生 `vkp_i`，不再生成每条消息 `.vkp`。
- v2.2：root 生命周期、加密/最小化 metadata、本地 seen DB 防重放、Shamir root 备份、可选 decoy payload、low-signature carrier 策略，以及 carrier audit/compare/profile。

v2.2 快速开始：

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
  --out .demo/alice_bob.root.vkpseed \
  --password rootpass \
  --label alice-bob

veil-node keypart root inspect \
  --in .demo/alice_bob.root.vkpseed

echo "secret" > .demo/secret.txt

python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY

veil-node --home .demo/alice seal \
  .demo/secret.txt \
  .demo/cover.zip \
  .demo/message.zip \
  --to alice \
  --password msgpass \
  --root-keypart .demo/alice_bob.root.vkpseed \
  --root-keypart-password rootpass \
  --crypto-core 2.2 \
  --low-signature \
  --signature-profile balanced

veil-node --home .demo/alice open \
  .demo/message.zip \
  --root-keypart .demo/alice_bob.root.vkpseed \
  --root-keypart-password rootpass \
  --out .demo/out \
  --password msgpass \
  --identity-password idpass

veil-node carrier audit --input .demo/message.zip --json
veil-node carrier compare --before .demo/cover.zip --after .demo/message.zip --json
```

root 生命周期：

```bash
veil-node keypart root rotate --in .demo/alice_bob.root.vkpseed --out .demo/alice_bob.epoch1.root.vkpseed --password rootpass
veil-node keypart root retire --in root.vkpseed --out retired.root.vkpseed --password rootpass
veil-node keypart root revoke --in root.vkpseed --out revoked.root.vkpseed --password rootpass
veil-node keypart root import --in root.vkpseed --password rootpass --label alice-bob
veil-node keypart root list
veil-node keypart root show --fingerprint <fingerprint>
```

Shamir 备份：

```bash
veil-node keypart root split \
  --in .demo/alice_bob.root.vkpseed \
  --password rootpass \
  --shares 5 \
  --threshold 3 \
  --out-dir .demo/shares

veil-node keypart root recover \
  --shares .demo/shares/root.share.1 .demo/shares/root.share.2 .demo/shares/root.share.3 \
  --out .demo/recovered.root.vkpseed \
  --password rootpass
```

防重放与 decoy：

- v2.2 成功打开后写入 `<home>/state/msg_seen.db`；同一 `msg_id` 再次打开会统一失败：`Unable to open message.`。
- `--no-replay-check` 只用于测试和本地调试，生产恢复不建议使用。
- `--decoy-input fake.txt --decoy-password fakepass` 会加入独立认证的 decoy payload。decoy 是抗胁迫辅助，不是数学上完美的可否认加密。

Low-signature privacy mode：

- 需要显式传入 `--low-signature`。
- Profile：`conservative`、`balanced`、`aggressive`。
- 目标是降低固定工程特征、最小化 metadata、改善本地隐私卫生和载体格式保真度。
- 不保证文件无法被识别为异常。

操作建议：

- 不要把 `.vkpseed`、密码、身份私钥目录和 carrier 存在同一位置或同一渠道。
- root 泄露后：revoke、rotate、停止使用旧 root 加密新消息，并通过独立渠道重新分发新 root。
- carrier audit 只是本地工程风险评分；文件大小、mtime、路径和传输行为仍可能暴露风险。

## 使用说明

身份和联系人：

```bash
veil-node --home ~/.veilnode/alice identity create --name alice --password idpass --overwrite
veil-node --home ~/.veilnode/alice identity export --out alice.vid
veil-node --home ~/.veilnode/alice identity import --in bob.vid --alias bob
veil-node --home ~/.veilnode/alice identity list
veil-node --home ~/.veilnode/alice identity health --identity-password idpass
veil-node --home ~/.veilnode/alice contact import bob.vid --alias bob
veil-node --home ~/.veilnode/alice contact list
veil-node --home ~/.veilnode/alice contact show --alias bob
```

加密和解密：

```bash
# v1：默认生成 message.vkp 和 message.vauth
veil-node --home ~/.veilnode/alice seal secret.zip cover.mp4 message.mp4 --to bob --password msgpass
veil-node --home ~/.veilnode/bob open message.mp4 --keypart message.vkp --out restored --password msgpass --identity-password idpass

# v2：使用预共享 root.vkpseed，不生成 message.vkp
veil-node --home ~/.veilnode/alice seal secret.zip cover.mp4 message.mp4 --to bob --password msgpass \
  --root-keypart root.vkpseed --root-keypart-password rootpass --no-external-keypart
veil-node --home ~/.veilnode/bob open message.mp4 --root-keypart root.vkpseed --root-keypart-password rootpass \
  --out restored --password msgpass --identity-password idpass
```

工程和维护命令：

```bash
veil-node doctor
veil-node audit
veil-node capacity --carrier cover.zip --payload-size 1048576
veil-node verify-carrier --input message.zip --format zip
veil-node verify-only --input message.zip --keypart message.vkp --auth-state message.vauth --password msgpass --identity-password idpass
veil-node verify-only --input message.zip --root-keypart root.vkpseed --root-keypart-password rootpass --auth-state message.vauth --password msgpass --identity-password idpass
veil-node repair keypart --keypart message.vkp
veil-node migrate keypart --keypart message.vkp --out message.v1.vkp
veil-node profile levels
veil-node profile create --out hardened.profile.json --level hardened
veil-node nodepkg export --out alice.vpkg
veil-node package --out dist/veilnode.pyz
veil-node test-vector
veil-node secure-delete --path message.vkp --dry-run
```

客户端：macOS、Windows、iOS/iPadOS 和 Android 是当前发行目标。Linux 与 NAS GUI 不再作为发行目标；这些系统请使用 CLI。macOS、Windows GUI 覆盖 seal/open/root/carrier 主要流程；iOS/iPadOS 与 Android 源码包围绕 `.vpkg`、`.vid`、`.vkpseed`、crypto core v2.2 和共享核心工作流保持一致。

导出固定客户端可导入的节点包：

```bash
veil-node --home .demo/alice nodepkg export --out .demo/alice.vpkg
veil-node nodepkg inspect --in .demo/alice.vpkg
```

## 支持的载体格式

```bash
--format png
--format bmp
--format wav
--format mp4
--format zip
--format pdf
--format 7z
--format vmsg
```

载体嵌入策略：

- PNG：随机合法 ancillary chunk。
- WAV：随机未知 RIFF chunk。
- MP4：标准 `free` box。
- ZIP：随机名称的 stored member，因此 ZIP 仍可解压。
- PDF：增量更新 stream object。
- BMP / 7z：尾部附加，依赖常见解析器的容忍行为。
- vmsg：Veil 内部裸封装格式，用于跨平台交换和回归测试，不伪装成普通媒体。

MP4 自动生成载体时会优先使用 `ffmpeg`。7z 自动生成载体时需要本机有 `7z` 命令。

## veil-factory

生成一个拥有独立命令名、Profile、命令别名、参数别名、chunk 大小、padding 策略和载体格式白名单的节点：

```bash
veil-factory create-node \
  --name shade \
  --out-dir nodes \
  --chunk-size 32768 \
  --padding bucket \
  --bucket-size 65536 \
  --containers png,bmp,wav,mp4,zip,pdf,7z,vmsg \
  --param-style mixed \
  --init-identity-password idpass
```

使用生成的节点：

```bash
./nodes/shade identity list
```

## 工程化命令

本地自检：检查依赖、Python 版本、加密自检、协议兼容、Profile 和外部工具。

```bash
veil-node doctor
```

审计本地身份、联系人和权限状态：

```bash
veil-node --home .demo/alice audit
veil-node --home .demo/alice identity health --identity-password idpass
```

查看和创建安全 Profile：

```bash
veil-node profile levels
veil-node profile create \
  --out .demo/hardened.profile.json \
  --name alice \
  --level hardened
veil-node --profile .demo/hardened.profile.json profile show
```

容量/策略评估：

```bash
veil-node capacity --format png --payload-size 1048576
veil-node capacity --carrier cover.pdf --payload-size 1048576
```

验证生成的载体是否还能正常解析：

```bash
veil-node verify-carrier \
  --input .demo/message.zip \
  --format zip
```

修复或迁移 keypart 元数据：

```bash
veil-node repair keypart --keypart .demo/message.vkp
veil-node migrate keypart \
  --keypart .demo/message.vkp \
  --out .demo/message.v1.vkp
veil-node repair scan --dir .demo
```

联系人管理：

```bash
veil-node --home .demo/alice contact import .demo/alice.vid --alias alice
veil-node --home .demo/alice contact list
veil-node --home .demo/alice contact show --alias alice
```

构建跨平台 Python zipapp：

```bash
veil-node package --out dist/veilnode.pyz
python3 dist/veilnode.pyz --help
```

运行稳定测试向量：

```bash
veil-node test-vector
```

安全删除是显式危险操作。先 dry-run：

```bash
veil-node secure-delete --path .demo/message.vkp --dry-run
```

真正执行需要强确认：

```bash
veil-node secure-delete \
  --path .demo/message.vkp \
  --yes \
  --confirm-text DELETE
```

## Profile 安全等级

内置三个等级：

- `dev`：快速迭代等级，KDF 参数更轻，适合演示和短周期验证。
- `balanced`：默认等级，适合一般使用。
- `hardened`：更高 KDF 成本和更大的 padding bucket，速度更慢。

需要最高安全余量时可不启用演示加速变量：

```bash
VEIL_FAST_KDF=1
```

默认 KDF 参数会使用更高成本配置。

## 已实现的安全属性

- 稳定协议元数据：`veil-msg` v1 / v2，并带读取器兼容性检查。
- Profile 元数据：支持 `dev`、`balanced`、`hardened`。
- Argon2id 密码派生，可配置内存、迭代次数和并行度。
- HKDF 多子密钥派生。
- 每条消息独立随机 `file_key`。
- v2 离线 root keypart：`.vkpseed` 由密码保护，每条消息随机 `msg_id` / `message_salt`，通过 HKDF 派生内存中的 `vkp_i`，不再输出每条消息独立 `.vkp`。
- XChaCha20-Poly1305 内容加密。
- AES-256-GCM 外层加密、manifest 加密、keypart 密封和 auth_state 密封。
- X25519 接收方公钥封装 `file_key`。
- 多接收方 envelope。
- 私钥只保存在本地身份区，并由身份密码加密。
- keypart 不是完整密钥，只是解密资格的一部分。v2 中 root seed 仍必须结合消息密码、接收方身份和 auth_state 才能恢复。
- 离线一次性 `auth_state`。
- 可选设备绑定：`--device-bind`。
- 假层支持：`--decoy-input` 与 `--decoy-password`。
- 失败无详细反馈：密码错误、keypart/root seed 错误、私钥错误、auth_state 已用、manifest 损坏、payload 损坏都走泛化失败。
- payload 分片、密钥派生乱序、随机 gap、随机/bucket padding。
- 发送后自动验证载体；v1 把验证元数据写入 keypart，v2 在 seal 报告中返回验证结果。
- 事务式解密：先完整解密、hash 校验、输出提交成功，然后才消费 auth_state。
- 日志/诊断脱敏工具。

## 代码架构

CLI 背后是分层 Python 包：

- `crypto`：KDF、HKDF、AEAD 和密钥工具。
- `compression`：输入文件/文件夹打包与恢复。
- `chunks`：分片、乱序与重组。
- `padding`：随机 padding 与 bucket padding。
- `container` / `adapter`：载体生成、嵌入、提取、容量评估和验证。
- `message`：`veil-msg` 构建与事务式恢复。
- `identity` / `contacts`：本地身份与联系人管理。
- `profile`：安全 Profile 与协议关联配置。
- `protocol`：协议版本、兼容性和加密套件元数据。
- `diagnostics`：doctor、audit、capacity 和载体验证。
- `repair`：恢复扫描与元数据迁移。
- `api`：`VeilAPI` 统一门面，供 CLI、GUI、移动端和 NAS 端调用。

## 安全模型

VeilNode 将离线运行、认证加密、公钥封装、密码派生密钥材料、一次性认证状态和载体保持能力组合成统一工作流。它面向私密文件交换：载体保持普通文件体验，恢复资格由多份独立材料共同控制。

- v1 把 locator 元数据放在密码密封的 `.vkp` 中。
- v2 使用受密码保护的 `.vkpseed` 和每条消息 HKDF 派生，避免每条消息传递 `.vkp`。
- `.vkpseed`、身份密码、auth state 和载体文件建议尽量分渠道保存或传输。
- root keypart seed 是长期共享材料，应定期 rotate。
- Secure Enclave、TPM、YubiKey、Keychain 进入平台适配模型；可移植发行路径使用密码保护的本地身份存储和可选本地设备绑定。

## 测试

运行完整测试：

```bash
python3 -m unittest discover -s tests -v
```

回归测试覆盖：

- PNG 加密/解密回环。
- 一次性 auth 重放失败。
- 假层密码恢复假内容。
- 多接收方解密。
- 所有支持载体格式的嵌入、提取和本地可解析性。
- Factory 生成节点和 Profile。
- 协议元数据与 keypart 校验。
- v2 root keypart 创建、v2 加密/解密、错误 root seed、错误密码、auth 重放、v1/v2 提示和重复发送唯一性。
- `doctor`、`audit`、`profile`、`contact`、`capacity`、`verify-only`、`verify-carrier`、`repair`、`migrate`、`package`、`test-vector`。
- `VeilAPI` 统一 API 门面。

`secure-delete` 使用显式运行时确认；自动化测试覆盖拒绝和 dry-run 路径。
