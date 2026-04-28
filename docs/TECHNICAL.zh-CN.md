# VeilNode 技术说明

VeilNode Suite 的核心原则是：所有平台客户端只负责界面和系统集成，真正的加密、封装、协议兼容和载体适配统一走 `veil-core`（当前 Python 实现目录为 `veil_core/`）。

## 命名

- 项目名：`VeilNode`
- 套件名：`VeilNode Suite`
- 核心库：`veil-core`
- 母程序 / 节点生成器：`veil-factory`
- 命令行节点客户端：`veil-node`
- 图形客户端：`veil-gui`
- 消息协议：`veil-msg`
- 内部消息格式：`.vmsg`
- 身份文件：`.vid`
- 密钥分片文件：`.vkp`
- root keypart 种子：`.vkpseed`
- 节点包：`.vpkg`

宣传语：

```text
VeilNode — encrypted files disguised as ordinary data.
```

## 核心分层

- `crypto`：Argon2id、HKDF、AES-GCM、XChaCha20-Poly1305 兼容层、哈希和编码。
- `compression`：输入文件/文件夹的标准化打包与恢复。
- `chunks`：payload 分片、基于密钥的乱序和重组。
- `padding`：随机 padding 与 bucket padding。
- `container`：载体生成、嵌入、提取、容量评估和可打开性验证。
- `identity` / `contacts`：本地身份、`.vid` 公钥身份和联系人。
- `message`：`veil-msg` 构建、解密和事务式 auth_state 消费。
- `nodepkg`：`.vpkg` 导出、导入和检查。
- `protocol`：协议版本与兼容性检查。
- `profile`：`dev`、`balanced`、`hardened` 安全档案。
- `platform`：`SecureStore`、`DeviceBinding`、`FileProvider` 平台边界。
- `diagnostics` / `repair`：doctor、audit、capacity、repair、migrate。
- `api`：给 CLI、GUI 和未来移动端调用的统一 API。

## 文件格式

`.vid` 只包含节点 ID、名称、公钥、创建时间和格式类型，不包含私钥。

`.vkp` 是 v1 每条消息独立生成的密钥分片文件，包含密封记录、协议元数据、载体验证信息和完整性哈希。它不是完整密钥，不能单独解密。

`.vkpseed` 是 v2 长期离线 root keypart seed。文件本身通过 Argon2id + AES-GCM 密码保护，`inspect` 只显示 kind、version、created_at、KDF 参数和 fingerprint，不显示 seed。

v2 每条消息的派生关系：

```text
vkp_i = HKDF(root_vkp, salt=msg_id, info="veil-vkp-v2" || file_hash || receiver_id)
password_key = Argon2id(password, salt=message_salt, profile_params)
message_key = HKDF(vkp_i || password_key, salt=message_salt, info="veil-message-key-v2")
```

`msg_id` 和 `message_salt` 每条消息随机。`root_vkp`、`vkp_i`、`message_key` 都不会写入载体。v2 当前会在载体内放置公开的 per-message 恢复元数据，用于在没有每条消息 `.vkp` 的情况下恢复派生路径。

`.vpkg` 是固定客户端导入的节点包，包含公开身份、加密私钥材料、Profile、联系人、adapter 列表和完整性标签。桌面端可以生成专属包装器，也可以导入 `.vpkg`；移动端、NAS 和未来 Web/WASM 更适合固定客户端 + `.vpkg`。

`.vmsg` 是 Veil 内部消息封装格式，用于跨平台交换、调试和回归测试。它不是伪装成图片、视频、ZIP 的普通载体。

## 解密事务

一次性认证状态必须在“成功之后”消费：

1. 读取 auth_state。
2. 解密 v1 keypart 记录，或用 `.vkpseed` 派生 v2 message key。
3. 恢复 file_key。
4. 从载体提取 payload。
5. 解密 manifest 和内容。
6. 校验 archive hash。
7. 写入临时 staging 目录。
8. 原子提交输出。
9. 只有全部成功后才消费 auth_state。

`verify-only` 会在写出和消费认证状态之前停止。

## 第一批稳定载体

- ZIP：stored member。
- PDF：增量 stream object。
- MP4：`free` box。
- PNG：合法 ancillary chunk。
- WAV：未知 RIFF chunk。
- BMP / 7z：尾部附加兼容路径。
- `.vmsg`：内部裸封装。

JPEG 不作为核心载体，因为有损重压缩很容易破坏隐藏数据。

## 测试向量

```bash
veil-node test-vector
```

该命令验证 v1 XChaCha20-Poly1305 兼容向量和 v2 root keypart 派生向量，是未来 Rust、Swift、Kotlin、WASM 绑定保持跨平台兼容的回归锚点。
