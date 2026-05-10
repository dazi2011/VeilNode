# VeilNode 平台客户端

分工原则非常简单：**`veil-core` 负责密码学、消息格式与兼容性**；
**平台客户端只负责 UI 与系统集成**。任何客户端都不重写加密。

## 客户端矩阵

| 平台 | 路径 | 状态 | 验证 |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | 原生 SwiftUI 桌面 App，内嵌 `veil-core`。 | `swift build --product VeilNode` |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk 桌面 GUI，调用共享 CLI。 | `python -m py_compile clients/windows/VeilNodeGui.pyw` |
| iOS / iPadOS | `clients/ios/` | SwiftUI **伴侣 App**：导入、SHA-256、CLI 命令复制。 | `xcodegen generate && xcodebuild` |
| Android | `clients/android/` | Java **伴侣 App**：导入、SHA-256、CLI 命令复制。 | `gradle :app:assembleDebug` |
| Linux | — | 仅 CLI（GUI 发行已下线）。 | `veil-node --help` |
| NAS | — | 仅 CLI（GUI / web 网关已下线）。 | `veil-node doctor` |

## macOS

- SwiftPM + SwiftUI 桌面外壳。
- 八个 Tab：Dashboard · Seal · Open · Roots · Carrier · Strategy · Contacts · Settings。
- 所有文件输入都用 `NSOpenPanel`；用户不需要手动输入路径。
- Seal / Open 支持批量。
- v1 外部 keypart 与 v2 root keypart 模式并存。
- crypto core 2.2 全覆盖：自适应策略选择、固定签名扫描、低固定特征档位、
  root 生命周期、root 存储、carrier audit / compare / profile，
  Strategy 标签按"规划 + 评分"两段排版。
- Settings 标签显示套件版本、加密内核标记，并直接链接 GitHub 仓库 /
  最新 release / 技术与平台文档。
- 发行 bundle（`VeilNode.app`，位于 DMG 内）把共享的 `veil-core` Python
  包以及文档放在 `Contents/Resources/VeilNodeCore`。
- `script/build_and_run.sh` 支持 `run` / `--debug` / `--logs` /
  `--telemetry` / `--verify` / `--package`。

## Windows

- `clients/windows/VeilNodeGui.pyw`：Tk GUI，调用共享 `veil-core`。
- 发行 ZIP 内附 `VeilNodeGui.bat` 启动器。
- `BuildExe.bat`：一键 PyInstaller，把同一份源码生成
  `dist/windows-exe/veil-node.exe`。
- 便携 ZIP 同时打包了**所有平台**的 `Build*` helper 和**完整源树**：
  Windows 主机可以在 ZIP 内直接 `BuildApk.bat` 构建 Android APK，无需
  重新克隆仓库。
- Tk GUI 与 macOS 表面一致：按钮选择、批量 seal / open、v1/v2 模式、
  自适应策略、固定签名扫描、低固定特征档、root 生命周期、root 存储、
  carrier audit / compare / profile，并提供完整的 advanced CLI 标签。

## iOS / iPadOS

iOS / iPadOS 是**故意做窄**的伴侣 App。

- 原生 SwiftUI，四个 Tab：Overview · Inspect · Commands · About。
- **Overview** 解释伴侣 App 的边界与加密内核固定面。
- **Inspect** 用系统标准 `fileImporter`（Files / iCloud Drive /
  share-sheet）选文件，使用 `CryptoKit` 计算 SHA-256，方便核对桌面输出。
  **不在设备上做解密**。
- **Commands** 内置 5 个常用命令卡片：doctor / identity create /
  root create / 自适应 seal / open。每张卡都有 Copy command 按钮。
- **About** 显示套件版本、加密内核标记，并提供 GitHub 仓库、最新
  release、技术文档、平台文档的直链。
- 适配 Files / share-sheet、Keychain、Secure Enclave、Face ID / Touch ID
  的边界都有文档说明；**在设备上 seal / open 不在范围内**。
- 签名 IPA 必须有真实的 Apple Developer 账号和 provisioning profile。
  `BuildIpa.sh` 拒绝伪造未签名 IPA。

## Android

Android 与 iOS 同形 —— 故意做窄的伴侣 App。

- 原生 Java，单 Activity，四个 Tab：Overview · Inspect · Commands · About。
- **Inspect** 用 `Intent.ACTION_OPEN_DOCUMENT`（Storage Access Framework）
  选文件，用 `MessageDigest` 计算 SHA-256。
- **Commands** 与 iOS 同形，每张卡都有 Copy 按钮。
- **About** 链向仓库与 release。
- 适配 Storage Access Framework、Android Keystore / StrongBox、
  biometric、share 流的边界都有文档说明；**在设备上 seal / open 不在
  范围内**。
- 当 JDK 17+ / Gradle / Android SDK 齐全时，发行打包器会输出 debug-signed
  APK；上架商店要使用真实的 release 签名。

## Linux

Linux GUI 已不再是发行目标，使用共享 CLI 即可：

```bash
veil-node --help
veil-node doctor
veil-node seal ...
veil-node open ...
```

## NAS

NAS GUI / web 网关已从发行目标中移除。NAS 使用 CLI 自动化即可，并把
root 材料、密码、载体放在**互相分离**的存储位置。

## Release 打包

```bash
veil-node package --release --out dist/release
```

manifest 会标明每个产物是 built 还是 blocked。macOS DMG 在 macOS 上当
SwiftPM 与 `hdiutil` 可用时构建；Windows ZIP 是跨平台便携包（GUI +
zipapp + 所有 `Build*` helper + 源树）；Android APK 在 SDK / Gradle / JDK
都齐时构建；IPA 需要真实的 Apple Developer 账号和 provisioning profile，
缺失时打成 `blocked` —— **绝不伪造 IPA**。

GUI 客户端只调用共享 CLI / core，覆盖 v1/v2 读取兼容与 crypto core 2.2
全流程：identity / contact、root 生命周期、root 存储、Shamir 拆分/恢复、
seal / open、自适应 strategy（features / generate / select / score / scan）、
replay 控制、decoy、carrier audit / compare / profile、repair、migrate、
doctor、test-vector。移动伴侣 App 按设计停在"导入、哈希、复制命令"。
