# VeilNode 平台客户端

平台规则：GUI 和系统集成可以因平台而异，但加密、文件格式、协议兼容和容器适配必须调用同一个 `veil-core`。

## 客户端矩阵

| 平台 | 路径 | 当前实现 | 验证方式 |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | 原生 SwiftUI 桌面 App | `swift build --product VeilNode` 与 GUI 验证 |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk 桌面 GUI 包 | Python 编译检查 |
| iOS/iPadOS | `clients/ios/` | SwiftUI App + XcodeGen/Xcode 工程 | 模拟器/target 构建；有签名链时导出 IPA |
| Android | `clients/android/` | 原生 Android Gradle 工程 | debug-signed APK 构建 |
| Linux | CLI only | GUI 发行支持已移除 | `veil-node --help` |
| NAS | CLI only | GUI/web 网关发行支持已移除 | `veil-node doctor` |

## macOS

包含 SwiftPM SwiftUI App、TabView + NavigationStack、doctor/test-vector 状态按钮、seal/open/root/carrier/strategy/contact 表单、共享核心命令桥接，以及 `script/build_and_run.sh`。seal/open 的文件和目录通过按钮弹窗选择，不需要手动输入路径；支持批量加密/解密，并支持 v1/v2 读取兼容、crypto core v2.2、adaptive policy、low-signature 与 fixed-signature scan。发行包内嵌共享 `veil-core` 与文档。平台适配模型覆盖 Keychain、Secure Enclave、Touch ID、Finder 工作流和拖拽入口。

## Windows

包含 `clients/windows/VeilNodeGui.pyw`、`VeilNodeGui.bat` 启动器和 `BuildExe.bat` Windows 本地一键 PyInstaller 辅助脚本，调用共享 `veil-core`。界面提供按钮式文件/目录选择、批量 seal/open 队列、adaptive policy、fixed-signature scan、root 生命周期、root store、Shamir、carrier audit/profile 与高级 CLI 面板，并与 macOS 的 v1/v2/v2.2 流程对齐。平台适配模型覆盖 Credential Manager / DPAPI、TPM、Windows Hello、资源管理器工作流和 MSI/MSIX 打包。

## Linux

Linux GUI 不再作为发行目标。Linux 系统请使用共享 CLI：

```bash
veil-node --help
veil-node doctor
veil-node seal ...
veil-node open ...
```

## iOS / iPadOS

提供 SwiftUI 移动客户端源码包，包含 inbox、seal、strategy、roots、carrier、contacts、settings 移动端入口，围绕固定 App + `.vpkg` 导入模型设计，并对齐文件 App、分享菜单、Keychain、Secure Enclave、Face ID / Touch ID 与小文件工作流。`clients/ios/project.yml` 与 `VeilNodeiOS.xcodeproj` 定义真实 App target；最终 IPA 需要有效 Apple Developer Team 账号和 provisioning profile，不生成未签名占位 IPA。

## Android

提供最小依赖的原生 Android Gradle App，包含 inbox、seal、strategy、roots、carrier、contacts、settings 移动端入口，围绕固定 App + `.vpkg` 导入模型设计，并对齐 Storage Access Framework、Android Keystore、StrongBox、生物识别解锁和分享菜单。Android SDK、Gradle 与可用 JDK 齐备时，release packager 会产出真实 debug-signed APK；生产/商店签名必须使用真实 release key。

## NAS

NAS GUI/web 网关不再作为发行目标。NAS 系统请使用 CLI 自动化，并把 root、密码、carrier 分开保存。

## 发行打包

```bash
veil-node package --release --out dist/release
```

release manifest 会报告已构建和被阻塞的产物。macOS DMG 需要 macOS 上的 SwiftPM 与 `hdiutil`。Windows ZIP 会打包 GUI launcher、Python zipapp 和 `BuildExe.bat`；原生 `.exe` 需要 Windows/PyInstaller 构建主机。Android APK 从 `clients/android` 构建；IPA 需要真实 Apple Developer 账号与 provisioning profile，缺失时会报告 blocked，不会伪造产物。

所有客户端不得重写加密逻辑，必须调用共享 CLI/core，并覆盖 v1/v2 读取兼容和 crypto core v2.2：身份/联系人、root 生命周期、root store、Shamir、seal/open、adaptive strategy features/generate/select/score/scan、防重放、decoy、carrier audit/compare/profile、repair、migrate、doctor、test-vector。
