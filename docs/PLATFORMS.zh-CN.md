# VeilNode 平台客户端

平台规则：GUI 和系统集成可以因平台而异，但加密、文件格式、协议兼容和容器适配必须调用同一个 `veil-core`。

## 客户端矩阵

| 平台 | 路径 | 当前实现 | 验证方式 |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | 原生 SwiftUI 桌面 App | `swift build --product VeilNode` 与 GUI 验证 |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk 桌面 GUI 包 | Python 编译检查 |
| iOS/iPadOS | `clients/ios/` | SwiftUI 移动客户端源码包 | 源码结构检查 |
| Android | `clients/android/` | Jetpack Compose 移动客户端源码包 | 源码结构检查 |
| Linux | CLI only | GUI 发行支持已移除 | `veil-node --help` |
| NAS | CLI only | GUI/web 网关发行支持已移除 | `veil-node doctor` |

## macOS

包含 SwiftPM SwiftUI App、TabView + NavigationStack、doctor/test-vector 状态按钮、seal/open/root/carrier/contact 表单、共享核心命令桥接，以及 `script/build_and_run.sh`。seal/open 的文件和目录通过按钮弹窗选择，不需要手动输入路径；支持批量加密/解密，并支持 v1 external keypart、v2 root keypart 与 crypto core v2.2 low-signature 模式。发行包内嵌共享 `veil-core` 与文档。平台适配模型覆盖 Keychain、Secure Enclave、Touch ID、Finder 工作流和拖拽入口。

## Windows

包含 `clients/windows/VeilNodeGui.pyw` 与 `VeilNodeGui.bat` 启动器，调用共享 `veil-core`。界面提供按钮式文件/目录选择、批量 seal/open 队列、root 生命周期、root store、Shamir、carrier audit/profile 与高级 CLI 面板，并与 macOS 的 v1/v2/v2.2 流程对齐。平台适配模型覆盖 Credential Manager / DPAPI、TPM、Windows Hello、资源管理器工作流和 MSI/MSIX 打包。

## Linux

Linux GUI 不再作为发行目标。Linux 系统请使用共享 CLI：

```bash
veil-node --help
veil-node doctor
veil-node seal ...
veil-node open ...
```

## iOS / iPadOS

提供 SwiftUI 移动客户端源码包，包含 inbox、seal、roots、carrier、contacts、settings 移动端入口，围绕固定 App + `.vpkg` 导入模型设计，并对齐文件 App、分享菜单、Keychain、Secure Enclave、Face ID / Touch ID 与小文件工作流。最终 IPA 需要 Xcode project/workspace、签名证书和 provisioning profile。

## Android

提供 Jetpack Compose 移动客户端源码包，包含 inbox、seal、roots、carrier、contacts、settings 移动端入口，围绕固定 App + `.vpkg` 导入模型设计，并对齐 Storage Access Framework、Android Keystore、StrongBox、生物识别解锁和分享菜单。最终 APK 需要 Gradle Android project 文件。

## NAS

NAS GUI/web 网关不再作为发行目标。NAS 系统请使用 CLI 自动化，并把 root、密码、carrier 分开保存。

## 发行打包

```bash
veil-node package --release --out dist/release
```

release manifest 会报告已构建和被阻塞的产物。macOS DMG 需要 macOS 上的 SwiftPM 与 `hdiutil`。Windows ZIP 会打包 GUI launcher 与 Python zipapp；原生 `.exe` 需要 Windows/PyInstaller 构建主机。APK/IPA 需要平台工程和签名资产，缺失时会报告 blocked，不会伪造产物。

所有客户端不得重写加密逻辑，必须调用共享 CLI/core，并覆盖 v1、v2、crypto core v2.2：身份/联系人、root 生命周期、root store、Shamir、seal/open、防重放、decoy、carrier audit/compare/profile、repair、migrate、doctor、test-vector。
