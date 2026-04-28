# VeilNode 平台客户端

平台规则：GUI 和系统集成可以因平台而异，但加密、文件格式、协议兼容和容器适配必须调用同一个 `veil-core`。

## 当前状态

| 平台 | 路径 | 当前实现 | 验证方式 |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | 原生 SwiftUI 外壳 | `swift build --product VeilNode` 与 GUI 手测 |
| Windows | `clients/windows/VeilNodeGui.pyw` | 独立 Tk GUI 包装器 | Python 编译检查 |
| Linux | `clients/linux/veil-node-gui` | 独立 Tk GUI 包装器 | Python 编译检查 |
| iOS/iPadOS | `clients/ios/` | SwiftUI 源码脚手架 | 源码结构检查 |
| Android | `clients/android/` | Jetpack Compose 源码脚手架 | 源码结构检查 |
| NAS | `clients/nas/veil-node-web.py` | localhost 网关脚手架 | Python 编译检查与 `/health` |

## macOS

已实现 SwiftPM SwiftUI App、TabView + NavigationStack、doctor/test-vector 状态按钮、seal/open/contact 表单、共享核心命令桥接，以及 `script/build_and_run.sh`。seal/open 的文件和目录通过按钮弹窗选择，不需要手动输入路径；支持批量加密/解密，并支持 v1 external keypart 与 v2 root keypart 两种模式。Dashboard 按钮走原生状态路径；完整加密自检仍以共享 `veil-core` CLI 和测试套件为准。

后续要接入 Keychain、Secure Enclave、Touch ID、Finder 右键菜单和原生拖拽快捷入口。

## Windows

已实现 `clients/windows/VeilNodeGui.pyw`，调用共享 `veil-core`。界面提供按钮式文件/目录选择、批量 seal/open 队列，并与 macOS 的 v1 external keypart / v2 root keypart 流程对齐。

后续要接入 Credential Manager / DPAPI、TPM、Windows Hello、资源管理器右键菜单和 MSI/MSIX 打包。

## Linux

已实现 `clients/linux/veil-node-gui`，调用共享 `veil-core`。

后续要接入 Secret Service、GNOME Keyring、KWallet、TPM2、YubiKey、AppImage、deb、rpm 和 Flatpak。

## iOS / iPadOS

已提供 SwiftUI 固定 App + `.vpkg` 导入模型源码骨架。

后续要接入文件 App、分享菜单、Keychain、Secure Enclave、Face ID / Touch ID 和小文件加密/解密流程。

## Android

已提供 Jetpack Compose 固定 App + `.vpkg` 导入模型源码骨架。

后续要接入 Storage Access Framework、Android Keystore、StrongBox、生物识别解锁和分享菜单。

## NAS

已实现本地 `/health` 网关。后续需要显式存储根目录、认证、反向代理文档和只读审计模式。
