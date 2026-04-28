# VeilNode 平台客户端

平台规则：GUI 和系统集成可以因平台而异，但加密、文件格式、协议兼容和容器适配必须调用同一个 `veil-core`。

## 客户端矩阵

| 平台 | 路径 | 当前实现 | 验证方式 |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | 原生 SwiftUI 桌面 App | `swift build --product VeilNode` 与 GUI 验证 |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk 桌面 GUI 包 | Python 编译检查 |
| Linux | `clients/linux/veil-node-gui` | Tk 桌面 GUI 包 | Python 编译检查 |
| iOS/iPadOS | `clients/ios/` | SwiftUI 移动客户端源码包 | 源码结构检查 |
| Android | `clients/android/` | Jetpack Compose 移动客户端源码包 | 源码结构检查 |
| NAS | `clients/nas/veil-node-web.py` | 本地 NAS 网关包 | Python 编译检查与 `/health` |

## macOS

包含 SwiftPM SwiftUI App、TabView + NavigationStack、doctor/test-vector 状态按钮、seal/open/contact 表单、共享核心命令桥接，以及 `script/build_and_run.sh`。seal/open 的文件和目录通过按钮弹窗选择，不需要手动输入路径；支持批量加密/解密，并支持 v1 external keypart 与 v2 root keypart 两种模式。发行包内嵌共享 `veil-core` 与文档。平台适配模型覆盖 Keychain、Secure Enclave、Touch ID、Finder 工作流和拖拽入口。

## Windows

包含 `clients/windows/VeilNodeGui.pyw` 与 `VeilNodeGui.bat` 启动器，调用共享 `veil-core`。界面提供按钮式文件/目录选择、批量 seal/open 队列，并与 macOS 的 v1 external keypart / v2 root keypart 流程对齐。平台适配模型覆盖 Credential Manager / DPAPI、TPM、Windows Hello、资源管理器工作流和 MSI/MSIX 打包。

## Linux

包含 `clients/linux/veil-node-gui`，调用共享 `veil-core`，与 Windows 共用 Tk 桌面交互模型。平台适配模型覆盖 Secret Service、GNOME Keyring、KWallet、TPM2、YubiKey、AppImage、deb、rpm 和 Flatpak。

## iOS / iPadOS

提供 SwiftUI 移动客户端源码包，包含 inbox、seal、contacts、settings 四个移动端入口，围绕固定 App + `.vpkg` 导入模型设计，并对齐文件 App、分享菜单、Keychain、Secure Enclave、Face ID / Touch ID 与小文件工作流。

## Android

提供 Jetpack Compose 移动客户端源码包，包含 inbox、seal、contacts、settings 四个移动端入口，围绕固定 App + `.vpkg` 导入模型设计，并对齐 Storage Access Framework、Android Keystore、StrongBox、生物识别解锁和分享菜单。

## NAS

提供本地 NAS 网关与 `/health`，接入共享 `veil-core doctor`。部署模型覆盖显式存储根目录、认证、反向代理和只读审计模式。
