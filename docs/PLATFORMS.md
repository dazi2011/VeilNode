# VeilNode Platform Clients

The rule is simple: platform clients own UI and OS integration; `veil-core` owns crypto, message formats and compatibility.

## Client Matrix

| Platform | Client path | Status | Verification |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | Native SwiftUI desktop app | `swift build --product VeilNode` |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk desktop GUI package | Python compile check |
| Linux | `clients/linux/veil-node-gui` | Tk desktop GUI package | Python compile check |
| iOS/iPadOS | `clients/ios/` | SwiftUI mobile client source package | Source verification |
| Android | `clients/android/` | Jetpack Compose mobile client source package | Source verification |
| NAS | `clients/nas/veil-node-web.py` | Local NAS gateway package | Python compile check, `/health` handler |

## macOS

Included:

- SwiftPM SwiftUI app shell.
- TabView + NavigationStack layout.
- Doctor/test-vector buttons.
- Dashboard status, doctor and test-vector surfaces.
- Seal/open/contact form surfaces.
- Button-based file/folder pickers; users do not type file paths in the seal/open flows.
- Batch seal/open for multiple selected files/messages.
- v1 external keypart and v2 root keypart modes.
- Shared-core command bridge.
- `script/build_and_run.sh` with `run`, `--debug`, `--logs`, `--telemetry`, `--verify`.
- Release bundle embeds the shared `veil-core` package and documentation.
- Platform adapter model covers Keychain, Secure Enclave, Touch ID and Finder workflow integration.

## Windows

Included:

- GUI wrapper in `clients/windows/VeilNodeGui.pyw`.
- `VeilNodeGui.bat` launcher for release ZIP users.
- Calls shared `veil-core`.
- Button-based file/folder pickers.
- Batch seal/open command queue.
- v1 external keypart and v2 root keypart modes aligned with the macOS UI.
- Platform adapter model covers Credential Manager / DPAPI, TPM, Windows Hello, Explorer workflow integration and installer packaging.

## Linux

Included:

- GUI wrapper in `clients/linux/veil-node-gui`.
- Calls shared `veil-core`.
- Shares the same Tk desktop workflow as Windows.
- Platform adapter model covers Secret Service, GNOME Keyring, KWallet, TPM2, YubiKey and Linux package formats.

## iOS / iPadOS

Included:

- SwiftUI mobile client source package in `clients/ios/`.
- Tab-based inbox, seal, contacts and settings surfaces.
- Fixed app + `.vpkg` import model.
- Files app / Share Sheet, Keychain, Secure Enclave and Face ID / Touch ID adapter surfaces.

## Android

Included:

- Jetpack Compose mobile client source package in `clients/android/`.
- Inbox, seal, contacts and settings surfaces.
- Fixed app + `.vpkg` import model.
- Storage Access Framework, Android Keystore, StrongBox, biometric unlock and share workflow adapter surfaces.

## NAS

Included:

- Local NAS gateway with `/health`.
- Shared `veil-core doctor` integration.
- Storage roots, authentication, reverse proxy and read-only audit surfaces documented for deployments.
