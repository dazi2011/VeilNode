# VeilNode Platform Clients

The rule is simple: platform clients own UI and OS integration; `veil-core` owns crypto, message formats and compatibility.

## Current Client Status

| Platform | Client path | Status | Verification |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | Native SwiftUI shell | `swift build --product VeilNode` |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk GUI wrapper | Python compile check |
| Linux | `clients/linux/veil-node-gui` | Tk GUI wrapper | Python compile check |
| iOS/iPadOS | `clients/ios/` | SwiftUI scaffold | Source scaffold, shared-core boundary |
| Android | `clients/android/` | Compose scaffold | Source scaffold, shared-core boundary |
| NAS | `clients/nas/veil-node-web.py` | localhost gateway scaffold | Python compile check, `/health` handler |

## macOS

Implemented:

- SwiftPM SwiftUI app shell.
- TabView + NavigationStack layout.
- Doctor/test-vector buttons.
- Dashboard buttons use a native status path; full crypto checks remain the shared `veil-core` CLI/test suite.
- Seal/open/contact form surfaces.
- Button-based file/folder pickers; users do not type file paths in the seal/open flows.
- Batch seal/open for multiple selected files/messages.
- v1 external keypart and v2 root keypart modes.
- Shared-core command bridge.
- `script/build_and_run.sh` with `run`, `--debug`, `--logs`, `--telemetry`, `--verify`.
- Codex Run action in `.codex/environments/environment.toml`.

Planned:

- Keychain SecureStore.
- Secure Enclave DeviceBinding.
- Touch ID unlock.
- Finder right-click service.
- Native drag/drop shortcuts and Finder right-click service.

## Windows

Implemented:

- Independent GUI wrapper in `clients/windows/VeilNodeGui.pyw`.
- Calls shared `veil-core`.
- Button-based file/folder pickers.
- Batch seal/open command queue.
- v1 external keypart and v2 root keypart modes aligned with the macOS UI.

Planned:

- Credential Manager / DPAPI SecureStore.
- TPM DeviceBinding.
- Windows Hello unlock.
- Explorer context menu.
- MSI/MSIX packaging.

## Linux

Implemented:

- Independent GUI wrapper in `clients/linux/veil-node-gui`.
- Calls shared `veil-core`.

Planned:

- Secret Service / GNOME Keyring / KWallet SecureStore.
- TPM2 / YubiKey DeviceBinding.
- AppImage, deb, rpm and Flatpak packaging.

## iOS / iPadOS

Implemented:

- SwiftUI source scaffold in `clients/ios/`.
- Fixed app + `.vpkg` import architecture documented.

Planned:

- Files app import/export.
- Share sheet.
- Keychain SecureStore.
- Secure Enclave DeviceBinding.
- Face ID / Touch ID unlock.
- Small-file seal/open workflows.

## Android

Implemented:

- Jetpack Compose source scaffold in `clients/android/`.
- Fixed app + `.vpkg` import architecture documented.

Planned:

- Storage Access Framework.
- Android Keystore / StrongBox.
- Biometric unlock.
- Share sheet.
- Small-file seal/open workflows.

## NAS

Implemented:

- Localhost-only health gateway scaffold.

Planned:

- Explicit storage roots.
- Authentication.
- Reverse proxy documentation.
- Read-only audit mode.
