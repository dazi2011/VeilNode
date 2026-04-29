# VeilNode Platform Clients

The rule is simple: platform clients own UI and OS integration; `veil-core` owns crypto, message formats and compatibility.

## Client Matrix

| Platform | Client path | Status | Verification |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | Native SwiftUI desktop app | `swift build --product VeilNode` |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk desktop GUI package | Python compile check |
| iOS/iPadOS | `clients/ios/` | SwiftUI mobile client source package | Source verification |
| Android | `clients/android/` | Jetpack Compose mobile client source package | Source verification |
| Linux | CLI only | GUI release support removed | `veil-node --help` |
| NAS | CLI only | GUI/web gateway release support removed | `veil-node doctor` |

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
- Crypto core v2.2 seal/open, low-signature profiles, root lifecycle, root store, carrier tools via shared CLI surfaces.
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
- Crypto core v2.2 seal/open, low-signature profiles, root lifecycle, root store and carrier audit/profile surfaces.
- Platform adapter model covers Credential Manager / DPAPI, TPM, Windows Hello, Explorer workflow integration and installer packaging.

## Linux

Linux GUI is no longer a supported release target. Use the shared CLI:

```bash
veil-node --help
veil-node doctor
veil-node seal ...
veil-node open ...
```

## iOS / iPadOS

Included:

- SwiftUI mobile client source package in `clients/ios/`.
- Tab-based inbox, seal, roots, carrier, contacts and settings surfaces.
- Fixed app + `.vpkg` import model.
- Files app / Share Sheet, Keychain, Secure Enclave and Face ID / Touch ID adapter surfaces.
- UI coverage tracks crypto core v2.2 workflows; final IPA creation requires an Xcode project/workspace and signing identity.

## Android

Included:

- Jetpack Compose mobile client source package in `clients/android/`.
- Inbox, seal, roots, carrier, contacts and settings surfaces.
- Fixed app + `.vpkg` import model.
- Storage Access Framework, Android Keystore, StrongBox, biometric unlock and share workflow adapter surfaces.
- UI coverage tracks crypto core v2.2 workflows; final APK creation requires Gradle Android project files.

## NAS

NAS GUI/web gateway support is removed from release targets. Use CLI automation on NAS systems and keep root material, passwords and carriers in separate storage locations.

## Release Packaging

```bash
veil-node package --release --out dist/release
```

The release manifest reports built and blocked artifacts. macOS DMG builds on macOS when SwiftPM and `hdiutil` are present. Windows ZIP is produced as a portable GUI + zipapp bundle; a native `.exe` requires a Windows/PyInstaller build host. APK and IPA require platform projects and signing assets and are reported as blocked if those are absent.

No client should reimplement crypto. GUI clients call the shared CLI/core and must expose v1, v2 and crypto core v2.2 flows: identity/contact management, root lifecycle, root store, Shamir split/recover, seal/open, replay controls, decoy, carrier audit/compare/profile, repair, migrate, doctor and test-vector.
