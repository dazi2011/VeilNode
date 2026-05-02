# VeilNode Platform Clients

The rule is simple: platform clients own UI and OS integration; `veil-core` owns crypto, message formats and compatibility.

## Client Matrix

| Platform | Client path | Status | Verification |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | Native SwiftUI desktop app | `swift build --product VeilNode` |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk desktop GUI package | Python compile check |
| iOS/iPadOS | `clients/ios/` | SwiftUI app with XcodeGen/Xcode project | simulator/target build; signed IPA when provisioning exists |
| Android | `clients/android/` | Native Android Gradle project | debug-signed APK build |
| Linux | CLI only | GUI release support removed | `veil-node --help` |
| NAS | CLI only | GUI/web gateway release support removed | `veil-node doctor` |

## macOS

Included:

- SwiftPM SwiftUI app shell.
- TabView + NavigationStack layout.
- Doctor/test-vector buttons.
- Dashboard status, doctor and test-vector surfaces.
- Seal/open/root/carrier/strategy/contact form surfaces.
- Button-based file/folder pickers; users do not type file paths in the seal/open flows.
- Batch seal/open for multiple selected files/messages.
- v1 external keypart and v2 root keypart modes.
- Crypto core v2.2 seal/open, adaptive policy selection, fixed-signature scan, low-signature profiles, root lifecycle, root store and carrier tools via shared CLI surfaces.
- Shared-core command bridge.
- `script/build_and_run.sh` with `run`, `--debug`, `--logs`, `--telemetry`, `--verify`.
- Release bundle embeds the shared `veil-core` package and documentation.
- Platform adapter model covers Keychain, Secure Enclave, Touch ID and Finder workflow integration.

## Windows

Included:

- GUI wrapper in `clients/windows/VeilNodeGui.pyw`.
- `VeilNodeGui.bat` launcher for release ZIP users.
- `BuildExe.bat` one-click local PyInstaller helper for building `veil-node.exe` on Windows.
- Calls shared `veil-core`.
- Button-based file/folder pickers.
- Batch seal/open command queue.
- v1 external keypart and v2 root keypart modes aligned with the macOS UI.
- Crypto core v2.2 seal/open, adaptive policy selection, fixed-signature scan, low-signature profiles, root lifecycle, root store and carrier audit/profile surfaces.
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
- XcodeGen project spec and generated `VeilNodeiOS.xcodeproj`.
- Tab-based inbox, seal, strategy, roots, carrier, contacts and settings surfaces.
- Fixed app + `.vpkg` import model.
- Files app / Share Sheet, Keychain, Secure Enclave and Face ID / Touch ID adapter surfaces.
- UI coverage tracks crypto core v2.2 and adaptive policy workflows.
- Signed IPA creation requires a valid Apple Developer account and provisioning profile; VeilNode does not ship unsigned placeholder IPA files.

## Android

Included:

- Minimal native Android Gradle app in `clients/android/`.
- Inbox, seal, strategy, roots, carrier, contacts and settings surfaces.
- Fixed app + `.vpkg` import model.
- Storage Access Framework, Android Keystore, StrongBox, biometric unlock and share workflow adapter surfaces.
- UI coverage tracks crypto core v2.2 and adaptive policy workflows. The packager emits a real debug-signed APK when Android SDK, Gradle and a working JDK are available; production store signing must use a real release key.

## NAS

NAS GUI/web gateway support is removed from release targets. Use CLI automation on NAS systems and keep root material, passwords and carriers in separate storage locations.

## Release Packaging

```bash
veil-node package --release --out dist/release
```

The release manifest reports built and blocked artifacts. macOS DMG builds on macOS when SwiftPM and `hdiutil` are present. Windows ZIP is produced as a portable GUI + zipapp bundle and includes `BuildExe.bat` for Windows-hosted `.exe` creation. Android APK builds from `clients/android` when the Android SDK/Gradle/JDK chain is available. IPA export requires a real Apple Developer account and provisioning profile and is reported as blocked if those are absent; VeilNode does not fabricate mobile binaries.

No client should reimplement crypto. GUI clients call the shared CLI/core and must expose v1/v2 reader compatibility plus crypto core v2.2 flows: identity/contact management, root lifecycle, root store, Shamir split/recover, seal/open, adaptive strategy features/generate/select/score/scan, replay controls, decoy, carrier audit/compare/profile, repair, migrate, doctor and test-vector.
