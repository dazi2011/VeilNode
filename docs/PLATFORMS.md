# VeilNode Platform Clients

The split is simple: **`veil-core` owns crypto, message format and
compatibility**; **platform clients own UI and OS integration**. No client
re-implements crypto.

## Client matrix

| Platform | Path | Status | Verification |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | Native SwiftUI desktop app embedding `veil-core`. | `swift build --product VeilNode` |
| Windows | `clients/windows/VeilNodeGui.pyw` | Tk desktop GUI calling shared CLI. | `python -m py_compile clients/windows/VeilNodeGui.pyw` |
| iOS / iPadOS | `clients/ios/` | SwiftUI **companion app** (import, SHA-256, CLI commands). | `xcodegen generate && xcodebuild` |
| Android | `clients/android/` | Native Java **companion app** (import, SHA-256, CLI commands). | `gradle :app:assembleDebug` |
| Linux | — | CLI only. GUI release support removed. | `veil-node --help` |
| NAS | — | CLI only. GUI / web gateway release support removed. | `veil-node doctor` |

## macOS

- SwiftPM + SwiftUI desktop shell.
- `TabView` + `NavigationStack` layout with eight tabs:
  Dashboard · Seal · Open · Roots · Carrier · Strategy · Contacts · Settings.
- All file inputs use button-driven `NSOpenPanel`; users do not type paths.
- Batch seal / open across multiple files or messages.
- v1 external keypart and v2 root keypart modes side by side.
- Crypto core 2.2 surfaces: adaptive policy selection, fixed-signature scan,
  low-signature profile picker, root lifecycle, root store, carrier audit /
  compare / profile, strategy plan & score sections.
- Settings tab shows suite version, crypto core marker and direct links to
  the repo / latest release / docs.
- Release bundle (`VeilNode.app` inside the DMG) embeds the shared
  `veil-core` Python package and documentation under
  `Contents/Resources/VeilNodeCore`.
- `script/build_and_run.sh` supports `run`, `--debug`, `--logs`,
  `--telemetry`, `--verify`, `--package`.

## Windows

- GUI wrapper `clients/windows/VeilNodeGui.pyw` uses Tk and calls the shared
  `veil-core` package.
- `VeilNodeGui.bat` is the launcher inside the release ZIP.
- `BuildExe.bat` is a one-click PyInstaller helper that produces
  `dist/windows-exe/veil-node.exe` from the same source tree.
- The portable ZIP also contains every other `Build*` helper plus the full
  source tree, so a Windows host can build the Android APK
  (`BuildApk.bat`) without re-cloning.
- Tk GUI mirrors macOS surfaces: button-based pickers, batch seal / open,
  v1 / v2 modes, adaptive policy, fixed-signature scan, low-signature
  profile, root lifecycle, root store, carrier audit / compare / profile,
  full advanced CLI tab.

## iOS / iPadOS

iOS / iPadOS is a deliberately narrow **companion app**.

- Native SwiftUI tabs:
  Overview · Inspect · Commands · About.
- **Overview** — explains the companion-app boundary and the crypto-core
  fixed surface.
- **Inspect** — picks a file via the standard `fileImporter` (Files /
  iCloud Drive / share-sheet), reports name, size and SHA-256 using
  `CryptoKit` so you can confirm a carrier or `.vmsg` matches what the
  desktop produced. It does not decrypt.
- **Commands** — pre-canned, copy-to-clipboard CLI snippets covering
  doctor, identity create, root create, adaptive seal and open. Each card
  has a "Copy command" button.
- **About** — suite version, crypto core marker, and direct links to repo,
  latest release, technical notes, and platform matrix.
- Adapter surfaces for Files / share-sheet, Keychain, Secure Enclave and
  Face ID / Touch ID are documented at the boundary; on-device sealing or
  opening is **out of scope** by design.
- Signed IPA creation requires a valid Apple Developer account and
  provisioning profile. `BuildIpa.sh` refuses to fabricate an unsigned IPA.

## Android

Android is the same shape as iOS — a deliberately narrow **companion app**.

- Native Java single-Activity UI with four tabs:
  Overview · Inspect · Commands · About.
- **Inspect** uses `Intent.ACTION_OPEN_DOCUMENT` (Storage Access Framework)
  to pick a file and computes SHA-256 via `MessageDigest`.
- **Commands** mirrors the iOS card layout with a Copy button per command.
- **About** links to the repo and the latest release.
- Adapter surfaces for Storage Access Framework, Android Keystore /
  StrongBox, biometric unlock and share workflows are documented at the
  boundary; on-device sealing or opening is **out of scope** by design.
- The release packager emits a real debug-signed APK when JDK 17+, Gradle,
  and the Android SDK are available; production store signing must use a
  real release key.

## Linux

Linux GUI is no longer a supported release target. Use the shared CLI:

```bash
veil-node --help
veil-node doctor
veil-node seal ...
veil-node open ...
```

## NAS

NAS GUI / web gateway support is removed. Use CLI automation on NAS systems
and keep root material, passwords and carriers in **separate** storage
locations.

## Release packaging

```bash
veil-node package --release --out dist/release
```

The release manifest reports built and blocked artifacts. macOS DMG builds
on macOS when SwiftPM and `hdiutil` are present. The Windows ZIP is a
portable cross-platform bundle: GUI + Python zipapp + every `Build*`
helper + the source tree, so any host can build its target binary in
place. Android APK builds when the SDK + Gradle + JDK chain is available.
IPA export requires a real Apple Developer account and provisioning profile
and is reported as `blocked` if those are absent — VeilNode does not
fabricate mobile binaries.

No client re-implements crypto. GUI clients call the shared CLI / core and
expose v1 / v2 reader compatibility plus crypto core 2.2 flows: identity /
contact management, root lifecycle, root store, Shamir split / recover,
seal / open, adaptive strategy features / generate / select / score / scan,
replay controls, decoy, carrier audit / compare / profile, repair, migrate,
doctor and test-vector. Mobile companion apps deliberately stop at "import,
hash, copy command".
