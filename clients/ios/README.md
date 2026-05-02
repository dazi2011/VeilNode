# VeilNode iOS / iPadOS Client

This native SwiftUI client package provides the iOS/iPadOS shell for VeilNode mobile workflows.

Architecture:

`SwiftUI App -> platform FileProvider/SecureStore -> shared veil-core FFI/WASM/mobile binding`.

Client surfaces:

- Fixed app + imported `.vpkg` node package model.
- Files app / share-sheet oriented workflows.
- Keychain / Secure Enclave adapter boundary.
- SwiftUI TabView + NavigationStack shell.
- Inbox, seal, strategy, roots, carrier, contacts and settings navigation aligned with desktop terminology.
- v1/v2 reader compatibility plus crypto core v2.2 command coverage, including adaptive policy, fixed-signature scan, root lifecycle, Shamir backup, replay seen database, decoy and carrier audit/profile, is expected to route through the shared core.

Build:

```bash
cd clients/ios
xcodegen generate
xcodebuild -project VeilNodeiOS.xcodeproj -target VeilNodeiOS -configuration Release -sdk iphoneos build
```

The release packager can export `VeilNode-iOS-iPadOS.ipa` when `VEILNODE_DEVELOPMENT_TEAM` points to a valid Apple Developer Team ID and Xcode can create or use a provisioning profile. It does not create unsigned or fake IPA files.
