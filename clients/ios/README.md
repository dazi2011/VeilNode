# VeilNode iOS / iPadOS Client

This native SwiftUI client package provides the iOS/iPadOS shell for VeilNode mobile workflows.

Architecture:

`SwiftUI App -> platform FileProvider/SecureStore -> shared veil-core FFI/WASM/mobile binding`.

Client surfaces:

- Fixed app + imported `.vpkg` node package model.
- Files app / share-sheet oriented workflows.
- Keychain / Secure Enclave adapter boundary.
- SwiftUI TabView + NavigationStack shell.
- Inbox, seal, roots, carrier, contacts and settings navigation aligned with desktop terminology.
- v1/v2/v2.2 command coverage, including root lifecycle, Shamir backup, replay seen database, decoy and carrier audit/profile, is expected to route through the shared core.

Packaging note: final `.ipa` creation requires an Xcode project/workspace, signing identity and provisioning profile. This source package is not a signed IPA by itself.
