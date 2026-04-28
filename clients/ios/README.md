# VeilNode iOS / iPadOS Client

This native SwiftUI client package provides the iOS/iPadOS shell for VeilNode mobile workflows.

Architecture:

`SwiftUI App -> platform FileProvider/SecureStore -> shared veil-core FFI/WASM/mobile binding`.

Client surfaces:

- Fixed app + imported `.vpkg` node package model.
- Files app / share-sheet oriented workflows.
- Keychain / Secure Enclave adapter boundary.
- SwiftUI TabView + NavigationStack shell.
- Inbox, seal, contacts and settings navigation aligned with desktop terminology.
