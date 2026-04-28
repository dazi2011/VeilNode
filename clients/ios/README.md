# VeilNode iOS Client

This is the native iOS/iPadOS client scaffold. It intentionally does not reimplement cryptography.

The intended production bridge is:

`SwiftUI App -> platform FileProvider/SecureStore -> shared veil-core FFI/WASM/mobile binding`.

Current scaffold covers:

- Fixed app + imported `.vpkg` node package model.
- Files app / share-sheet oriented workflows.
- Keychain / Secure Enclave adapter boundary.
- SwiftUI TabView + NavigationStack shell.

The desktop CLI remains the reference implementation until the mobile binding is added.
