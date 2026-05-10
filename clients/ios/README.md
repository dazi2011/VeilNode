# VeilNode iOS / iPadOS Client

This is the **companion app** for VeilNode on iOS and iPadOS. It does
**not** ship a Python crypto core, and does **not** seal or open messages
on-device. The desktop CLI / GUI is the single source of truth for
cryptography.

What the companion app does:

- **Overview** — explains the companion-app boundary and the fixed
  cryptographic surface (`root_vkp`, HKDF, Argon2id, AEAD, `msg_id`,
  `message_salt`, `file_hash`, root-derived `vkp_i`, `message_key`).
- **Inspect** — picks a file via the standard SwiftUI `fileImporter`
  (Files / iCloud Drive / share-sheet) and reports name, size and a
  SHA-256 computed by `CryptoKit`, so you can confirm a carrier or a
  `.vmsg` matches what the desktop produced. It does not decrypt.
- **Commands** — pre-canned CLI snippets covering doctor, identity
  create, root keypart create, adaptive seal and open. Each card has a
  Copy command button.
- **About** — suite version, crypto core marker, links to the project
  repo, latest release, technical notes, and platform matrix.

## Build

```bash
cd clients/ios
xcodegen generate
xcodebuild -project VeilNodeiOS.xcodeproj -scheme VeilNodeiOS \
  -configuration Release -sdk iphoneos build
```

Or run the one-click signed-IPA helper from a macOS host:

```bash
export VEILNODE_DEVELOPMENT_TEAM=ABCDE12345   # your Apple Team ID
clients/ios/BuildIpa.sh
```

`BuildIpa.sh` refuses to produce an unsigned or fake IPA. The release
packager (`veil-node package --release`) reports the IPA as `blocked` if
no team is configured, and the workflow does not fabricate one.
