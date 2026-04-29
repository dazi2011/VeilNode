# VeilNode Android Client

This Android client package provides the Jetpack Compose shell for VeilNode mobile workflows.

Architecture:

`Jetpack Compose App -> Storage Access Framework/FileProvider -> Android Keystore/StrongBox -> shared veil-core binding`.

Client surfaces:

- Fixed app + imported `.vpkg` node package model.
- Android share-sheet oriented workflows.
- Android Keystore / StrongBox adapter boundary.
- Inbox, seal, roots, carrier, contacts and settings navigation aligned with desktop terminology.
- v1/v2/v2.2 command coverage, including root lifecycle, Shamir backup, replay seen database, decoy and carrier audit/profile, is expected to route through the shared core.

Packaging note: final `.apk` creation requires Gradle Android project files and Android SDK tooling. This source package is not a signed APK by itself.
