# VeilNode Android Client

This Android client package provides the Jetpack Compose shell for VeilNode mobile workflows.

Architecture:

`Jetpack Compose App -> Storage Access Framework/FileProvider -> Android Keystore/StrongBox -> shared veil-core binding`.

Client surfaces:

- Fixed app + imported `.vpkg` node package model.
- Android share-sheet oriented workflows.
- Android Keystore / StrongBox adapter boundary.
- Inbox, seal, contacts and settings navigation aligned with desktop terminology.
