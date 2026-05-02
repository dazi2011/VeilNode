# VeilNode Android Client

This Android client package provides a minimal native Android shell for VeilNode mobile workflows. It deliberately uses standard Android widgets and the Android Gradle Plugin so a real debug-signed APK can be produced without adding a separate UI framework.

Architecture:

`Android Activity -> Storage Access Framework/FileProvider -> Android Keystore/StrongBox -> shared veil-core binding`.

Client surfaces:

- Fixed app + imported `.vpkg` node package model.
- Android share-sheet oriented workflows.
- Android Keystore / StrongBox adapter boundary.
- Inbox, seal, strategy, roots, carrier, contacts and settings navigation aligned with desktop terminology.
- v1/v2 reader compatibility plus crypto core v2.2 command coverage, including adaptive policy, fixed-signature scan, root lifecycle, Shamir backup, replay seen database, decoy and carrier audit/profile, is expected to route through the shared core.

Build:

```bash
cd clients/android
gradle :app:assembleDebug --no-daemon --console=plain
```

The release packager copies `app/build/outputs/apk/debug/app-debug.apk` as `VeilNode-Android-debug.apk` when Android SDK tooling and a working Java runtime are available. Store release signing is not fabricated; configure a real signing key before distributing a production APK.
