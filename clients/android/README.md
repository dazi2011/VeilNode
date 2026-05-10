# VeilNode Android Client

This is the **companion app** for VeilNode on Android. Like iOS, it does
**not** ship a Python crypto core, and does **not** seal or open messages
on-device. The desktop CLI / GUI is the single source of truth for
cryptography.

What the companion app does:

- **Overview** — explains the companion-app boundary and the fixed
  cryptographic surface.
- **Inspect** — picks a file via `Intent.ACTION_OPEN_DOCUMENT` (Storage
  Access Framework) and reports name, size and SHA-256 computed by
  `MessageDigest`, so you can confirm a carrier matches what the desktop
  produced. It does not decrypt.
- **Commands** — copy-to-clipboard CLI snippets for doctor, identity
  create, root keypart create, adaptive seal and open.
- **About** — suite version, crypto core marker, repo / release links.

## Build

```bash
cd clients/android
gradle :app:assembleDebug --no-daemon --console=plain
```

Or use the one-click helper:

```bash
clients/android/BuildApk.sh   # macOS / Linux host
clients\android\BuildApk.bat  :: Windows host
```

The release packager (`veil-node package --release`) copies
`app/build/outputs/apk/debug/app-debug.apk` to
`VeilNode-Android-debug.apk` when JDK 17+, Gradle and the Android SDK are
available on the host. Production store signing must use a real release
key — VeilNode does not fabricate one.
