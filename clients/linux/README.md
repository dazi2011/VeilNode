# VeilNode Linux Client

`veil-node-gui` is the current Linux desktop GUI wrapper. It calls the shared Python `veil-core` package and does not reimplement encryption.

Planned native adapters:

- SecureStore: Secret Service, GNOME Keyring, KWallet.
- DeviceBinding: TPM2 and YubiKey.
- Packaging: AppImage, deb, rpm, Flatpak.

Run from the repository root:

```bash
clients/linux/veil-node-gui
```
