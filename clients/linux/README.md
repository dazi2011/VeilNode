# VeilNode Linux Client

`veil-node-gui` is the Linux desktop GUI entrypoint. It calls the shared Python `veil-core` package and mirrors the Windows Tk desktop workflow.

Platform adapter coverage:

- SecureStore: Secret Service, GNOME Keyring, KWallet.
- DeviceBinding: TPM2 and YubiKey.
- Packaging: AppImage, deb, rpm, Flatpak.

Run from the repository root:

```bash
clients/linux/veil-node-gui
```
