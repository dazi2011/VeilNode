# VeilNode Windows Client

`VeilNodeGui.pyw` is the Windows desktop GUI entrypoint. It calls the shared Python `veil-core` package and mirrors the macOS v1/v2/v2.2 workflow.

GUI behavior:

- Button-based file/folder selection; no manual path typing for seal/open paths.
- Batch seal/open command queue.
- v1 external `.vkp`, v2 root `.vkpseed` and crypto core v2.2 low-signature workflows.
- Root lifecycle, root store, Shamir split/recover, carrier audit/compare/profile and advanced CLI command access.

Platform adapter coverage:

- SecureStore: Credential Manager / DPAPI.
- DeviceBinding: TPM and Windows Hello.
- FileProvider: Explorer file paths and context menu integration.
- Installer: MSI / MSIX.

Run from the repository root:

```powershell
python clients\windows\VeilNodeGui.pyw
```

Or double-click `clients\windows\VeilNodeGui.bat` inside the release ZIP. The portable ZIP includes a Python zipapp; a native `.exe` must be produced on a Windows build host with PyInstaller or an equivalent packager.
