# VeilNode Windows Client

`VeilNodeGui.pyw` is the Windows desktop GUI entrypoint. It calls the shared Python `veil-core` package and mirrors the macOS v1/v2 workflow.

GUI behavior:

- Button-based file/folder selection; no manual path typing for seal/open paths.
- Batch seal/open command queue.
- v1 external `.vkp` and v2 root `.vkpseed` workflows.

Platform adapter coverage:

- SecureStore: Credential Manager / DPAPI.
- DeviceBinding: TPM and Windows Hello.
- FileProvider: Explorer file paths and context menu integration.
- Installer: MSI / MSIX.

Run from the repository root:

```powershell
python clients\windows\VeilNodeGui.pyw
```

Or double-click `clients\windows\VeilNodeGui.bat` inside the release ZIP.
