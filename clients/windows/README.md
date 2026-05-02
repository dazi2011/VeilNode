# VeilNode Windows Client

`VeilNodeGui.pyw` is the Windows desktop GUI entrypoint. It calls the shared Python `veil-core` package and mirrors the macOS v1/v2 reader plus crypto core v2.2 workflow.

GUI behavior:

- Button-based file/folder selection; no manual path typing for seal/open paths.
- Batch seal/open command queue.
- v1/v2 reader compatibility, v2.2 root `.vkpseed`, adaptive policy, fixed-signature scan and low-signature workflows.
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

Or double-click `clients\windows\VeilNodeGui.bat` inside the release ZIP.

To build a local Windows executable on a Windows host:

```bat
clients\windows\BuildExe.bat
```

The portable ZIP includes a Python zipapp, GUI launcher and `BuildExe.bat`. Built `.exe` output belongs in `dist\windows-exe` or a GitHub Release asset, not in the source repository.
