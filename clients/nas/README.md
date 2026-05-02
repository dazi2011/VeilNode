# Unsupported Release Target

NAS GUI/web gateway support has been removed from the release matrix. Use the shared CLI for NAS automation:

```bash
veil-node doctor
veil-node seal ...
veil-node open ...
```

Keep root keyparts, passwords and carriers in separate storage locations. This folder is retained only as an explicit unsupported-target notice. NAS GUI/web code is not packaged in new releases.
