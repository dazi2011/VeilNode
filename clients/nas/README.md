# Unsupported Release Target

NAS GUI/web gateway support has been removed from the release matrix. Use the shared CLI for NAS automation:

```bash
veil-node doctor
veil-node seal ...
veil-node open ...
```

Keep root keyparts, passwords and carriers in separate storage locations. This legacy folder is retained only for source-history compatibility and is not packaged in new releases.
