# VeilNode NAS Client

`veil-node-web.py` is the local NAS gateway entrypoint. It exposes `/health`, which runs the shared `veil-core doctor` command.

Run locally:

```bash
clients/nas/veil-node-web.py
curl http://127.0.0.1:8765/health
```

Deployment model: explicit storage roots, authentication, reverse proxy guidance and read-only audit mode.
