# VeilNode NAS Client

`veil-node-web.py` is a minimal localhost NAS gateway scaffold. It exposes `/health`, which runs the shared `veil-core doctor` command.

It is intentionally local-only by default:

```bash
clients/nas/veil-node-web.py
curl http://127.0.0.1:8765/health
```

Production NAS work should add authentication, reverse proxy guidance, read-only audit mode and explicit storage roots before exposing any endpoint beyond localhost.
