from __future__ import annotations

import json
import platform
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .bootstrap import missing_dependencies
from .container import SUPPORTED_FORMATS, capacity_report, generate_carrier, verify_container
from .crypto import _xchacha20_subkey_and_nonce, sha256
from .identity import IdentityStore
from .permissions import home_permission_report
from .platform import platform_report
from .profile import profile_summary
from .protocol import compatibility_report, current_protocol


def doctor(home: str | Path, profile: dict) -> dict:
    checks = []
    missing = missing_dependencies()
    checks.append({"name": "dependencies", "ok": not missing, "missing": missing})
    checks.append({"name": "python", "ok": sys.version_info >= (3, 11), "version": sys.version})
    checks.append({"name": "crypto-self-test", "ok": _crypto_self_test()})
    protocol = compatibility_report(profile.get("protocol"))
    checks.append({"name": "protocol", "ok": protocol["compatible"], **protocol})
    checks.append({"name": "profile", "ok": True, "summary": profile_summary(profile)})
    tools = {tool: shutil.which(tool) is not None for tool in ["ffmpeg", "ffprobe", "7z"]}
    checks.append({"name": "external-tools", "ok": True, "tools": tools})
    checks.append({"name": "permissions", "ok": True, "report": home_permission_report(home)})
    checks.append({"name": "platform-adapters", "ok": True, "report": platform_report()})
    return {
        "ok": all(item.get("ok", False) for item in checks if item["name"] not in {"external-tools", "permissions"}),
        "platform": platform.platform(),
        "protocol": current_protocol(),
        "checks": checks,
    }


def audit(home: str | Path, profile: dict) -> dict:
    store = IdentityStore(home)
    state = store.list_identities()
    private = state.get("private")
    findings = []
    if not private:
        findings.append({"severity": "warn", "message": "no local private identity"})
    perms = home_permission_report(home)
    for item in perms.get("private_files", []):
        if not item.get("ok"):
            findings.append({"severity": "warn", "message": f"loose permissions: {item['path']}", "mode": item.get("mode")})
    kdf = profile.get("kdf", {})
    if int(kdf.get("memory_kib", 0)) < 65536:
        findings.append({"severity": "warn", "message": "KDF memory is below balanced profile"})
    return {
        "ok": not any(item["severity"] == "error" for item in findings),
        "identity": {"present": private is not None, "contacts": len(state.get("contacts", []))},
        "permissions": perms,
        "findings": findings,
    }


def capacity(path: str | Path | None, fmt: str | None, payload_size: int | None = None) -> dict:
    return capacity_report(path, fmt, payload_size=payload_size)


def verify_carrier(path: str | Path, fmt: str | None = None) -> dict:
    return verify_container(path, fmt)


def verify_all_generated_carriers() -> dict:
    results = []
    root = Path.cwd()
    for fmt in sorted(SUPPORTED_FORMATS):
        data = generate_carrier(fmt)
        target = root / f".veil-verify-{fmt}.{fmt}"
        target.write_bytes(data)
        try:
            results.append(verify_container(target, fmt))
        finally:
            try:
                target.unlink()
            except OSError:
                pass
    return {"ok": all(item["ok"] for item in results), "results": results}


def _crypto_self_test() -> bool:
    key = bytes(range(32))
    nonce = bytes(range(24))
    aad = b"veil-doctor"
    plain = b"self-test"
    sub, n12 = _xchacha20_subkey_and_nonce(key, nonce)
    aead = ChaCha20Poly1305(sub)
    ciphertext = aead.encrypt(n12, plain, aad)
    return aead.decrypt(n12, ciphertext, aad) == plain and len(sha256(ciphertext)) == 32
