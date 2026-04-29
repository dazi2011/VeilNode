from __future__ import annotations

import json
import platform
import sys
from pathlib import Path

from .protocol import current_protocol, protocol_v2


VECTOR_SHA256 = "exsSIWRZx1sHfvT1YALeRPDwweeNq4ioZMgNkadMLNo"


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    command = args[0] if args else "doctor"
    if command == "doctor":
        result = _doctor()
    elif command == "test-vector":
        result = _test_vector_status()
    else:
        raise SystemExit(f"unsupported gui bridge command: {command}")
    print(json.dumps(result, indent=2, ensure_ascii=False))


def _doctor() -> dict:
    checks = [
        {"name": "python", "ok": sys.version_info >= (3, 9), "version": sys.version},
        {
            "name": "protocol",
            "ok": True,
            "message": {
                "default": current_protocol(),
                "root_keypart": protocol_v2(),
                "offline_envelope_crypto_core": "2.2",
            },
        },
        {"name": "project-root", "ok": _project_root_present()},
        {"name": "gui-bridge", "ok": True, "message": "Lightweight GUI health path is active."},
        {"name": "note", "ok": True, "message": "Run veil-node doctor and veil-node test-vector for full dependency and crypto verification."},
    ]
    return {
        "ok": all(item["ok"] for item in checks),
        "platform": platform.platform(),
        "protocol": {"default": current_protocol(), "root_keypart": protocol_v2(), "crypto_core_version": "2.2"},
        "checks": checks,
    }


def _test_vector_status() -> dict:
    return {
        "ok": True,
        "protocol": {"default": current_protocol(), "root_keypart": protocol_v2(), "crypto_core_version": "2.2"},
        "vectors": [
            {
                "name": "veil-xchacha20poly1305-v1",
                "expected_sha256": VECTOR_SHA256,
                "source": "GUI bridge status; full vector verified by veil-node test-vector.",
            },
            {
                "name": "veil-root-vkp-derivation-v2",
                "source": "GUI bridge status; full vector verified by veil-node test-vector.",
            },
            {
                "name": "veil-offline-envelope-core-v2.2-metadata",
                "crypto_core_version": "2.2",
                "source": "GUI bridge status; full vector verified by veil-node test-vector.",
            }
        ],
    }


def _project_root_present() -> bool:
    root = Path(__file__).resolve().parents[1]
    return (root / "veil_core").exists() and (root / "pyproject.toml").exists()
