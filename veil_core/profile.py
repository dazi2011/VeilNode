from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .container import SUPPORTED_FORMATS
from .crypto import DEFAULT_KDF, FAST_KDF, canonical_json, fingerprint, kdf_params
from .errors import VeilError
from .protocol import current_protocol


SECURITY_LEVELS: dict[str, dict[str, Any]] = {
    "dev": {
        "kdf": FAST_KDF,
        "chunk_size": 16384,
        "padding": "random",
        "bucket_size": 16384,
    },
    "balanced": {
        "kdf": DEFAULT_KDF,
        "chunk_size": 65536,
        "padding": "bucket",
        "bucket_size": 65536,
    },
    "hardened": {
        "kdf": {
            "memory_kib": 262144,
            "iterations": 4,
            "lanes": 4,
            "length": 32,
        },
        "chunk_size": 32768,
        "padding": "bucket",
        "bucket_size": 262144,
    },
}


def build_profile(
    *,
    name: str = "veil-node",
    security_level: str = "balanced",
    containers: list[str] | None = None,
) -> dict[str, Any]:
    if security_level not in SECURITY_LEVELS:
        raise VeilError(f"unknown security level: {security_level}")
    formats = containers or sorted(SUPPORTED_FORMATS)
    invalid = [fmt for fmt in formats if fmt not in SUPPORTED_FORMATS]
    if invalid:
        raise VeilError(f"unsupported containers: {', '.join(invalid)}")
    base = dict(SECURITY_LEVELS[security_level])
    base.update(
        {
            "kind": "veil-profile",
            "profile_version": 1,
            "node_name": name,
            "security_level": security_level,
            "supported_containers": formats,
            "protocol": current_protocol(),
            "receive_failure_messages": [
                "unable to open message",
                "operation failed",
                "message could not be recovered",
            ],
        }
    )
    base["kdf"] = kdf_params(base["kdf"])
    base["profile_id"] = fingerprint(canonical_json({k: v for k, v in base.items() if k != "profile_id"}))
    return base


def load_profile(path: str | Path | None, defaults: dict[str, Any]) -> dict[str, Any]:
    profile = dict(defaults)
    if path:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        profile.update(data)
    profile["kdf"] = kdf_params(profile.get("kdf"))
    profile.setdefault("protocol", current_protocol())
    profile.setdefault("profile_version", 1)
    profile.setdefault("security_level", "custom")
    return profile


def write_profile(path: str | Path, profile: dict[str, Any]) -> dict[str, Any]:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return profile


def profile_summary(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_name": profile.get("node_name"),
        "profile_version": profile.get("profile_version", 1),
        "security_level": profile.get("security_level", "custom"),
        "protocol": profile.get("protocol"),
        "chunk_size": profile.get("chunk_size"),
        "padding": profile.get("padding"),
        "bucket_size": profile.get("bucket_size"),
        "containers": profile.get("supported_containers", []),
        "kdf": profile.get("kdf"),
        "profile_id": profile.get("profile_id"),
    }
