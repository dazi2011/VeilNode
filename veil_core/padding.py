from __future__ import annotations

import secrets

from .errors import VeilError


def padding_len(current_len: int, policy: dict) -> int:
    mode = str(policy.get("padding", "bucket")).lower()
    bucket = max(1, int(policy.get("bucket_size", 65536)))
    if mode == "none":
        return 0
    if mode == "random":
        return secrets.randbelow(bucket + 1)
    if mode == "bucket":
        rounded = ((current_len + bucket - 1) // bucket) * bucket
        return (rounded - current_len) + secrets.randbelow(max(2, bucket // 8))
    raise VeilError(f"unknown padding mode: {mode}")


def estimate_padding(current_len: int, policy: dict) -> dict:
    mode = str(policy.get("padding", "bucket")).lower()
    bucket = max(1, int(policy.get("bucket_size", 65536)))
    if mode == "none":
        return {"mode": mode, "min": 0, "max": 0}
    if mode == "random":
        return {"mode": mode, "min": 0, "max": bucket}
    rounded = ((current_len + bucket - 1) // bucket) * bucket
    base = rounded - current_len
    return {"mode": mode, "min": base, "max": base + max(1, bucket // 8) - 1}
