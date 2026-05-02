from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from veil_core.carrier_tools import carrier_compare
from veil_core.container import verify_container
from veil_core.errors import VeilError

from .policy import EnvelopePolicy, load_policy_file


FIXED_SIGNATURES = [
    b"VeilNode",
    b"veil-msg",
    b"root_vkp",
    b"vkp_i",
    b"message_key",
    b"crypto_core_version",
    b"veil-offline-envelope",
]


def scan_fixed_signatures(path: str | Path) -> dict[str, Any]:
    raw = Path(path).read_bytes()
    matches = []
    for marker in FIXED_SIGNATURES:
        start = 0
        while True:
            pos = raw.find(marker, start)
            if pos < 0:
                break
            matches.append({"signature": marker.decode("ascii"), "offset": pos})
            start = pos + len(marker)
    return {"found_plain_signatures": bool(matches), "matches": matches}


def score_paths(before: str | Path, after: str | Path, policy_path: str | Path | None = None, policy: EnvelopePolicy | None = None) -> dict[str, Any]:
    if policy is None:
        if policy_path is None:
            raise VeilError("policy is required")
        policy = load_policy_file(policy_path)
    policy.validate()
    before_path = Path(before)
    after_path = Path(after)
    before_raw = before_path.read_bytes()
    after_raw = after_path.read_bytes()
    verify = verify_container(after_path, policy.carrier_format)
    compare = carrier_compare(before_path, after_path, as_json=True)
    size_delta_ratio = abs(len(after_raw) - len(before_raw)) / max(1, len(before_raw))
    size_delta_score = min(1.0, size_delta_ratio)
    entropy_delta_score = min(1.0, abs(_entropy(after_raw) - _entropy(before_raw)) / 8.0)
    structure_delta_score = float(compare.get("structure_delta_score", 0.0))
    metadata_delta_score = float(compare.get("metadata_delta_score", 0.0))
    parser_validity_score = 0.0 if verify.get("ok") else 1.0
    scan = scan_fixed_signatures(after_path)
    fixed_signature_penalty = min(1.0, 0.35 * len(scan["matches"]))
    payload_size = max(0, len(after_raw) - len(before_raw))
    payload_ratio_penalty = min(1.0, payload_size / max(1, len(before_raw)) / max(0.01, float(policy.constraints.get("max_payload_ratio", 0.15))))
    weights = {
        "size_delta_score": 0.15,
        "entropy_delta_score": 0.15,
        "structure_delta_score": 0.20,
        "metadata_delta_score": 0.10,
        "parser_validity_score": 0.25,
        "fixed_signature_penalty": 0.25,
        "payload_ratio_penalty": 0.10,
    }
    overall = (
        size_delta_score * weights["size_delta_score"]
        + entropy_delta_score * weights["entropy_delta_score"]
        + structure_delta_score * weights["structure_delta_score"]
        + metadata_delta_score * weights["metadata_delta_score"]
        + parser_validity_score * weights["parser_validity_score"]
        + fixed_signature_penalty * weights["fixed_signature_penalty"]
        + payload_ratio_penalty * weights["payload_ratio_penalty"]
    )
    if not verify.get("ok"):
        overall = max(overall, 0.85)
    notes = ["local engineering risk score; it is not a detectability guarantee"]
    if not verify.get("ok"):
        notes.append("parser could not validate carrier")
    if scan["matches"]:
        notes.append("fixed plaintext signature found")
    return {
        "overall_score": round(min(1.0, overall), 4),
        "size_delta_score": round(size_delta_score, 4),
        "entropy_delta_score": round(entropy_delta_score, 4),
        "structure_delta_score": round(structure_delta_score, 4),
        "metadata_delta_score": round(metadata_delta_score, 4),
        "parser_validity_score": round(parser_validity_score, 4),
        "fixed_signature_penalty": round(fixed_signature_penalty, 4),
        "payload_ratio_penalty": round(payload_ratio_penalty, 4),
        "recommendation": _recommendation(overall, verify.get("ok", False)),
        "parser_valid": bool(verify.get("ok")),
        "fixed_signature_scan": scan,
        "notes": notes,
    }


def score_json(before: str | Path, after: str | Path, policy_path: str | Path) -> dict[str, Any]:
    return score_paths(before, after, policy_path=policy_path)


def _recommendation(score: float, parser_valid: bool) -> str:
    if not parser_valid or score >= 0.6:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


def _entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = Counter(raw)
    return -sum((count / len(raw)) * math.log2(count / len(raw)) for count in counts.values())
