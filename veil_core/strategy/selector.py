from __future__ import annotations

import secrets
import tempfile
from pathlib import Path
from typing import Any

from veil_core.carrier_tools import carrier_audit, carrier_compare
from veil_core.container import embed_payload, verify_container
from veil_core.errors import VeilError

from .features import extract_features
from .generator import generate_policies_from_features
from .model import rank_candidates
from .policy import EnvelopePolicy
from .scorer import score_paths


def select_policy(
    carrier_path: str | Path,
    payload_path: str | Path,
    *,
    count: int = 50,
    model_path: str | Path | None = None,
    low_signature: bool = True,
) -> dict[str, Any]:
    features = extract_features(carrier_path, payload_path)
    candidates = generate_policies_from_features(features["carrier_features"], features["payload_features"], count=count, low_signature=low_signature)
    candidates = rank_candidates(candidates, model_path, features["carrier_features"])
    evaluated: list[dict[str, Any]] = []
    best: dict[str, Any] | None = None
    with tempfile.TemporaryDirectory(prefix="veil-policy-") as tmp:
        tmpdir = Path(tmp)
        for index, policy in enumerate(candidates, start=1):
            try:
                result = dry_run_policy(carrier_path, payload_path, policy, tmpdir / f"candidate-{index}{Path(carrier_path).suffix}")
            except Exception as exc:
                result = {
                    "policy": policy.to_json(),
                    "strategy_score": {"overall_score": 1.0, "recommendation": "high", "notes": [str(exc)]},
                    "accepted": False,
                    "reject_reason": str(exc),
                }
            evaluated.append(result)
            if not result["accepted"]:
                continue
            if best is None or result["strategy_score"]["overall_score"] < best["strategy_score"]["overall_score"]:
                best = result
    if best is None:
        raise VeilError("no adaptive policy candidate survived verify-carrier and scoring")
    return {
        **features,
        "selected_policy": best["policy"],
        "selected_score": best["strategy_score"],
        "evaluated_count": len(evaluated),
        "accepted_count": sum(1 for item in evaluated if item["accepted"]),
        "model_used": bool(model_path),
        "temp_cleaned": True,
        "candidates": [
            {
                "policy": item["policy"],
                "strategy_score": item["strategy_score"],
                "accepted": item["accepted"],
                "reject_reason": item.get("reject_reason"),
            }
            for item in evaluated
        ],
    }


def dry_run_policy(carrier_path: str | Path, payload_path: str | Path, policy: EnvelopePolicy, out_path: str | Path) -> dict[str, Any]:
    policy.validate(expected_format=policy.carrier_format)
    carrier = Path(carrier_path).read_bytes()
    payload_size = Path(payload_path).stat().st_size
    # Dry-run payload is random local bytes; it never contains user secrets.
    envelope_overhead = 96 * 1024 if policy.embed_strategy == "zip_comment" else 8192
    dry_payload = secrets.token_bytes(max(1, payload_size + envelope_overhead))
    output = Path(out_path)
    embedded = embed_payload(carrier, dry_payload, policy.carrier_format, strategy=policy.embed_strategy)
    output.write_bytes(embedded.data)
    verify = verify_container(output, policy.carrier_format)
    audit = carrier_audit(output, as_json=True)
    compare = carrier_compare(carrier_path, output, as_json=True)
    score = score_paths(carrier_path, output, policy=policy)
    accepted = bool(verify.get("ok")) and score["fixed_signature_penalty"] == 0.0
    reason = None
    if not verify.get("ok"):
        reason = "verify-carrier failed"
    elif score["fixed_signature_penalty"] > 0:
        reason = "fixed plaintext signature found"
    return {
        "policy": policy.to_json(),
        "dry_run_output": str(output),
        "embed_result": {"mode": embedded.mode, "offset": embedded.offset, "length": embedded.length, "extra": embedded.extra},
        "verify_carrier": verify,
        "audit_score": audit,
        "compare_score": compare,
        "strategy_score": score,
        "accepted": accepted,
        "reject_reason": reason,
    }
