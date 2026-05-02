from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from veil_core.errors import VeilError

from .features import extract_features
from .generator import generate_policies_from_features
from .selector import dry_run_policy


def collect_dataset(samples_dir: str | Path, payloads_dir: str | Path, out: str | Path, *, candidates_per_sample: int = 30) -> dict[str, Any]:
    carriers = sorted(p for p in Path(samples_dir).rglob("*") if p.is_file())
    payloads = sorted(p for p in Path(payloads_dir).rglob("*") if p.is_file())
    if not carriers:
        raise VeilError("samples directory contains no carrier files")
    if not payloads:
        raise VeilError("payloads directory contains no payload files")
    rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="veil-dataset-") as tmp:
        tmpdir = Path(tmp)
        for carrier in carriers:
            for payload in payloads:
                try:
                    features = extract_features(carrier, payload)
                    policies = generate_policies_from_features(
                        features["carrier_features"],
                        features["payload_features"],
                        count=candidates_per_sample,
                        low_signature=True,
                    )
                except Exception:
                    continue
                scored = []
                for index, policy in enumerate(policies, start=1):
                    try:
                        item = dry_run_policy(carrier, payload, policy, tmpdir / f"{carrier.stem}-{payload.stem}-{index}{carrier.suffix}")
                    except Exception as exc:
                        item = {
                            "policy": policy.to_json(),
                            "audit_score": {},
                            "compare_score": {},
                            "strategy_score": {"overall_score": 1.0, "recommendation": "high", "notes": [str(exc)]},
                            "verify_carrier": {"ok": False},
                            "accepted": False,
                        }
                    scored.append(item)
                if not scored:
                    continue
                best_score = min(item["strategy_score"]["overall_score"] for item in scored if item["accepted"]) if any(item["accepted"] for item in scored) else None
                for item in scored:
                    row = {
                        "carrier_features": features["carrier_features"],
                        "payload_features": features["payload_features"],
                        "candidate_policy": item["policy"],
                        "audit_score": item["audit_score"],
                        "compare_score": item["compare_score"],
                        "strategy_score": item["strategy_score"],
                        "parser_valid": bool(item["verify_carrier"].get("ok")),
                        "selected": best_score is not None and item["accepted"] and item["strategy_score"]["overall_score"] == best_score,
                    }
                    _assert_dataset_safe(row)
                    rows.append(row)
    dest = Path(out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    return {"dataset": str(dest), "rows": len(rows), "secret_free": True}


def _assert_dataset_safe(row: dict[str, Any]) -> None:
    raw = json.dumps(row, sort_keys=True).lower()
    for marker in ["root_vkp", "vkp_i", "message_key", "password", "root_seed"]:
        if marker in raw:
            raise VeilError("dataset row contains forbidden secret-like material")
