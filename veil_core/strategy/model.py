from __future__ import annotations

import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from veil_core.errors import VeilError

from .policy import CRYPTO_CORE_VERSION, EnvelopePolicy


MODEL_TYPE = "heuristic_ranker"
MODEL_VERSION = 1


def train_heuristic_model(dataset_path: str | Path, out_path: str | Path) -> dict[str, Any]:
    rows = []
    for line in Path(dataset_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    strategy_scores: dict[str, list[float]] = defaultdict(list)
    format_weights: dict[str, list[float]] = defaultdict(list)
    ratio_buckets: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        policy = row.get("candidate_policy", {})
        carrier = row.get("carrier_features", {})
        score = float(row.get("strategy_score", {}).get("overall_score", 1.0))
        fmt = str(carrier.get("format") or policy.get("carrier_format") or "unknown")
        strategy = str(policy.get("embed_strategy") or "unknown")
        ratio = float(carrier.get("payload_ratio", 0.0))
        bucket = _ratio_bucket(ratio)
        strategy_scores[f"{fmt}:{strategy}"].append(score)
        format_weights[fmt].append(score)
        ratio_buckets[fmt][bucket].append(score)
    model = {
        "model_type": MODEL_TYPE,
        "model_version": MODEL_VERSION,
        "crypto_core_version_supported": [CRYPTO_CORE_VERSION],
        "created_at": int(time.time()),
        "trained_sample_count": len(rows),
        "format_weights": {fmt: round(_avg(values), 6) for fmt, values in sorted(format_weights.items())},
        "strategy_scores": {key: round(_avg(values), 6) for key, values in sorted(strategy_scores.items())},
        "payload_ratio_buckets": {
            fmt: {bucket: round(_avg(values), 6) for bucket, values in sorted(buckets.items())}
            for fmt, buckets in sorted(ratio_buckets.items())
        },
        "risk_note": "Heuristic ranker predicts local engineering score only; verifier and scorer remain authoritative.",
    }
    _assert_model_safe(model)
    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(model, indent=2, ensure_ascii=False), encoding="utf-8")
    return inspect_model(dest)


def inspect_model(path: str | Path) -> dict[str, Any]:
    model = load_model(path)
    return {
        "model_type": model.get("model_type"),
        "model_version": model.get("model_version"),
        "supported_crypto_core_version": model.get("crypto_core_version_supported", []),
        "trained_sample_count": model.get("trained_sample_count", 0),
        "supported_formats": sorted(model.get("format_weights", {}).keys()),
        "created_at": model.get("created_at"),
    }


def load_model(path: str | Path) -> dict[str, Any]:
    model = json.loads(Path(path).read_text(encoding="utf-8"))
    _assert_model_safe(model)
    if model.get("model_type") != MODEL_TYPE:
        raise VeilError("unsupported strategy model type")
    if CRYPTO_CORE_VERSION not in model.get("crypto_core_version_supported", []):
        raise VeilError("strategy model does not support crypto core 2.2")
    return model


def rank_candidates(policies: list[EnvelopePolicy], model_path: str | Path | None, carrier_features: dict[str, Any] | None = None) -> list[EnvelopePolicy]:
    if not model_path:
        return policies
    model = load_model(model_path)
    ratio = float((carrier_features or {}).get("payload_ratio", 0.0))
    bucket = _ratio_bucket(ratio)

    def predicted(policy: EnvelopePolicy) -> float:
        key = f"{policy.carrier_format}:{policy.embed_strategy}"
        direct = model.get("strategy_scores", {}).get(key)
        fmt_score = model.get("format_weights", {}).get(policy.carrier_format, 0.5)
        bucket_score = model.get("payload_ratio_buckets", {}).get(policy.carrier_format, {}).get(bucket, fmt_score)
        if direct is None:
            direct = max(0.5, float(fmt_score) + 0.1)
        return float(direct) * 0.75 + float(bucket_score) * 0.25

    return sorted(policies, key=predicted)


def _ratio_bucket(value: float) -> str:
    if value <= 0.02:
        return "0-2pct"
    if value <= 0.05:
        return "2-5pct"
    if value <= 0.15:
        return "5-15pct"
    return "15pct-plus"


def _avg(values: list[float]) -> float:
    return sum(values) / max(1, len(values))


def _assert_model_safe(model: dict[str, Any]) -> None:
    raw = json.dumps(model, sort_keys=True).lower()
    for marker in ["root_vkp", "vkp_i", "message_key", "password", "root_seed"]:
        if marker in raw:
            raise VeilError("strategy model contains forbidden secret-like material")
