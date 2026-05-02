from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from veil_core.errors import VeilError

from .features import extract_features
from .policy import (
    CHUNK_PROFILES,
    LOCATOR_STRATEGIES,
    METADATA_LAYOUTS,
    PADDING_PROFILES,
    CRYPTO_CORE_VERSION,
    EnvelopePolicy,
)
from .registry import estimate_capacity, strategies_for_format


def generate_policies(
    carrier_path: str | Path,
    payload_path: str | Path,
    *,
    count: int = 50,
    low_signature: bool = True,
) -> dict[str, Any]:
    features = extract_features(carrier_path, payload_path)
    policies = generate_policies_from_features(features["carrier_features"], features["payload_features"], count=count, low_signature=low_signature)
    return {
        **features,
        "candidate_count": len(policies),
        "policies": [policy.to_json() for policy in policies],
    }


def generate_policies_from_features(
    carrier_features: dict[str, Any],
    payload_features: dict[str, Any],
    *,
    count: int = 50,
    low_signature: bool = True,
) -> list[EnvelopePolicy]:
    fmt = str(carrier_features.get("format", "")).lower()
    payload_size = int(payload_features.get("payload_size", carrier_features.get("payload_size", 0)))
    required_capacity = payload_size + 1024
    carrier_size = int(carrier_features.get("carrier_size", 0))
    payload_ratio = payload_size / max(1, carrier_size)
    strategies = [
        spec
        for spec in strategies_for_format(fmt)
        if (not low_signature or spec.low_signature_compatible)
        and estimate_capacity(spec, carrier_features) >= required_capacity
        and payload_ratio <= spec.max_payload_ratio
    ]
    if not strategies:
        raise VeilError(f"no legal envelope strategies fit {fmt} carrier and payload")
    rnd = secrets.SystemRandom()
    chunk_profiles = sorted(CHUNK_PROFILES)
    padding_profiles = sorted(PADDING_PROFILES)
    metadata_layouts = sorted(METADATA_LAYOUTS)
    locator_strategies = sorted(LOCATOR_STRATEGIES)
    out: list[EnvelopePolicy] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    attempts = max(count * 20, 100)
    for _ in range(attempts):
        spec = rnd.choice(strategies)
        policy = EnvelopePolicy(
            crypto_core_version=CRYPTO_CORE_VERSION,
            carrier_format=fmt,
            embed_strategy=spec.name,
            chunk_profile=rnd.choice(chunk_profiles),
            padding_profile=rnd.choice(padding_profiles),
            metadata_layout=rnd.choice(metadata_layouts),
            locator_strategy=rnd.choice(locator_strategies),
            low_signature=low_signature,
            risk_budget=0.25 if payload_ratio <= 0.15 else 0.4,
            constraints={
                "max_payload_ratio": spec.max_payload_ratio,
                "preserve_timestamps": True,
                "avoid_tail_append": fmt not in {"bmp", "7z"},
                "capacity_estimate": estimate_capacity(spec, carrier_features),
            },
        )
        policy.validate(expected_format=fmt)
        key = (policy.embed_strategy, policy.chunk_profile, policy.padding_profile, policy.metadata_layout, policy.locator_strategy)
        if key in seen:
            continue
        seen.add(key)
        out.append(policy)
        if len(out) >= count:
            break
    return out
