from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

from veil_core.errors import VeilError


CapacityEstimator = Callable[[dict[str, Any]], int]


@dataclass(frozen=True)
class StrategySpec:
    name: str
    carrier_format: str
    max_payload_ratio: float
    capacity_estimator: str
    embedder: str
    extractor: str
    verifier: str
    audit_hooks: list[str]
    low_signature_compatible: bool

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def strategies_for_format(fmt: str) -> list[StrategySpec]:
    fmt = fmt.lower().lstrip(".")
    return [spec for spec in _REGISTRY if spec.carrier_format == fmt]


def get_strategy(name: str, fmt: str | None = None) -> StrategySpec:
    for spec in _REGISTRY:
        if spec.name == name and (fmt is None or spec.carrier_format == fmt):
            return spec
    raise VeilError(f"unknown strategy: {name}")


def list_strategies(fmt: str | None = None) -> dict[str, Any]:
    items = _REGISTRY if fmt is None else strategies_for_format(fmt)
    return {"strategies": [item.to_json() for item in items], "count": len(items)}


def estimate_capacity(spec: StrategySpec, carrier_features: dict[str, Any]) -> int:
    size = int(carrier_features.get("carrier_size", 0))
    capacity = int(carrier_features.get("capacity_estimate", 0))
    stats = dict(carrier_features.get("structure_stats", {}))
    if spec.carrier_format == "zip":
        if spec.name == "zip_comment":
            return min(65535, max(0, 65535 - int(stats.get("comment_size", 0))))
        if spec.name == "zip_extra_field":
            return max(0, int(stats.get("extra_field_total_size", 0)) + max(512, size // 4))
        return max(capacity, size * 2)
    if spec.carrier_format == "png":
        return max(capacity, size // 4)
    if spec.carrier_format == "mp4":
        free = int(stats.get("free_box_total_size", 0))
        return max(free, capacity, size // 6)
    if spec.carrier_format == "pdf":
        return max(capacity, size // 3)
    if spec.carrier_format == "wav":
        return max(capacity, int(stats.get("data_chunk_size", 0)) // 2)
    if spec.carrier_format in {"bmp", "7z"}:
        return max(capacity, size // 10)
    if spec.carrier_format == "vmsg":
        return max(capacity, size + 1024 * 1024)
    return capacity


def _spec(name: str, fmt: str, ratio: float, *, low: bool = True) -> StrategySpec:
    return StrategySpec(
        name=name,
        carrier_format=fmt,
        max_payload_ratio=ratio,
        capacity_estimator=f"{fmt}_capacity",
        embedder=f"{name}_embed",
        extractor=f"{name}_extract",
        verifier=f"{fmt}_verify",
        audit_hooks=[f"{fmt}_audit", "fixed_signature_scan"],
        low_signature_compatible=low,
    )


_REGISTRY = [
    _spec("zip_stored_member", "zip", 0.35),
    _spec("zip_extra_field", "zip", 0.10),
    _spec("zip_comment", "zip", 0.08),
    _spec("zip_distributed_entries", "zip", 0.30),
    _spec("zip_mimic_existing_entries", "zip", 0.25),
    _spec("png_single_ancillary", "png", 0.18),
    _spec("png_distributed_ancillary", "png", 0.22),
    _spec("png_palette_safe", "png", 0.05),
    _spec("mp4_single_free_box", "mp4", 0.18),
    _spec("mp4_multi_free_box", "mp4", 0.22),
    _spec("mp4_moov_adjacent", "mp4", 0.12),
    _spec("mp4_mdat_adjacent", "mp4", 0.16),
    _spec("pdf_incremental_object", "pdf", 0.20),
    _spec("pdf_object_stream", "pdf", 0.18),
    _spec("pdf_metadata_stream", "pdf", 0.10),
    _spec("wav_unknown_chunk", "wav", 0.18),
    _spec("wav_data_adjacent_chunk", "wav", 0.16),
    _spec("bmp_conservative_tail_append", "bmp", 0.08),
    _spec("sevenz_conservative_tail_append", "7z", 0.06),
    _spec("vmsg_internal_envelope", "vmsg", 0.95),
]
