from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from veil_core.errors import VeilError


CRYPTO_CORE_VERSION = "2.2"
POLICY_VERSION = 1
SECRET_FIELD_MARKERS = {
    "root_seed",
    "root_vkp",
    "vkp_i",
    "message_key",
    "password",
    "private_key",
    "secret",
}
CHUNK_PROFILES = {
    "fixed_8k",
    "fixed_16k",
    "fixed_32k",
    "fixed_64k",
    "mixed_small",
    "mixed_medium",
    "mimic_payload",
}
PADDING_PROFILES = {"none", "random", "bucket", "mimic-carrier", "fixed-profile"}
METADATA_LAYOUTS = {"encrypted_single", "encrypted_split", "encrypted_split_shuffled", "encrypted_minimal_outer"}
LOCATOR_STRATEGIES = {"keyed_locator_v2", "distributed_locator", "encrypted_locator_hint"}


@dataclass(frozen=True)
class EnvelopePolicy:
    policy_version: int = POLICY_VERSION
    crypto_core_version: str = CRYPTO_CORE_VERSION
    carrier_format: str = "vmsg"
    embed_strategy: str = "vmsg_internal_envelope"
    chunk_profile: str = "mixed_medium"
    padding_profile: str = "mimic-carrier"
    metadata_layout: str = "encrypted_split"
    locator_strategy: str = "keyed_locator_v2"
    low_signature: bool = True
    risk_budget: float = 0.25
    randomization_seed_id: str = field(default_factory=lambda: secrets.token_hex(8))
    constraints: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        data = asdict(self)
        _assert_no_secret_material(data)
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "EnvelopePolicy":
        _assert_no_secret_material(data)
        if int(data.get("policy_version", POLICY_VERSION)) != POLICY_VERSION:
            raise VeilError("unsupported envelope policy version")
        if str(data.get("crypto_core_version", CRYPTO_CORE_VERSION)) != CRYPTO_CORE_VERSION:
            raise VeilError("policy cannot change crypto_core_version; only 2.2 is supported")
        policy = cls(
            policy_version=int(data.get("policy_version", POLICY_VERSION)),
            crypto_core_version=str(data.get("crypto_core_version", CRYPTO_CORE_VERSION)),
            carrier_format=str(data.get("carrier_format", "vmsg")).lower(),
            embed_strategy=str(data.get("embed_strategy", "vmsg_internal_envelope")),
            chunk_profile=str(data.get("chunk_profile", "mixed_medium")),
            padding_profile=str(data.get("padding_profile", "mimic-carrier")),
            metadata_layout=str(data.get("metadata_layout", "encrypted_split")),
            locator_strategy=str(data.get("locator_strategy", "keyed_locator_v2")),
            low_signature=bool(data.get("low_signature", True)),
            risk_budget=float(data.get("risk_budget", 0.25)),
            randomization_seed_id=str(data.get("randomization_seed_id") or secrets.token_hex(8)),
            constraints=dict(data.get("constraints", {})),
        )
        policy.validate()
        return policy

    def validate(self, *, expected_format: str | None = None) -> None:
        _assert_no_secret_material(self.to_json())
        if self.crypto_core_version != CRYPTO_CORE_VERSION:
            raise VeilError("policy cannot alter crypto core")
        if expected_format and self.carrier_format != expected_format:
            raise VeilError(f"policy carrier format {self.carrier_format} does not match {expected_format}")
        if self.chunk_profile not in CHUNK_PROFILES:
            raise VeilError(f"unsupported chunk profile: {self.chunk_profile}")
        if self.padding_profile not in PADDING_PROFILES:
            raise VeilError(f"unsupported padding profile: {self.padding_profile}")
        if self.metadata_layout not in METADATA_LAYOUTS:
            raise VeilError(f"unsupported metadata layout: {self.metadata_layout}")
        if self.locator_strategy not in LOCATOR_STRATEGIES:
            raise VeilError(f"unsupported locator strategy: {self.locator_strategy}")
        if not 0.0 <= self.risk_budget <= 1.0:
            raise VeilError("risk_budget must be between 0 and 1")


def load_policy_file(path: str | Path) -> EnvelopePolicy:
    return EnvelopePolicy.from_json(json.loads(Path(path).read_text(encoding="utf-8")))


def save_policy_file(policy: EnvelopePolicy, path: str | Path) -> dict[str, Any]:
    policy.validate()
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(policy.to_json(), indent=2, ensure_ascii=False), encoding="utf-8")
    return {"policy": str(dest), "secret_free": True}


def inspect_policy(path: str | Path) -> dict[str, Any]:
    policy = load_policy_file(path)
    data = policy.to_json()
    return {
        "valid": True,
        "secret_free": True,
        "policy_version": data["policy_version"],
        "crypto_core_version": data["crypto_core_version"],
        "carrier_format": data["carrier_format"],
        "embed_strategy": data["embed_strategy"],
        "chunk_profile": data["chunk_profile"],
        "padding_profile": data["padding_profile"],
        "metadata_layout": data["metadata_layout"],
        "locator_strategy": data["locator_strategy"],
        "low_signature": data["low_signature"],
        "risk_budget": data["risk_budget"],
        "constraints": data["constraints"],
    }


def policy_runtime_overrides(policy: EnvelopePolicy) -> dict[str, Any]:
    chunk_size = {
        "fixed_8k": 8192,
        "fixed_16k": 16384,
        "fixed_32k": 32768,
        "fixed_64k": 65536,
        "mixed_small": 16384,
        "mixed_medium": 32768,
        "mimic_payload": 65536,
    }[policy.chunk_profile]
    padding_mode = {
        "none": "none",
        "random": "random",
        "bucket": "bucket",
        "mimic-carrier": "bucket",
        "fixed-profile": "bucket",
    }[policy.padding_profile]
    bucket_size = max(chunk_size, 8192)
    return {
        "chunk_size": chunk_size,
        "padding": padding_mode,
        "bucket_size": bucket_size,
        "envelope_policy": policy.to_json(),
    }


def _assert_no_secret_material(data: Any, path: str = "") -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            lowered = str(key).lower()
            if any(marker in lowered for marker in SECRET_FIELD_MARKERS):
                raise VeilError(f"policy contains forbidden secret-like field: {path + str(key)}")
            _assert_no_secret_material(value, f"{path}{key}.")
    elif isinstance(data, list):
        for index, value in enumerate(data):
            _assert_no_secret_material(value, f"{path}{index}.")
    elif isinstance(data, str):
        lowered = data.lower()
        if any(marker in lowered for marker in {"root_vkp", "vkp_i", "message_key", "password"}):
            raise VeilError("policy contains forbidden secret-like value")
