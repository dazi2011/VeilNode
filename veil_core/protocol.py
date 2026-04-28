from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import VeilError


PROTOCOL_NAME = "veil-msg"
PROTOCOL_VERSION = 1
MIN_READER_VERSION = 1
MAX_READER_VERSION = 2
CRYPTO_SUITE_V1 = "argon2id-hkdf-x25519-xchacha20poly1305-aes256gcm-v1"
CRYPTO_SUITE_V2 = "root-vkp-hkdf-argon2id-x25519-xchacha20poly1305-aes256gcm-v2"
CRYPTO_SUITE = CRYPTO_SUITE_V1


@dataclass(frozen=True)
class ProtocolInfo:
    name: str = PROTOCOL_NAME
    version: int = PROTOCOL_VERSION
    min_reader: int = MIN_READER_VERSION
    suite: str = CRYPTO_SUITE

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "min_reader": self.min_reader,
            "suite": self.suite,
        }


def current_protocol() -> dict[str, Any]:
    return ProtocolInfo().to_json()


def protocol_v2() -> dict[str, Any]:
    return ProtocolInfo(version=2, min_reader=2, suite=CRYPTO_SUITE_V2).to_json()


def assert_supported(protocol: dict[str, Any] | None) -> None:
    if not protocol:
        return
    name = protocol.get("name", PROTOCOL_NAME)
    version = int(protocol.get("version", 1))
    min_reader = int(protocol.get("min_reader", 1))
    if name != PROTOCOL_NAME:
        raise VeilError(f"unsupported protocol name: {name}")
    if min_reader > MAX_READER_VERSION or version > MAX_READER_VERSION:
        raise VeilError(f"unsupported protocol version: {version}")


def compatibility_report(protocol: dict[str, Any] | None) -> dict[str, Any]:
    try:
        assert_supported(protocol)
        compatible = True
        reason = "supported"
    except VeilError as exc:
        compatible = False
        reason = str(exc)
    data = protocol or {"name": PROTOCOL_NAME, "version": 1, "min_reader": 1, "suite": "legacy-v1"}
    return {
        "compatible": compatible,
        "reason": reason,
        "reader_min": MIN_READER_VERSION,
        "reader_max": MAX_READER_VERSION,
        "message": data,
    }
