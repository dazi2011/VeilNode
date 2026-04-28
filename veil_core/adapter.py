from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .container import (
    EmbedResult,
    capacity_report,
    carrier_bytes,
    embed_payload,
    normalize_format,
    verify_container,
)


@dataclass(frozen=True)
class ContainerAdapter:
    format: str

    @classmethod
    def for_path(cls, path: str | Path | None = None, fmt: str | None = None) -> "ContainerAdapter":
        return cls(normalize_format(fmt, path))

    def carrier(self, path: str | Path | None = None) -> bytes:
        return carrier_bytes(self.format, path)

    def embed(self, carrier: bytes, payload: bytes) -> EmbedResult:
        return embed_payload(carrier, payload, self.format)

    def verify(self, path: str | Path) -> dict:
        return verify_container(path, self.format)

    def capacity(self, path: str | Path | None = None, payload_size: int | None = None) -> dict:
        return capacity_report(path, self.format, payload_size=payload_size)
