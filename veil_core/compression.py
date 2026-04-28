from __future__ import annotations

from pathlib import Path

from .archive import pack_path, unpack_archive


def pack_input(path: str | Path) -> tuple[bytes, dict]:
    return pack_path(path)


def unpack_payload(raw: bytes, out_dir: str | Path) -> list[Path]:
    return unpack_archive(raw, out_dir)
