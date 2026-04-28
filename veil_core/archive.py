from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

from .errors import VeilError


def pack_path(path: str | Path) -> tuple[bytes, dict]:
    source = Path(path)
    if not source.exists():
        raise VeilError(f"input does not exist: {source}")
    source = source.resolve()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT) as tar:
        tar.add(source, arcname=source.name, recursive=True)
    raw = buf.getvalue()
    meta = {
        "root_name": source.name,
        "input_type": "directory" if source.is_dir() else "file",
        "archive": "tar.gz",
        "archive_size": len(raw),
        "source_size": _path_size(source),
    }
    return raw, meta


def unpack_archive(raw: bytes, out_dir: str | Path) -> list[Path]:
    target_root = Path(out_dir).resolve()
    target_root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            if member.issym() or member.islnk():
                raise VeilError("archive contains unsupported link entries")
            destination = (target_root / member.name).resolve()
            if not _is_relative_to(destination, target_root):
                raise VeilError("archive path traversal blocked")
        tar.extractall(target_root)
        for member in members:
            written.append((target_root / member.name).resolve())
    return written


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _path_size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                pass
    return total
