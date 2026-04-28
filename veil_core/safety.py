from __future__ import annotations

import os
from pathlib import Path

from .errors import VeilError


def secure_delete(path: str | Path, *, confirm: bool = False, dry_run: bool = False) -> dict:
    target = Path(path)
    if not target.exists():
        raise VeilError(f"path does not exist: {target}")
    if dry_run:
        return {"path": str(target), "would_delete": True, "deleted": False}
    if not confirm:
        raise VeilError("refusing to delete without --yes")
    if target.is_dir():
        raise VeilError("secure-delete currently accepts files only")
    size = target.stat().st_size
    with target.open("r+b") as handle:
        handle.write(os.urandom(size))
        handle.flush()
        os.fsync(handle.fileno())
    target.unlink()
    return {"path": str(target), "bytes_overwritten": size, "deleted": True}
