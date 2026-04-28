from __future__ import annotations

import os
import stat
from pathlib import Path


def file_permission_report(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        return {"path": str(p), "exists": False, "ok": False, "issue": "missing"}
    mode = stat.S_IMODE(p.stat().st_mode)
    group_world = mode & (stat.S_IRWXG | stat.S_IRWXO)
    return {
        "path": str(p),
        "exists": True,
        "mode": oct(mode),
        "ok": group_world == 0,
        "issue": None if group_world == 0 else "group/world permissions present",
    }


def home_permission_report(home: str | Path) -> dict:
    root = Path(home)
    paths = [
        root / "identity.private.json",
        root / "identity.public.json",
    ]
    return {
        "home": str(root),
        "exists": root.exists(),
        "private_files": [file_permission_report(path) for path in paths if path.exists()],
    }


def can_write_dir(path: str | Path) -> bool:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return os.access(target, os.W_OK)
