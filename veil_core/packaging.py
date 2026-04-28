from __future__ import annotations

import shutil
import tempfile
import zipapp
from pathlib import Path


def build_zipapp(out: str | Path) -> dict:
    root = Path(__file__).resolve().parents[1]
    target = Path(out).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / "veilnode-app"
        shutil.copytree(root / "veil_core", staging / "veil_core")
        zipapp.create_archive(
            staging,
            target=target,
            interpreter="/usr/bin/env python3",
            main="veil_core.bootstrap:bootstrap_then_main",
        )
    return {"package": str(target), "type": "zipapp", "run": f"python3 {target}"}
