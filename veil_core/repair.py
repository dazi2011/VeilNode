from __future__ import annotations

import json
from pathlib import Path

from .errors import VeilError
from .protocol import compatibility_report, current_protocol


def repair_keypart(path: str | Path, out: str | Path | None = None) -> dict:
    src = Path(path)
    data = json.loads(src.read_text(encoding="utf-8"))
    changes = []
    if "kind" not in data:
        data["kind"] = "veil-keypart"
        changes.append("added kind")
    if "protocol" not in data:
        data["protocol"] = current_protocol()
        changes.append("added protocol")
    records = data.get("records")
    if not isinstance(records, list):
        raise VeilError("keypart has no records array")
    if data.get("record_count") != len(records):
        data["record_count"] = len(records)
        changes.append("fixed record_count")
    report = {
        "source": str(src),
        "compatible": compatibility_report(data.get("protocol")),
        "changes": changes,
        "would_write": out is not None,
    }
    if out:
        dest = Path(out)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(data, indent=2), encoding="utf-8")
        report["output"] = str(dest)
    return report


def migrate_keypart(path: str | Path, out: str | Path) -> dict:
    report = repair_keypart(path, out)
    report["migration"] = {"from": "legacy-or-v1", "to": current_protocol()}
    return report


def recovery_scan(directory: str | Path) -> dict:
    root = Path(directory)
    staging = sorted(str(path) for path in root.glob(".veil-recover-*") if path.is_dir())
    return {
        "directory": str(root),
        "staging_outputs": staging,
        "hint": "staging directories mean recovery output completed before final commit or cleanup",
    }
