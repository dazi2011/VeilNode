from __future__ import annotations

import json
import math
import os
import re
import struct
import wave
import zipfile
from collections import Counter
from pathlib import Path

from .container import SUPPORTED_FORMATS, capacity_report, normalize_format, verify_container
from .crypto import b64e, sha256
from .errors import VeilError


def carrier_audit(path: str | Path, *, as_json: bool = False) -> dict:
    target = Path(path)
    fmt = _detect_format(target)
    raw = target.read_bytes()
    warnings: list[str] = []
    notes: list[str] = []
    suspicious = 0
    capacity = 0
    anomaly = 0.0
    try:
        if fmt == "png":
            details = _audit_png(raw, warnings, notes)
            suspicious = details["unknown_chunks"]
            capacity = details["capacity"]
            anomaly += min(0.45, suspicious * 0.04)
        elif fmt == "zip":
            details = _audit_zip(target, warnings, notes)
            suspicious = details["extra_entries"]
            capacity = details["capacity"]
            anomaly += min(0.45, details["comment_size"] / max(1, len(raw)))
        elif fmt == "mp4":
            details = _audit_mp4(raw, warnings, notes)
            suspicious = details["free_boxes"]
            capacity = details["capacity"]
            anomaly += min(0.5, details["free_bytes"] / max(1, len(raw)))
        elif fmt == "pdf":
            details = _audit_pdf(raw, warnings, notes)
            suspicious = details["incremental_updates"]
            capacity = max(0, len(raw) // 4)
            anomaly += min(0.4, max(0, suspicious - 1) * 0.08)
        elif fmt == "wav":
            details = _audit_wav(target, warnings, notes)
            suspicious = details["unknown_chunks"]
            capacity = details["capacity"]
            anomaly += min(0.45, suspicious * 0.06)
        elif fmt in {"bmp", "7z"}:
            declared = _declared_size(fmt, raw)
            tail = max(0, len(raw) - declared)
            capacity = max(0, len(raw) // 8)
            suspicious = 1 if tail else 0
            if tail:
                warnings.append("tail data is present")
            anomaly += min(0.6, tail / max(1, len(raw)))
        elif fmt == "vmsg":
            capacity = len(raw)
        else:
            warnings.append("unknown file format")
            anomaly = 0.7
    except Exception as exc:
        warnings.append(f"audit parser warning: {exc}")
        anomaly = max(anomaly, 0.65)
    payload_ratio = capacity / max(1, len(raw))
    anomaly = min(1.0, anomaly + min(0.35, payload_ratio / 6))
    recommendation = "safe" if anomaly < 0.25 else "risky" if anomaly < 0.6 else "avoid"
    return {
        "format": fmt,
        "size": len(raw),
        "capacity_estimate": int(capacity),
        "payload_ratio": round(payload_ratio, 6),
        "anomaly_score": round(anomaly, 4),
        "suspicious_chunks": suspicious,
        "structural_warnings": warnings,
        "recommendation": recommendation,
        "notes": notes if as_json else notes[:],
    }


def carrier_compare(before: str | Path, after: str | Path, *, as_json: bool = False) -> dict:
    before_path = Path(before)
    after_path = Path(after)
    before_raw = before_path.read_bytes()
    after_raw = after_path.read_bytes()
    fmt = _detect_format(after_path)
    size_delta = len(after_raw) - len(before_raw)
    size_delta_ratio = size_delta / max(1, len(before_raw))
    before_audit = carrier_audit(before_path, as_json=True)
    after_audit = carrier_audit(after_path, as_json=True)
    structure_delta_score = abs(after_audit["anomaly_score"] - before_audit["anomaly_score"])
    metadata_delta_score = min(1.0, abs(len(_visible_ascii(after_raw)) - len(_visible_ascii(before_raw))) / max(1, len(before_raw)))
    entropy_delta_score = abs(_entropy(after_raw) - _entropy(before_raw)) / 8.0
    total = min(1.0, abs(size_delta_ratio) + structure_delta_score + metadata_delta_score + entropy_delta_score)
    overall = "low" if total < 0.25 else "medium" if total < 0.6 else "high"
    return {
        "format": fmt,
        "size_delta": size_delta,
        "size_delta_ratio": round(size_delta_ratio, 6),
        "structure_delta_score": round(structure_delta_score, 4),
        "metadata_delta_score": round(metadata_delta_score, 4),
        "entropy_delta_score": round(entropy_delta_score, 4),
        "overall_risk": overall,
        "notes": ["local engineering risk score; it is not a detectability guarantee"] if as_json else [],
    }


def create_carrier_profile(samples: str | Path, out: str | Path) -> dict:
    sample_dir = Path(samples)
    if not sample_dir.exists():
        raise VeilError("sample directory does not exist")
    audits = []
    for path in sorted(p for p in sample_dir.rglob("*") if p.is_file()):
        try:
            audits.append(carrier_audit(path, as_json=True))
        except Exception:
            continue
    by_format = Counter(item["format"] for item in audits)
    profile = {
        "type": "veil-carrier-mimic-profile",
        "profile_version": 1,
        "sample_count": len(audits),
        "formats": dict(by_format),
        "size_buckets": _buckets([item["size"] for item in audits]),
        "anomaly_score_avg": round(sum(item["anomaly_score"] for item in audits) / max(1, len(audits)), 4),
        "risk_note": "This profile is a local format-statistics guide, not a detectability guarantee.",
        "samples_sha256": b64e(sha256(json.dumps(audits, sort_keys=True).encode("utf-8"))),
    }
    dest = Path(out)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(profile, indent=2), encoding="utf-8")
    return {"profile": str(dest), "summary": inspect_carrier_profile(dest)}


def inspect_carrier_profile(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("type") != "veil-carrier-mimic-profile":
        raise VeilError("not a carrier profile")
    return {
        "type": data.get("type"),
        "profile_version": data.get("profile_version"),
        "sample_count": data.get("sample_count"),
        "formats": data.get("formats", {}),
        "size_buckets": data.get("size_buckets", {}),
        "anomaly_score_avg": data.get("anomaly_score_avg"),
        "risk_note": data.get("risk_note"),
    }


def _detect_format(path: Path) -> str:
    raw = path.read_bytes()[:16]
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if raw.startswith(b"PK\x03\x04") or raw.startswith(b"PK\x05\x06") or raw.startswith(b"PK\x07\x08"):
        return "zip"
    if len(raw) >= 12 and raw[:4] == b"RIFF" and raw[8:12] == b"WAVE":
        return "wav"
    if raw.startswith(b"%PDF-"):
        return "pdf"
    if raw.startswith(b"BM"):
        return "bmp"
    if len(raw) >= 8 and raw[4:8] in {b"ftyp", b"moov", b"mdat", b"free"}:
        return "mp4"
    suffix = path.suffix.lower().lstrip(".")
    return suffix if suffix in SUPPORTED_FORMATS else "unknown"


def _audit_png(raw: bytes, warnings: list[str], notes: list[str]) -> dict:
    pos = 8
    ancillary = 0
    unknown = 0
    max_chunk = 0
    seen_iend = False
    while pos + 12 <= len(raw):
        length = struct.unpack_from(">I", raw, pos)[0]
        kind = raw[pos + 4 : pos + 8]
        max_chunk = max(max_chunk, length)
        pos += 12 + length
        if kind[:1].islower():
            ancillary += 1
            if kind not in {b"tEXt", b"zTXt", b"iTXt", b"pHYs", b"gAMA", b"cHRM", b"sRGB", b"tIME"}:
                unknown += 1
        if kind == b"IEND":
            seen_iend = True
            break
    if seen_iend and pos < len(raw):
        warnings.append("data exists after IEND")
    if max_chunk > len(raw) * 0.8:
        warnings.append("very large PNG chunk")
    notes.append(f"ancillary_chunks={ancillary}")
    return {"unknown_chunks": unknown, "capacity": max(0, len(raw) // 5)}


def _audit_zip(path: Path, warnings: list[str], notes: list[str]) -> dict:
    with zipfile.ZipFile(path, "r") as zf:
        infos = zf.infolist()
        comment_size = len(zf.comment)
        randomish = sum(1 for info in infos if re.search(r"[A-Za-z0-9_-]{14,}", info.filename))
    if comment_size > max(1024, path.stat().st_size // 10):
        warnings.append("large ZIP comment")
    if randomish > max(3, len(infos) // 2):
        warnings.append("many random-looking ZIP entry names")
    notes.append(f"entries={len(infos)}")
    return {"extra_entries": max(0, len(infos) - 1), "comment_size": comment_size, "capacity": max(0, path.stat().st_size * 2)}


def _audit_mp4(raw: bytes, warnings: list[str], notes: list[str]) -> dict:
    pos = 0
    free_boxes = 0
    free_bytes = 0
    boxes = []
    while pos + 8 <= len(raw):
        size = struct.unpack_from(">I", raw, pos)[0]
        kind = raw[pos + 4 : pos + 8]
        header = 8
        if size == 1 and pos + 16 <= len(raw):
            size = struct.unpack_from(">Q", raw, pos + 8)[0]
            header = 16
        if size < header or pos + size > len(raw):
            warnings.append("MP4 box tree stops before EOF")
            break
        boxes.append(kind.decode("latin1", errors="replace"))
        if kind == b"free":
            free_boxes += 1
            free_bytes += size - header
        pos += size
    notes.append(f"boxes={','.join(boxes[:8])}")
    return {"free_boxes": free_boxes, "free_bytes": free_bytes, "capacity": max(free_bytes, len(raw) // 10)}


def _audit_pdf(raw: bytes, warnings: list[str], notes: list[str]) -> dict:
    eof = raw.rfind(b"%%EOF")
    if eof >= 0 and eof + 5 < len(raw.rstrip()):
        warnings.append("data exists after final PDF EOF")
    updates = max(0, raw.count(b"startxref") - 1)
    streams = raw.count(b"stream")
    notes.append(f"streams={streams}")
    return {"incremental_updates": updates, "streams": streams}


def _audit_wav(path: Path, warnings: list[str], notes: list[str]) -> dict:
    raw = path.read_bytes()
    pos = 12
    unknown = 0
    data_seen = False
    while pos + 8 <= len(raw):
        chunk_id = raw[pos : pos + 4]
        size = struct.unpack_from("<I", raw, pos + 4)[0]
        end = pos + 8 + size + (size % 2)
        if end > len(raw):
            warnings.append("WAV chunk exceeds file size")
            break
        if chunk_id == b"data":
            data_seen = True
        elif chunk_id not in {b"fmt ", b"LIST", b"fact", b"bext", b"JUNK"}:
            unknown += 1
        if data_seen and chunk_id not in {b"data", b"LIST", b"JUNK"}:
            notes.append(f"post_data_chunk={chunk_id.decode('latin1', errors='replace')}")
        pos = end
    with wave.open(str(path), "rb") as wav:
        frames = wav.getnframes()
    return {"unknown_chunks": unknown, "capacity": max(0, frames // 2)}


def _declared_size(fmt: str, raw: bytes) -> int:
    if fmt == "bmp" and len(raw) >= 6:
        return struct.unpack_from("<I", raw, 2)[0]
    return len(raw)


def _entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = Counter(raw)
    return -sum((count / len(raw)) * math.log2(count / len(raw)) for count in counts.values())


def _visible_ascii(raw: bytes) -> bytes:
    return bytes(byte for byte in raw if 32 <= byte <= 126)


def _buckets(values: list[int]) -> dict:
    buckets = Counter()
    for value in values:
        if value < 10_000:
            buckets["<10KB"] += 1
        elif value < 1_000_000:
            buckets["10KB-1MB"] += 1
        elif value < 50_000_000:
            buckets["1MB-50MB"] += 1
        else:
            buckets[">50MB"] += 1
    return dict(buckets)
