from __future__ import annotations

import math
import os
import re
import struct
import wave
import zipfile
import zlib
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from veil_core.container import SUPPORTED_FORMATS, capacity_report, normalize_format
from veil_core.crypto import sha256


@dataclass(frozen=True)
class CarrierFeatures:
    format: str
    carrier_size: int
    payload_size: int
    payload_ratio: float
    carrier_entropy: float
    capacity_estimate: int
    structure_stats: dict[str, Any]
    metadata_size: int
    existing_padding_estimate: int
    timestamp_stats: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PayloadFeatures:
    payload_size: int
    payload_entropy: float
    file_ext: str
    file_hash_prefix: str
    compressed_estimate: int

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


def extract_features(carrier_path: str | Path, payload_path: str | Path) -> dict[str, dict[str, Any]]:
    carrier = carrier_features(carrier_path, payload_size=Path(payload_path).stat().st_size)
    payload = payload_features(payload_path)
    return {"carrier_features": carrier.to_json(), "payload_features": payload.to_json()}


def carrier_features(carrier_path: str | Path, *, payload_size: int = 0) -> CarrierFeatures:
    path = Path(carrier_path)
    raw = path.read_bytes()
    fmt = detect_format(path, raw)
    size = len(raw)
    try:
        capacity = int(capacity_report(path, fmt, payload_size=payload_size).get("practical_limit") or 0)
    except Exception:
        capacity = 0
    if capacity <= 0:
        capacity = _fallback_capacity(fmt, size)
    structure = _structure_stats(path, raw, fmt)
    metadata_size = int(structure.get("metadata_size", 0))
    padding_estimate = int(structure.get("existing_padding_estimate", 0))
    timestamp_stats = _timestamp_stats(path, structure)
    return CarrierFeatures(
        format=fmt,
        carrier_size=size,
        payload_size=int(payload_size),
        payload_ratio=round(payload_size / max(1, size), 6),
        carrier_entropy=round(_entropy(raw), 6),
        capacity_estimate=max(0, capacity),
        structure_stats=structure,
        metadata_size=metadata_size,
        existing_padding_estimate=padding_estimate,
        timestamp_stats=timestamp_stats,
    )


def payload_features(payload_path: str | Path) -> PayloadFeatures:
    path = Path(payload_path)
    raw = path.read_bytes()
    compressed = len(zlib.compress(raw)) if raw else 0
    return PayloadFeatures(
        payload_size=len(raw),
        payload_entropy=round(_entropy(raw), 6),
        file_ext=path.suffix.lower().lstrip("."),
        file_hash_prefix=sha256(raw).hex()[:16],
        compressed_estimate=compressed,
    )


def detect_format(path: Path, raw: bytes | None = None) -> str:
    raw = path.read_bytes()[:16] if raw is None else raw[:16]
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
    return suffix if suffix in SUPPORTED_FORMATS else normalize_format(None, path)


def _structure_stats(path: Path, raw: bytes, fmt: str) -> dict[str, Any]:
    if fmt == "zip":
        return _zip_stats(path, raw)
    if fmt == "png":
        return _png_stats(raw)
    if fmt == "mp4":
        return _mp4_stats(raw)
    if fmt == "pdf":
        return _pdf_stats(raw)
    if fmt == "wav":
        return _wav_stats(path, raw)
    if fmt in {"bmp", "7z"}:
        return _tail_stats(fmt, raw)
    return {
        "file_size": len(raw),
        "metadata_size": 0,
        "existing_padding_estimate": 0,
        "structural_warnings": [],
    }


def _zip_stats(path: Path, raw: bytes) -> dict[str, Any]:
    warnings: list[str] = []
    try:
        with zipfile.ZipFile(path, "r") as zf:
            infos = zf.infolist()
            comment_size = len(zf.comment)
            extra_total = sum(len(info.extra or b"") for info in infos)
            methods = Counter(str(info.compress_type) for info in infos)
            timestamps = [info.date_time[:3] for info in infos]
            names = [info.filename for info in infos]
    except zipfile.BadZipFile:
        infos = []
        comment_size = 0
        extra_total = 0
        methods = Counter()
        timestamps = []
        names = []
        warnings.append("zip parser failed")
    eocd = raw.rfind(b"PK\x05\x06")
    central_directory_size = 0
    if eocd >= 0 and eocd + 22 <= len(raw):
        central_directory_size = struct.unpack_from("<I", raw, eocd + 12)[0]
    randomish = sum(1 for name in names if re.search(r"[A-Za-z0-9_-]{14,}", name))
    extensions = Counter(Path(name).suffix.lower().lstrip(".") or "<none>" for name in names)
    return {
        "entry_count": len(infos),
        "comment_size": comment_size,
        "central_directory_size": central_directory_size,
        "extra_field_total_size": extra_total,
        "timestamp_distribution": _counter_from_values(timestamps),
        "filename_pattern_stats": {
            "randomish_count": randomish,
            "extension_distribution": dict(extensions),
            "avg_name_length": round(sum(len(name) for name in names) / max(1, len(names)), 3),
        },
        "compression_method_distribution": dict(methods),
        "metadata_size": comment_size + central_directory_size + extra_total,
        "existing_padding_estimate": comment_size + extra_total,
        "structural_warnings": warnings,
    }


def _png_stats(raw: bytes) -> dict[str, Any]:
    pos = 8
    chunks = []
    ancillary = 0
    unknown = 0
    idat_total = 0
    iend_offset = -1
    standard = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tEXt", b"zTXt", b"iTXt", b"pHYs", b"gAMA", b"cHRM", b"sRGB", b"tIME", b"bKGD", b"tRNS"}
    warnings: list[str] = []
    while pos + 12 <= len(raw):
        length = struct.unpack_from(">I", raw, pos)[0]
        kind = raw[pos + 4 : pos + 8]
        data_end = pos + 8 + length
        crc_end = data_end + 4
        if crc_end > len(raw):
            warnings.append("truncated PNG chunk")
            break
        chunks.append(kind.decode("latin1", errors="replace"))
        if kind[:1].islower():
            ancillary += 1
        if kind not in standard:
            unknown += 1
        if kind == b"IDAT":
            idat_total += length
        pos = crc_end
        if kind == b"IEND":
            iend_offset = crc_end
            break
    trailing = max(0, len(raw) - iend_offset) if iend_offset >= 0 else 0
    if trailing:
        warnings.append("trailing bytes after IEND")
    return {
        "chunk_count": len(chunks),
        "ancillary_chunk_count": ancillary,
        "unknown_chunk_count": unknown,
        "idat_total_size": idat_total,
        "iend_offset": iend_offset,
        "trailing_bytes_after_iend": trailing,
        "metadata_size": max(0, len(raw) - idat_total),
        "existing_padding_estimate": trailing,
        "structural_warnings": warnings,
    }


def _mp4_stats(raw: bytes) -> dict[str, Any]:
    pos = 0
    boxes = []
    sizes = []
    free_count = 0
    free_total = 0
    moov = -1
    mdat = -1
    warnings: list[str] = []
    while pos + 8 <= len(raw):
        box_pos = pos
        size = struct.unpack_from(">I", raw, pos)[0]
        kind = raw[pos + 4 : pos + 8]
        header = 8
        if size == 1 and pos + 16 <= len(raw):
            size = struct.unpack_from(">Q", raw, pos + 8)[0]
            header = 16
        if size < header or pos + size > len(raw):
            warnings.append("MP4 box tree stops before EOF")
            break
        name = kind.decode("latin1", errors="replace")
        boxes.append(name)
        sizes.append(size)
        if kind == b"free":
            free_count += 1
            free_total += size - header
        if kind == b"moov" and moov < 0:
            moov = box_pos
        if kind == b"mdat" and mdat < 0:
            mdat = box_pos
        pos += size
    return {
        "box_count": len(boxes),
        "free_box_count": free_count,
        "free_box_total_size": free_total,
        "moov_position": moov,
        "mdat_position": mdat,
        "box_size_distribution": _buckets(sizes),
        "metadata_size": sum(s for n, s in zip(boxes, sizes) if n != "mdat"),
        "existing_padding_estimate": free_total,
        "structural_warnings": warnings,
    }


def _pdf_stats(raw: bytes) -> dict[str, Any]:
    object_count = len(re.findall(rb"\n\d+\s+\d+\s+obj\b", raw))
    xref_count = raw.count(b"xref")
    trailer_count = raw.count(b"trailer")
    eof_count = raw.count(b"%%EOF")
    stream_count = raw.count(b"stream")
    return {
        "object_count": object_count,
        "xref_count": xref_count,
        "trailer_count": trailer_count,
        "incremental_update_count": max(0, raw.count(b"startxref") - 1),
        "eof_count": eof_count,
        "stream_count": stream_count,
        "metadata_size": min(len(raw), max(0, object_count * 64 + xref_count * 128 + trailer_count * 64)),
        "existing_padding_estimate": max(0, len(raw) - (raw.rfind(b"%%EOF") + 5)) if b"%%EOF" in raw else 0,
        "structural_warnings": [] if eof_count else ["missing PDF EOF marker"],
    }


def _wav_stats(path: Path, raw: bytes) -> dict[str, Any]:
    pos = 12
    riff_count = 0
    unknown = 0
    data_size = 0
    warnings: list[str] = []
    while pos + 8 <= len(raw):
        riff_count += 1
        chunk_id = raw[pos : pos + 4]
        size = struct.unpack_from("<I", raw, pos + 4)[0]
        end = pos + 8 + size + (size % 2)
        if end > len(raw):
            warnings.append("WAV chunk exceeds file size")
            break
        if chunk_id == b"data":
            data_size += size
        elif chunk_id not in {b"fmt ", b"LIST", b"fact", b"bext", b"JUNK"}:
            unknown += 1
        pos = end
    try:
        with wave.open(str(path), "rb") as wav:
            wav.getnframes()
    except Exception as exc:
        warnings.append(f"wave parser warning: {exc}")
    if pos % 2:
        warnings.append("chunk alignment warning")
    return {
        "riff_chunk_count": riff_count,
        "unknown_chunk_count": unknown,
        "data_chunk_size": data_size,
        "alignment_warnings": [w for w in warnings if "align" in w.lower()],
        "metadata_size": max(0, len(raw) - data_size),
        "existing_padding_estimate": max(0, len(raw) - pos),
        "structural_warnings": warnings,
    }


def _tail_stats(fmt: str, raw: bytes) -> dict[str, Any]:
    declared = len(raw)
    warnings: list[str] = []
    if fmt == "bmp" and len(raw) >= 6:
        declared = struct.unpack_from("<I", raw, 2)[0]
        if declared > len(raw):
            warnings.append("declared BMP size exceeds file size")
    tail = max(0, len(raw) - declared)
    return {
        "file_size": len(raw),
        "detected_tail_extra_size": tail,
        "tail_ratio": round(tail / max(1, len(raw)), 6),
        "metadata_size": min(len(raw), 128),
        "existing_padding_estimate": tail,
        "structural_warnings": warnings,
    }


def _timestamp_stats(path: Path, structure: dict[str, Any]) -> dict[str, Any]:
    stat = path.stat()
    out = {
        "mtime": int(stat.st_mtime),
        "ctime": int(getattr(stat, "st_ctime", stat.st_mtime)),
        "size": stat.st_size,
    }
    if "timestamp_distribution" in structure:
        out["embedded_distribution"] = structure["timestamp_distribution"]
    return out


def _fallback_capacity(fmt: str, size: int) -> int:
    if fmt == "zip":
        return max(65535, size * 2)
    if fmt in {"png", "mp4", "pdf", "wav", "vmsg"}:
        return max(0, size // 4)
    return max(0, size // 8)


def _entropy(raw: bytes) -> float:
    if not raw:
        return 0.0
    counts = Counter(raw)
    return -sum((count / len(raw)) * math.log2(count / len(raw)) for count in counts.values())


def _counter_from_values(values: list[Any]) -> dict[str, int]:
    return {str(key): count for key, count in Counter(values).items()}


def _buckets(values: list[int]) -> dict[str, int]:
    buckets = {"0-1k": 0, "1k-64k": 0, "64k-1m": 0, "1m+": 0}
    for value in values:
        if value < 1024:
            buckets["0-1k"] += 1
        elif value < 65536:
            buckets["1k-64k"] += 1
        elif value < 1024 * 1024:
            buckets["64k-1m"] += 1
        else:
            buckets["1m+"] += 1
    return buckets
