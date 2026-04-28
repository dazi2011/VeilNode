from __future__ import annotations

import binascii
import io
import math
import os
import random
import re
import shutil
import struct
import subprocess
import tempfile
import wave
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from .crypto import b64e
from .errors import VeilError


SUPPORTED_FORMATS = {"png", "bmp", "wav", "mp4", "zip", "pdf", "7z", "vmsg"}


@dataclass(frozen=True)
class EmbedResult:
    data: bytes
    offset: int
    length: int
    mode: str
    container_format: str
    extra: dict


def normalize_format(value: str | None, path: str | Path | None = None) -> str:
    fmt = (value or "").lower().lstrip(".")
    if not fmt and path:
        suffix = Path(path).suffix.lower().lstrip(".")
        fmt = "zip" if suffix == "zip" else suffix
    if fmt == "jpg":
        fmt = "jpeg"
    if fmt not in SUPPORTED_FORMATS:
        raise VeilError(f"unsupported container format: {fmt or '<unknown>'}")
    return fmt


def carrier_bytes(fmt: str, carrier: str | Path | None = None) -> bytes:
    if carrier:
        return Path(carrier).read_bytes()
    return generate_carrier(fmt)


def embed_payload(carrier: bytes, payload: bytes, fmt: str) -> EmbedResult:
    fmt = normalize_format(fmt)
    if fmt == "png":
        return _embed_png(carrier, payload)
    if fmt == "wav":
        return _embed_wav(carrier, payload)
    if fmt == "mp4":
        return _embed_mp4(carrier, payload)
    if fmt == "zip":
        return _embed_zip(carrier, payload)
    if fmt == "pdf":
        return _embed_pdf(carrier, payload)
    return _append_blob(carrier, payload, fmt)


def extract_payload(path: str | Path, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0:
        raise VeilError("invalid payload locator")
    with Path(path).open("rb") as handle:
        handle.seek(offset)
        raw = handle.read(length)
    if len(raw) != length:
        raise VeilError("payload locator outside carrier")
    return raw


def verify_container(path: str | Path, fmt: str | None = None) -> dict:
    target = Path(path)
    real_fmt = normalize_format(fmt, target)
    checks: list[dict] = []
    try:
        if real_fmt == "png":
            _verify_png(target.read_bytes())
            checks.append({"name": "png-structure", "ok": True})
        elif real_fmt == "bmp":
            _verify_bmp(target.read_bytes())
            checks.append({"name": "bmp-structure", "ok": True})
        elif real_fmt == "wav":
            with wave.open(str(target), "rb") as wav_file:
                frames = wav_file.getnframes()
            checks.append({"name": "wav-readable", "ok": frames > 0, "frames": frames})
        elif real_fmt == "zip":
            with zipfile.ZipFile(target, "r") as zf:
                bad = zf.testzip()
                names = zf.namelist()
            checks.append({"name": "zip-testzip", "ok": bad is None, "entries": len(names)})
        elif real_fmt == "pdf":
            raw = target.read_bytes()
            ok = raw.startswith(b"%PDF-") and b"%%EOF" in raw[-2048:]
            checks.append({"name": "pdf-basic-structure", "ok": ok})
        elif real_fmt == "mp4":
            checks.append(_external_probe("ffprobe", ["ffprobe", "-v", "error", str(target)], "mp4-ffprobe"))
        elif real_fmt == "7z":
            checks.append(_external_probe("7z", ["7z", "t", str(target)], "7z-test"))
        elif real_fmt == "vmsg":
            checks.append({"name": "vmsg-readable", "ok": target.stat().st_size > 0})
        else:
            checks.append({"name": "known-format", "ok": False, "reason": "unsupported"})
    except Exception as exc:
        checks.append({"name": f"{real_fmt}-verify", "ok": False, "reason": str(exc)})
    return {"path": str(target), "format": real_fmt, "ok": all(item.get("ok") for item in checks), "checks": checks}


def capacity_report(path: str | Path | None, fmt: str | None, *, payload_size: int | None = None) -> dict:
    real_fmt = normalize_format(fmt, path)
    base_size = Path(path).stat().st_size if path and Path(path).exists() else len(generate_carrier(real_fmt))
    strategy = {
        "png": "ancillary chunk",
        "bmp": "tail append",
        "wav": "unknown RIFF chunk",
        "mp4": "free box",
        "zip": "stored member",
        "pdf": "incremental stream object",
        "7z": "tail append",
        "vmsg": "opaque internal envelope",
    }[real_fmt]
    practical_limit = (4 * 1024**3) - 16 if real_fmt in {"png", "wav", "mp4", "zip", "pdf", "vmsg"} else None
    accepted = True if practical_limit is None or payload_size is None else payload_size <= practical_limit
    return {
        "format": real_fmt,
        "carrier_size": base_size,
        "strategy": strategy,
        "payload_size": payload_size,
        "practical_limit": practical_limit,
        "accepted_by_strategy": accepted,
        "note": "capacity is bounded mostly by filesystem/parser tolerance for append/member strategies",
    }


def generate_carrier(fmt: str) -> bytes:
    fmt = normalize_format(fmt)
    if fmt == "png":
        return _generate_image("PNG")
    if fmt == "bmp":
        return _generate_image("BMP")
    if fmt == "wav":
        return _generate_wav()
    if fmt == "zip":
        return _generate_zip()
    if fmt == "pdf":
        return _generate_pdf()
    if fmt == "mp4":
        return _generate_mp4()
    if fmt == "7z":
        return _generate_7z()
    if fmt == "vmsg":
        return os.urandom(128)
    raise VeilError(f"cannot generate carrier: {fmt}")


def _embed_png(carrier: bytes, payload: bytes) -> EmbedResult:
    marker = b"IEND"
    pos = carrier.rfind(marker)
    if pos < 4:
        raise VeilError("invalid PNG carrier")
    chunk_start = pos - 4
    chunk_type = _png_chunk_type()
    chunk = struct.pack(">I", len(payload)) + chunk_type + payload
    crc = binascii.crc32(chunk_type + payload) & 0xFFFFFFFF
    chunk += struct.pack(">I", crc)
    data = carrier[:chunk_start] + chunk + carrier[chunk_start:]
    return EmbedResult(data, chunk_start + 8, len(payload), "png-ancillary-chunk", "png", {"chunk_type": chunk_type.decode("ascii")})


def _embed_wav(carrier: bytes, payload: bytes) -> EmbedResult:
    if len(carrier) < 12 or carrier[:4] != b"RIFF" or carrier[8:12] != b"WAVE":
        raise VeilError("invalid WAV carrier")
    chunk_id = _ascii_tag()
    chunk = chunk_id + struct.pack("<I", len(payload)) + payload
    if len(payload) % 2:
        chunk += b"\x00"
    data = bytearray(carrier + chunk)
    struct.pack_into("<I", data, 4, len(data) - 8)
    return EmbedResult(bytes(data), len(carrier) + 8, len(payload), "wav-unknown-chunk", "wav", {"chunk_id": chunk_id.decode("ascii")})


def _embed_mp4(carrier: bytes, payload: bytes) -> EmbedResult:
    if len(payload) + 8 <= 0xFFFFFFFF:
        box = struct.pack(">I4s", len(payload) + 8, b"free") + payload
        offset = len(carrier) + 8
    else:
        box = struct.pack(">I4sQ", 1, b"free", len(payload) + 16) + payload
        offset = len(carrier) + 16
    return EmbedResult(carrier + box, offset, len(payload), "mp4-free-box", "mp4", {"box": "free"})


def _embed_zip(carrier: bytes, payload: bytes) -> EmbedResult:
    name = f"assets/{b64e(os.urandom(9))}.bin"
    buf = io.BytesIO(carrier)
    try:
        with zipfile.ZipFile(buf, "a", compression=zipfile.ZIP_STORED) as zf:
            zf.writestr(name, payload)
    except zipfile.BadZipFile as exc:
        raise VeilError("invalid ZIP carrier") from exc
    data = buf.getvalue()
    with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
        info = zf.getinfo(name)
        header_offset = info.header_offset
    name_len, extra_len = struct.unpack_from("<HH", data, header_offset + 26)
    offset = header_offset + 30 + name_len + extra_len
    return EmbedResult(data, offset, len(payload), "zip-stored-member", "zip", {"member": name})


def _embed_pdf(carrier: bytes, payload: bytes) -> EmbedResult:
    if not carrier.startswith(b"%PDF-"):
        raise VeilError("invalid PDF carrier")
    root = _pdf_root(carrier)
    prev = _pdf_startxref(carrier)
    obj_num = _pdf_next_object_number(carrier)
    prefix = f"\n{obj_num} 0 obj\n<< /Length {len(payload)} >>\nstream\n".encode("ascii")
    obj_offset = len(carrier)
    data_offset = obj_offset + len(prefix)
    suffix = b"\nendstream\nendobj\n"
    xref_offset = data_offset + len(payload) + len(suffix)
    trailer = (
        f"xref\n{obj_num} 1\n{obj_offset:010d} 00000 n \n"
        f"trailer\n<< /Size {obj_num + 1} /Root {root} /Prev {prev} >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
    data = carrier + prefix + payload + suffix + trailer
    return EmbedResult(data, data_offset, len(payload), "pdf-incremental-stream", "pdf", {"object": obj_num})


def _append_blob(carrier: bytes, payload: bytes, fmt: str) -> EmbedResult:
    return EmbedResult(carrier + payload, len(carrier), len(payload), f"{fmt}-tail-append", fmt, {})


def _verify_png(raw: bytes) -> None:
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise VeilError("invalid PNG signature")
    pos = 8
    seen_iend = False
    while pos + 12 <= len(raw):
        length = struct.unpack_from(">I", raw, pos)[0]
        kind = raw[pos + 4 : pos + 8]
        data_start = pos + 8
        data_end = data_start + length
        crc_end = data_end + 4
        if crc_end > len(raw):
            raise VeilError("truncated PNG chunk")
        expected = struct.unpack_from(">I", raw, data_end)[0]
        actual = binascii.crc32(kind + raw[data_start:data_end]) & 0xFFFFFFFF
        if expected != actual:
            raise VeilError("PNG chunk CRC mismatch")
        pos = crc_end
        if kind == b"IEND":
            seen_iend = True
            break
    if not seen_iend:
        raise VeilError("PNG missing IEND")


def _verify_bmp(raw: bytes) -> None:
    if len(raw) < 54 or not raw.startswith(b"BM"):
        raise VeilError("invalid BMP header")
    declared = struct.unpack_from("<I", raw, 2)[0]
    if declared > len(raw):
        raise VeilError("BMP declared size exceeds file")


def _external_probe(tool: str, cmd: list[str], name: str) -> dict:
    if not shutil.which(tool):
        return {"name": name, "ok": True, "skipped": True, "reason": f"{tool} unavailable"}
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return {"name": name, "ok": proc.returncode == 0, "returncode": proc.returncode}


def _generate_image(fmt: str) -> bytes:
    width, height = 640, 360
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            r = int(80 + 90 * x / width)
            g = int(110 + 80 * y / height)
            b = int(150 + 45 * math.sin((x + y) / 48))
            noise = random.randrange(0, 10)
            pixels += bytes((min(255, r + noise), min(255, g + noise), min(255, b + noise)))
    if fmt == "PNG":
        return _generate_png(width, height, bytes(pixels))
    if fmt == "BMP":
        return _generate_bmp(width, height, bytes(pixels))
    raise VeilError(f"unsupported generated image format: {fmt}")


def _generate_png(width: int, height: int, rgb: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        crc = binascii.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    rows = bytearray()
    stride = width * 3
    for y in range(height):
        rows.append(0)
        rows += rgb[y * stride : (y + 1) * stride]
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(rows))) + chunk(b"IEND", b"")


def _generate_bmp(width: int, height: int, rgb: bytes) -> bytes:
    row_size = ((width * 3 + 3) // 4) * 4
    pixel_bytes = bytearray()
    stride = width * 3
    for y in range(height - 1, -1, -1):
        row = rgb[y * stride : (y + 1) * stride]
        bgr = bytearray()
        for x in range(0, len(row), 3):
            bgr += bytes((row[x + 2], row[x + 1], row[x]))
        bgr += b"\x00" * (row_size - len(bgr))
        pixel_bytes += bgr
    file_size = 14 + 40 + len(pixel_bytes)
    header = b"BM" + struct.pack("<IHHI", file_size, 0, 0, 54)
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixel_bytes), 2835, 2835, 0, 0)
    return header + dib + bytes(pixel_bytes)


def _generate_wav() -> bytes:
    out = io.BytesIO()
    rate = 44100
    duration = 1.0
    freq = 440.0
    frames = bytearray()
    for n in range(int(rate * duration)):
        sample = int(9000 * math.sin(2 * math.pi * freq * n / rate))
        frames += struct.pack("<h", sample)
    with wave.open(out, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(bytes(frames))
    return out.getvalue()


def _generate_zip() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", "This archive opens normally.\n")
    return out.getvalue()


def _generate_pdf() -> bytes:
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length 44 >>\nstream\nBT /F1 18 Tf 36 72 Td (Veil carrier) Tj ET\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{idx} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"
    xref_offset = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode("ascii")
    out += b"0000000000 65535 f \n"
    for offset in offsets[1:]:
        out += f"{offset:010d} 00000 n \n".encode("ascii")
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n"
    ).encode("ascii")
    return bytes(out)


def _generate_mp4() -> bytes:
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        # Parseable MP4 shell, not a real playable stream. Kept as fallback only.
        return struct.pack(">I4s4sIIII", 24, b"ftyp", b"isom", 0, 0x69736F6D, 0x6D703432, 8) + b"free"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "carrier.mp4"
        cmd = [
            ffmpeg,
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=black:s=320x240:d=1",
            "-pix_fmt",
            "yuv420p",
            "-movflags",
            "+faststart",
            str(out),
        ]
        subprocess.run(cmd, check=True)
        return out.read_bytes()


def _generate_7z() -> bytes:
    seven = shutil.which("7z")
    if not seven:
        raise VeilError("7z carrier generation requires the 7z command")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        seed = root / "README.txt"
        seed.write_text("This archive opens normally.\n", encoding="utf-8")
        out = root / "carrier.7z"
        subprocess.run([seven, "a", "-t7z", str(out), str(seed), "-mx=0"], check=True, stdout=subprocess.DEVNULL)
        return out.read_bytes()


def _ascii_tag() -> bytes:
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return bytes(random.choice(alphabet) for _ in range(4))


def _png_chunk_type() -> bytes:
    # Ancillary, private, reserved-valid, safe-to-copy: lowercase/lowercase/uppercase/lowercase.
    letters = b"abcdefghijklmnopqrstuvwxyz"
    uppers = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return bytes(
        [
            random.choice(letters),
            random.choice(letters),
            random.choice(uppers),
            random.choice(letters),
        ]
    )


def _pdf_root(raw: bytes) -> str:
    matches = re.findall(rb"/Root\s+(\d+\s+\d+\s+R)", raw)
    if not matches:
        raise VeilError("PDF root not found")
    return matches[-1].decode("ascii")


def _pdf_startxref(raw: bytes) -> int:
    matches = re.findall(rb"startxref\s+(\d+)", raw)
    if not matches:
        raise VeilError("PDF startxref not found")
    return int(matches[-1])


def _pdf_next_object_number(raw: bytes) -> int:
    nums = [int(m) for m in re.findall(rb"(?m)^(\d+)\s+\d+\s+obj\b", raw)]
    return max(nums, default=0) + 1
