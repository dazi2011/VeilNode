from __future__ import annotations

from .crypto import deterministic_shuffle
from .errors import VeilDecryptError


def split_chunks(raw: bytes, chunk_size: int) -> list[bytes]:
    size = max(1, int(chunk_size))
    return [raw[i : i + size] for i in range(0, len(raw), size)] or [b""]


def shuffle_chunks(chunks: list[bytes], seed: bytes) -> tuple[list[int], bytes]:
    order = deterministic_shuffle(len(chunks), seed)
    return order, b"".join(chunks[i] for i in order)


def reassemble_chunks(chunk_payload: bytes, lengths: list[int], order: list[int]) -> bytes:
    if len(lengths) != len(order):
        raise VeilDecryptError("unable to open message")
    chunks = [b""] * len(lengths)
    pos = 0
    for original_index in order:
        length = lengths[original_index]
        chunks[original_index] = chunk_payload[pos : pos + length]
        pos += length
    if pos > len(chunk_payload):
        raise VeilDecryptError("unable to open message")
    return b"".join(chunks)
