from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
import random
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


DEFAULT_KDF = {
    "memory_kib": 65536,
    "iterations": 3,
    "lanes": 4,
    "length": 32,
}

FAST_KDF = {
    "memory_kib": 4096,
    "iterations": 1,
    "lanes": 1,
    "length": 32,
}


@dataclass(frozen=True)
class PasswordKey:
    key: bytes
    salt: bytes
    params: dict[str, int]
    device_bound: bool = False


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64d(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + pad).encode("ascii"))


def random_b64(length: int = 16) -> str:
    return b64e(secrets.token_bytes(length))


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_json_bytes(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def sha256(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def fingerprint(raw: bytes, size: int = 16) -> str:
    return b64e(sha256(raw)[:size])


def device_secret() -> bytes:
    material = "|".join(
        [
            platform.node(),
            platform.system(),
            platform.machine(),
            str(uuid.getnode()),
        ]
    )
    return sha256(material.encode("utf-8"))


def kdf_params(params: dict[str, int] | None = None) -> dict[str, int]:
    merged = dict(DEFAULT_KDF)
    if os.environ.get("VEIL_FAST_KDF") == "1":
        merged.update(FAST_KDF)
    if params:
        merged.update({k: int(v) for k, v in params.items() if v is not None})
    return merged


def derive_password_key(
    password: str,
    salt: bytes,
    params: dict[str, int] | None = None,
    *,
    device_bound: bool = False,
) -> PasswordKey:
    cfg = kdf_params(params)
    secret = device_secret() if device_bound else None
    kdf = Argon2id(
        salt=salt,
        length=cfg["length"],
        iterations=cfg["iterations"],
        lanes=cfg["lanes"],
        memory_cost=cfg["memory_kib"],
        secret=secret,
    )
    key = kdf.derive(password.encode("utf-8"))
    return PasswordKey(key=key, salt=salt, params=cfg, device_bound=device_bound)


def hkdf(ikm: bytes, *, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def derive_vkp_i(root_vkp: bytes, msg_id: bytes, file_hash: bytes, receiver_id: bytes) -> bytes:
    return hkdf(root_vkp, salt=msg_id, info=b"veil-vkp-v2" + file_hash + receiver_id)


def derive_message_key_v2(
    vkp_i: bytes,
    password: str,
    message_salt: bytes,
    params: dict[str, int] | None = None,
) -> bytes:
    password_key = derive_password_key(password, message_salt, params)
    return hkdf(vkp_i + password_key.key, salt=message_salt, info=b"veil-message-key-v2")


def aes_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(12)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, *, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def xchacha_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> tuple[bytes, bytes]:
    nonce = secrets.token_bytes(24)
    sub_key, ietf_nonce = _xchacha20_subkey_and_nonce(key, nonce)
    return nonce, ChaCha20Poly1305(sub_key).encrypt(ietf_nonce, plaintext, aad)


def xchacha_decrypt(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, *, aad: bytes = b"") -> bytes:
    if len(ciphertext_and_tag) < 16:
        raise ValueError("ciphertext too short")
    sub_key, ietf_nonce = _xchacha20_subkey_and_nonce(key, nonce)
    return ChaCha20Poly1305(sub_key).decrypt(ietf_nonce, ciphertext_and_tag, aad)


def _xchacha20_subkey_and_nonce(key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    if len(key) != 32:
        raise ValueError("XChaCha20-Poly1305 requires a 32-byte key")
    if len(nonce) != 24:
        raise ValueError("XChaCha20-Poly1305 requires a 24-byte nonce")
    sub_key = _hchacha20(key, nonce[:16])
    return sub_key, b"\x00\x00\x00\x00" + nonce[16:]


def _hchacha20(key: bytes, nonce16: bytes) -> bytes:
    constants = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
    key_words = _le_words(key)
    nonce_words = _le_words(nonce16)
    state = list(constants + tuple(key_words) + tuple(nonce_words))
    for _ in range(10):
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    out = [state[i] for i in (0, 1, 2, 3, 12, 13, 14, 15)]
    return b"".join(word.to_bytes(4, "little") for word in out)


def _le_words(raw: bytes) -> list[int]:
    return [int.from_bytes(raw[i : i + 4], "little") for i in range(0, len(raw), 4)]


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotl32(state[b] ^ state[c], 7)


def subkey(pass_key: bytes, file_key: bytes, label: str, salt: bytes) -> bytes:
    pass_part = hkdf(pass_key, salt=salt, info=("veil/pass/" + label).encode("utf-8"))
    return hkdf(file_key, salt=pass_part, info=("veil/file/" + label).encode("utf-8"))


def deterministic_shuffle(count: int, seed: bytes) -> list[int]:
    order = list(range(count))
    rnd = random.Random(int.from_bytes(seed, "big"))
    rnd.shuffle(order)
    return order


def secure_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
