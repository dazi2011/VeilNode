from __future__ import annotations

import json
import secrets
import time
from pathlib import Path

from .crypto import (
    aes_decrypt,
    aes_encrypt,
    b64d,
    b64e,
    canonical_json,
    derive_password_key,
    fingerprint,
    kdf_params,
    sha256,
)
from .errors import VeilDecryptError, VeilError


ROOT_VKP_KIND = "veil-root-vkpseed"
ROOT_VKP_EXPORT_PREFIX = "VEIL-ROOT-VKPSEED-V1:"


def create_root_vkp_seed() -> bytes:
    return secrets.token_bytes(32)


def fingerprint_root_vkp(seed: bytes) -> str:
    return fingerprint(seed)


def seal_root_vkp_seed(seed: bytes, password: str, out_path: str | Path, kdf: dict | None = None) -> dict:
    if len(seed) < 32:
        raise VeilError("root_vkp seed must be at least 32 bytes")
    created_at = int(time.time())
    salt = secrets.token_bytes(16)
    pass_key = derive_password_key(password, salt, kdf_params(kdf))
    fp = fingerprint_root_vkp(seed)
    aad = canonical_json({"kind": ROOT_VKP_KIND, "fingerprint": fp, "version": 1})
    nonce, ciphertext = aes_encrypt(
        pass_key.key,
        canonical_json(
            {
                "seed": b64e(seed),
                "created_at": created_at,
                "fingerprint": fp,
                "version": 1,
            }
        ),
        aad=aad,
    )
    payload = {
        "kind": ROOT_VKP_KIND,
        "version": 1,
        "protocol_version": 2,
        "created_at": created_at,
        "fingerprint": fp,
        "kdf": pass_key.params,
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }
    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    dest.chmod(0o600)
    return inspect_root_vkp_seed(dest)


def open_root_vkp_seed(path: str | Path, password: str) -> bytes:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("kind") != ROOT_VKP_KIND:
            raise ValueError("wrong kind")
        aad = canonical_json({"kind": ROOT_VKP_KIND, "fingerprint": data["fingerprint"], "version": int(data["version"])})
        pass_key = derive_password_key(password, b64d(data["salt"]), data.get("kdf"))
        plaintext = aes_decrypt(pass_key.key, b64d(data["nonce"]), b64d(data["ciphertext"]), aad=aad)
        payload = json.loads(plaintext.decode("utf-8"))
        seed = b64d(payload["seed"])
        if fingerprint_root_vkp(seed) != data.get("fingerprint") or payload.get("fingerprint") != data.get("fingerprint"):
            raise ValueError("fingerprint mismatch")
        return seed
    except Exception as exc:
        raise VeilDecryptError("unable to open message") from exc


def inspect_root_vkp_seed(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("kind") != ROOT_VKP_KIND:
        raise VeilError("not a root keypart seed file")
    return {
        "kind": data.get("kind"),
        "version": data.get("version"),
        "protocol_version": data.get("protocol_version", 2),
        "fingerprint": data.get("fingerprint"),
        "created_at": data.get("created_at"),
        "kdf": data.get("kdf"),
    }


def rotate_root_vkp_seed(in_path: str | Path, out_path: str | Path, password: str, kdf: dict | None = None) -> dict:
    open_root_vkp_seed(in_path, password)
    return seal_root_vkp_seed(create_root_vkp_seed(), password, out_path, kdf)


def export_root_vkp_seed(path: str | Path, password: str, out_path: str | Path) -> dict:
    seed = open_root_vkp_seed(path, password)
    payload = ROOT_VKP_EXPORT_PREFIX + b64e(seed) + "\n"
    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(payload, encoding="utf-8")
    dest.chmod(0o600)
    return {
        "export": str(dest),
        "format": "base64-text",
        "fingerprint": fingerprint_root_vkp(seed),
        "sha256": b64e(sha256(payload.encode("utf-8"))),
    }


def import_root_vkp_seed(in_path: str | Path, out_path: str | Path, password: str, kdf: dict | None = None) -> dict:
    raw = Path(in_path).read_text(encoding="utf-8").strip()
    if raw.startswith(ROOT_VKP_EXPORT_PREFIX):
        raw = raw[len(ROOT_VKP_EXPORT_PREFIX) :]
    try:
        seed = b64d(raw)
    except Exception as exc:
        raise VeilError("invalid root keypart export") from exc
    return seal_root_vkp_seed(seed, password, out_path, kdf)
