from __future__ import annotations

import hmac
import json
import secrets
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from .crypto import (
    aes_decrypt,
    aes_encrypt,
    b64d,
    b64e,
    canonical_json,
    derive_password_key,
    fingerprint,
    hkdf,
    kdf_params,
    random_b64,
    sha256,
)
from .errors import VeilDecryptError, VeilError


ROOT_VKP_KIND = "veil-root-vkpseed"
ROOT_VKP_EXPORT_PREFIX = "VEIL-ROOT-VKPSEED-V1:"
ROOT_FILE_VERSION = 2
ROOT_STATUS_ACTIVE = "active"
ROOT_STATUS_RETIRED = "retired"
ROOT_STATUS_REVOKED = "revoked"
ROOT_STATUSES = {ROOT_STATUS_ACTIVE, ROOT_STATUS_RETIRED, ROOT_STATUS_REVOKED}
ROOT_ROTATE_INFO = b"veil-root-rotate-core-v2.2"
PROTOCOL_FAMILY = "veil-offline-envelope"
CRYPTO_CORE_VERSION = "2.2"


@dataclass(frozen=True)
class RootVkpSecret:
    seed: bytes
    metadata: dict
    path: str | None = None

    @property
    def fingerprint(self) -> str:
        return str(self.metadata.get("fingerprint") or fingerprint_root_vkp(self.seed))

    @property
    def root_epoch(self) -> int:
        return int(self.metadata.get("root_epoch", 0))

    @property
    def status(self) -> str:
        return str(self.metadata.get("status") or ROOT_STATUS_ACTIVE)

    @property
    def root_id(self) -> str:
        return str(self.metadata.get("root_id") or "")


def create_root_vkp_seed() -> bytes:
    return secrets.token_bytes(32)


def fingerprint_root_vkp(seed: bytes) -> str:
    return fingerprint(seed)


def seal_root_vkp_seed(
    seed: bytes,
    password: str,
    out_path: str | Path,
    kdf: dict | None = None,
    *,
    label: str | None = None,
    metadata: dict | None = None,
) -> dict:
    if len(seed) < 32:
        raise VeilError("root_vkp seed must be at least 32 bytes")
    now = int(time.time())
    base = dict(metadata or {})
    fp = fingerprint_root_vkp(seed)
    root_epoch = int(base.get("root_epoch", 0))
    root_id = str(base.get("root_id") or random_b64(16))
    status = str(base.get("status") or ROOT_STATUS_ACTIVE)
    if status not in ROOT_STATUSES:
        raise VeilError("invalid root status")
    salt = secrets.token_bytes(16)
    pass_key = derive_password_key(password, salt, kdf_params(kdf))
    public = {
        "type": ROOT_VKP_KIND,
        "kind": ROOT_VKP_KIND,
        # Kept only as a compatibility alias for old callers. The real file
        # format version is root_file_version.
        "version": 1,
        "protocol_version": 2,
        "protocol_family": PROTOCOL_FAMILY,
        "crypto_core_version": CRYPTO_CORE_VERSION,
        "root_file_version": ROOT_FILE_VERSION,
        "root_id": root_id,
        "root_label": label if label is not None else base.get("root_label"),
        "root_epoch": root_epoch,
        "created_at": int(base.get("created_at") or now),
        "rotated_at": base.get("rotated_at"),
        "valid_from": base.get("valid_from"),
        "valid_until": base.get("valid_until"),
        "status": status,
        "fingerprint": fp,
        "prev_fingerprint": base.get("prev_fingerprint"),
        "kdf_id": "argon2id",
        "seal_params": {
            "cipher": "AES-256-GCM",
            "kdf": pass_key.params,
            "salt": b64e(salt),
        },
        # Compatibility fields for root_file_version=1 readers.
        "kdf": pass_key.params,
        "salt": b64e(salt),
    }
    aad = _root_aad(public)
    plaintext = {
        "seed": b64e(seed),
        "created_at": public["created_at"],
        "fingerprint": fp,
        "root_id": root_id,
        "root_epoch": root_epoch,
        "root_file_version": ROOT_FILE_VERSION,
    }
    nonce, ciphertext = aes_encrypt(pass_key.key, canonical_json(plaintext), aad=aad)
    public["seal_params"]["nonce"] = b64e(nonce)
    public["nonce"] = b64e(nonce)
    public["seed_encrypted"] = b64e(ciphertext)
    public["ciphertext"] = b64e(ciphertext)
    public["metadata_mac"] = _root_metadata_mac(seed, public)
    dest = Path(out_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(public, indent=2), encoding="utf-8")
    dest.chmod(0o600)
    return inspect_root_vkp_seed(dest)


def open_root_vkp_seed(path: str | Path, password: str) -> bytes:
    return open_root_vkp_seed_info(path, password).seed


def open_root_vkp_seed_info(path: str | Path, password: str) -> RootVkpSecret:
    try:
        source = Path(path)
        data = json.loads(source.read_text(encoding="utf-8"))
        if data.get("kind") != ROOT_VKP_KIND and data.get("type") != ROOT_VKP_KIND:
            raise ValueError("wrong kind")
        if int(data.get("root_file_version", data.get("version", 1))) < 2:
            seed = _open_legacy_root_vkp_seed(data, password)
            return RootVkpSecret(seed=seed, metadata=_legacy_root_metadata(seed, data), path=str(source))
        params = dict(data.get("seal_params") or {})
        pass_key = derive_password_key(password, b64d(params.get("salt") or data["salt"]), params.get("kdf") or data.get("kdf"))
        aad = _root_aad(data)
        plaintext = aes_decrypt(
            pass_key.key,
            b64d(params.get("nonce") or data["nonce"]),
            b64d(data.get("seed_encrypted") or data["ciphertext"]),
            aad=aad,
        )
        payload = json.loads(plaintext.decode("utf-8"))
        seed = b64d(payload["seed"])
        expected = data.get("fingerprint")
        if fingerprint_root_vkp(seed) != expected or payload.get("fingerprint") != expected:
            raise ValueError("fingerprint mismatch")
        if payload.get("root_id") != data.get("root_id") or int(payload.get("root_epoch", -1)) != int(data.get("root_epoch", -2)):
            raise ValueError("root metadata mismatch")
        if not hmac.compare_digest(_root_metadata_mac(seed, data), str(data.get("metadata_mac") or "")):
            raise ValueError("metadata mac mismatch")
        return RootVkpSecret(seed=seed, metadata=_root_inspect_payload(data), path=str(source))
    except Exception as exc:
        raise VeilDecryptError("Unable to open message.") from exc


def inspect_root_vkp_seed(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if data.get("kind") != ROOT_VKP_KIND and data.get("type") != ROOT_VKP_KIND:
        raise VeilError("not a root keypart seed file")
    if int(data.get("root_file_version", data.get("version", 1))) < 2:
        return {
            "kind": data.get("kind"),
            "type": data.get("kind"),
            "version": data.get("version"),
            "root_file_version": 1,
            "protocol_version": data.get("protocol_version", 2),
            "fingerprint": data.get("fingerprint"),
            "created_at": data.get("created_at"),
            "kdf": data.get("kdf"),
            "status": ROOT_STATUS_ACTIVE,
            "root_epoch": 0,
        }
    return _root_inspect_payload(data)


def rotate_root_vkp_seed(in_path: str | Path, out_path: str | Path, password: str, kdf: dict | None = None) -> dict:
    old = open_root_vkp_seed_info(in_path, password)
    random_salt = secrets.token_bytes(32)
    new_seed = hkdf(old.seed, salt=random_salt, info=ROOT_ROTATE_INFO)
    now = int(time.time())
    metadata = dict(old.metadata)
    metadata.update(
        {
            "root_epoch": old.root_epoch + 1,
            "created_at": now,
            "rotated_at": now,
            "status": ROOT_STATUS_ACTIVE,
            "fingerprint": fingerprint_root_vkp(new_seed),
            "prev_fingerprint": old.fingerprint,
        }
    )
    return seal_root_vkp_seed(new_seed, password, out_path, kdf, metadata=metadata)


def set_root_vkp_seed_status(
    in_path: str | Path,
    out_path: str | Path,
    password: str,
    status: str,
    kdf: dict | None = None,
) -> dict:
    if status not in ROOT_STATUSES:
        raise VeilError("invalid root status")
    root = open_root_vkp_seed_info(in_path, password)
    metadata = dict(root.metadata)
    metadata["status"] = status
    if status in {ROOT_STATUS_RETIRED, ROOT_STATUS_REVOKED}:
        metadata["valid_until"] = metadata.get("valid_until") or int(time.time())
    return seal_root_vkp_seed(root.seed, password, out_path, kdf, metadata=metadata)


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


def import_root_vkp_seed(
    in_path: str | Path,
    out_path: str | Path,
    password: str,
    kdf: dict | None = None,
    *,
    label: str | None = None,
) -> dict:
    raw = Path(in_path).read_text(encoding="utf-8").strip()
    if raw.startswith("{"):
        root = open_root_vkp_seed_info(in_path, password)
        metadata = dict(root.metadata)
        if label is not None:
            metadata["root_label"] = label
        return seal_root_vkp_seed(root.seed, password, out_path, kdf, metadata=metadata)
    if raw.startswith(ROOT_VKP_EXPORT_PREFIX):
        raw = raw[len(ROOT_VKP_EXPORT_PREFIX) :]
    try:
        seed = b64d(raw)
    except Exception as exc:
        raise VeilError("invalid root keypart export") from exc
    return seal_root_vkp_seed(seed, password, out_path, kdf, label=label)


def root_store_dir(home: str | Path | None = None, root_store: str | Path | None = None) -> Path:
    if root_store:
        return Path(root_store).expanduser()
    if home:
        return Path(home).expanduser() / "roots"
    return Path.home() / ".veil" / "roots"


def import_root_to_store(
    in_path: str | Path,
    password: str,
    *,
    home: str | Path | None = None,
    root_store: str | Path | None = None,
    label: str | None = None,
    kdf: dict | None = None,
) -> dict:
    root = open_root_vkp_seed_info(in_path, password)
    metadata = dict(root.metadata)
    if label is not None:
        metadata["root_label"] = label
    store = root_store_dir(home, root_store)
    store.mkdir(parents=True, exist_ok=True)
    dest = store / f"{root.fingerprint}.root.vkpseed"
    if label is not None or int(metadata.get("root_file_version", ROOT_FILE_VERSION)) < 2:
        seal_root_vkp_seed(root.seed, password, dest, kdf, metadata=metadata)
    else:
        shutil.copy2(in_path, dest)
        dest.chmod(0o600)
    return {"imported": str(dest), "store": str(store), "root": inspect_root_vkp_seed(dest)}


def list_root_store(*, home: str | Path | None = None, root_store: str | Path | None = None) -> dict:
    store = root_store_dir(home, root_store)
    roots = []
    if store.exists():
        for path in sorted(store.glob("*.root.vkpseed")):
            try:
                item = inspect_root_vkp_seed(path)
                item["path"] = str(path)
                roots.append(item)
            except Exception:
                roots.append({"path": str(path), "status": "unreadable"})
    return {"store": str(store), "roots": roots}


def show_root_in_store(
    fingerprint_value: str,
    *,
    home: str | Path | None = None,
    root_store: str | Path | None = None,
) -> dict:
    matches = _root_store_matches(fingerprint_value, home=home, root_store=root_store)
    if not matches:
        raise VeilError("root not found")
    if len(matches) > 1:
        raise VeilError("multiple roots match; use a longer fingerprint")
    info = inspect_root_vkp_seed(matches[0])
    info["path"] = str(matches[0])
    return info


def remove_root_from_store(
    fingerprint_value: str,
    *,
    home: str | Path | None = None,
    root_store: str | Path | None = None,
    confirm: bool = False,
) -> dict:
    if not confirm:
        raise VeilError("root removal requires --yes")
    matches = _root_store_matches(fingerprint_value, home=home, root_store=root_store)
    if not matches:
        raise VeilError("root not found")
    if len(matches) > 1:
        raise VeilError("multiple roots match; use a longer fingerprint")
    target = matches[0]
    target.unlink()
    return {"removed": str(target)}


def resolve_root_from_store(
    *,
    password: str,
    home: str | Path | None = None,
    root_store: str | Path | None = None,
    fingerprint_value: str | None = None,
    label: str | None = None,
) -> RootVkpSecret:
    store = root_store_dir(home, root_store)
    if fingerprint_value:
        candidates = _root_store_matches(fingerprint_value, home=home, root_store=root_store)
    else:
        candidates = sorted(store.glob("*.root.vkpseed")) if store.exists() else []
        if label:
            candidates = [path for path in candidates if inspect_root_vkp_seed(path).get("root_label") == label]
    if not candidates:
        raise VeilDecryptError("Unable to open message.")
    if len(candidates) > 1 and not fingerprint_value:
        raise VeilDecryptError("Unable to open message.")
    last_error: Exception | None = None
    for path in candidates:
        try:
            return open_root_vkp_seed_info(path, password)
        except Exception as exc:
            last_error = exc
    raise VeilDecryptError("Unable to open message.") from last_error


def split_root_vkp_seed(
    in_path: str | Path,
    password: str,
    *,
    shares: int,
    threshold: int,
    out_dir: str | Path,
) -> dict:
    if shares < 2 or shares > 255:
        raise VeilError("shares must be between 2 and 255")
    if threshold < 2 or threshold > shares:
        raise VeilError("threshold must be between 2 and shares")
    root = open_root_vkp_seed_info(in_path, password)
    share_payloads = _shamir_split(root.seed, shares, threshold)
    dest = Path(out_dir)
    dest.mkdir(parents=True, exist_ok=True)
    files = []
    checksum = b64e(sha256(root.seed))
    for index, payload in enumerate(share_payloads, start=1):
        data = {
            "type": "veil-root-vkpseed-share",
            "share_file_version": 1,
            "share_index": index,
            "threshold": threshold,
            "total_shares": shares,
            "root_id": root.root_id,
            "root_label": root.metadata.get("root_label"),
            "root_fingerprint": root.fingerprint,
            "root_epoch": root.root_epoch,
            "checksum": checksum,
            "share_payload": b64e(payload),
        }
        path = dest / f"root.share.{index}"
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        path.chmod(0o600)
        files.append(str(path))
    return {"shares": files, "threshold": threshold, "total_shares": shares, "root_fingerprint": root.fingerprint}


def recover_root_vkp_seed(
    share_paths: list[str | Path],
    out_path: str | Path,
    password: str,
    kdf: dict | None = None,
) -> dict:
    loaded = [json.loads(Path(path).read_text(encoding="utf-8")) for path in share_paths]
    if not loaded:
        raise VeilError("at least one share is required")
    first = loaded[0]
    threshold = int(first.get("threshold", 0))
    if len(loaded) < threshold:
        raise VeilError("not enough shares to recover root")
    root_fp = first.get("root_fingerprint")
    root_epoch = int(first.get("root_epoch", -1))
    checksum = first.get("checksum")
    for item in loaded:
        if item.get("type") != "veil-root-vkpseed-share":
            raise VeilError("invalid root share")
        if int(item.get("threshold", 0)) != threshold or item.get("root_fingerprint") != root_fp:
            raise VeilError("root shares do not belong together")
        if int(item.get("root_epoch", -2)) != root_epoch or item.get("checksum") != checksum:
            raise VeilError("root shares do not belong together")
    points = [(int(item["share_index"]), b64d(item["share_payload"])) for item in loaded[:threshold]]
    seed = _shamir_recover(points)
    if b64e(sha256(seed)) != checksum or fingerprint_root_vkp(seed) != root_fp:
        raise VeilError("root share recovery failed")
    metadata = {
        "root_id": first.get("root_id") or random_b64(16),
        "root_label": first.get("root_label"),
        "root_epoch": root_epoch,
        "status": ROOT_STATUS_ACTIVE,
        "fingerprint": root_fp,
        "prev_fingerprint": None,
    }
    return seal_root_vkp_seed(seed, password, out_path, kdf, metadata=metadata)


def _open_legacy_root_vkp_seed(data: dict, password: str) -> bytes:
    aad = canonical_json({"kind": ROOT_VKP_KIND, "fingerprint": data["fingerprint"], "version": int(data["version"])})
    pass_key = derive_password_key(password, b64d(data["salt"]), data.get("kdf"))
    plaintext = aes_decrypt(pass_key.key, b64d(data["nonce"]), b64d(data["ciphertext"]), aad=aad)
    payload = json.loads(plaintext.decode("utf-8"))
    seed = b64d(payload["seed"])
    if fingerprint_root_vkp(seed) != data.get("fingerprint") or payload.get("fingerprint") != data.get("fingerprint"):
        raise ValueError("fingerprint mismatch")
    return seed


def _legacy_root_metadata(seed: bytes, data: dict) -> dict:
    return {
        "type": ROOT_VKP_KIND,
        "kind": ROOT_VKP_KIND,
        "root_file_version": 1,
        "version": data.get("version", 1),
        "protocol_version": data.get("protocol_version", 2),
        "root_id": data.get("root_id") or fingerprint_root_vkp(seed),
        "root_label": data.get("root_label"),
        "root_epoch": int(data.get("root_epoch", 0)),
        "created_at": data.get("created_at"),
        "rotated_at": data.get("rotated_at"),
        "valid_from": data.get("valid_from"),
        "valid_until": data.get("valid_until"),
        "status": data.get("status") or ROOT_STATUS_ACTIVE,
        "fingerprint": fingerprint_root_vkp(seed),
        "prev_fingerprint": data.get("prev_fingerprint"),
    }


def _root_inspect_payload(data: dict) -> dict:
    return {
        "kind": data.get("kind") or data.get("type"),
        "type": data.get("type") or data.get("kind"),
        "version": data.get("version", 1),
        "protocol_version": data.get("protocol_version", 2),
        "protocol_family": data.get("protocol_family"),
        "crypto_core_version": data.get("crypto_core_version"),
        "root_file_version": int(data.get("root_file_version", 1)),
        "root_id": data.get("root_id"),
        "root_label": data.get("root_label"),
        "root_epoch": int(data.get("root_epoch", 0)),
        "created_at": data.get("created_at"),
        "rotated_at": data.get("rotated_at"),
        "valid_from": data.get("valid_from"),
        "valid_until": data.get("valid_until"),
        "status": data.get("status") or ROOT_STATUS_ACTIVE,
        "fingerprint": data.get("fingerprint"),
        "prev_fingerprint": data.get("prev_fingerprint"),
        "kdf_id": data.get("kdf_id"),
        "kdf": (data.get("seal_params") or {}).get("kdf") or data.get("kdf"),
    }


def _root_aad(data: dict) -> bytes:
    public = {
        key: value
        for key, value in data.items()
        if key
        not in {
            "seed_encrypted",
            "ciphertext",
            "metadata_mac",
            "nonce",
        }
    }
    params = dict(public.get("seal_params") or {})
    params.pop("nonce", None)
    public["seal_params"] = params
    return canonical_json(public)


def _root_metadata_mac(seed: bytes, data: dict) -> str:
    key = hkdf(seed, salt=None, info=b"veil-root-vkpseed-metadata-mac-v2")
    material = {
        key_name: value
        for key_name, value in data.items()
        if key_name not in {"seed_encrypted", "ciphertext", "metadata_mac"}
    }
    return b64e(hmac.digest(key, canonical_json(material), "sha256"))


def _root_store_matches(
    fingerprint_value: str,
    *,
    home: str | Path | None = None,
    root_store: str | Path | None = None,
) -> list[Path]:
    store = root_store_dir(home, root_store)
    if not store.exists():
        return []
    matches = []
    for path in sorted(store.glob("*.root.vkpseed")):
        try:
            fp = str(inspect_root_vkp_seed(path).get("fingerprint") or "")
        except Exception:
            continue
        if fp == fingerprint_value or fp.startswith(fingerprint_value):
            matches.append(path)
    return matches


def _shamir_split(secret: bytes, shares: int, threshold: int) -> list[bytes]:
    polynomials = []
    for value in secret:
        polynomials.append([value] + [secrets.randbelow(256) for _ in range(threshold - 1)])
    outputs = [bytearray() for _ in range(shares)]
    for x in range(1, shares + 1):
        for coeffs in polynomials:
            outputs[x - 1].append(_gf_poly_eval(coeffs, x))
    return [bytes(item) for item in outputs]


def _shamir_recover(points: list[tuple[int, bytes]]) -> bytes:
    lengths = {len(payload) for _, payload in points}
    if len(lengths) != 1:
        raise VeilError("root shares have inconsistent payload lengths")
    size = lengths.pop()
    recovered = bytearray()
    for offset in range(size):
        total = 0
        for i, (x_i, payload_i) in enumerate(points):
            basis = 1
            for j, (x_j, _) in enumerate(points):
                if i == j:
                    continue
                basis = _gf_mul(basis, _gf_div(x_j, x_i ^ x_j))
            total ^= _gf_mul(payload_i[offset], basis)
        recovered.append(total)
    return bytes(recovered)


def _gf_poly_eval(coeffs: list[int], x: int) -> int:
    result = 0
    for coeff in reversed(coeffs):
        result = _gf_mul(result, x) ^ coeff
    return result


def _gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        b >>= 1
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
    return result


def _gf_pow(a: int, power: int) -> int:
    result = 1
    base = a
    while power:
        if power & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        power >>= 1
    return result


def _gf_inv(a: int) -> int:
    if a == 0:
        raise VeilError("invalid duplicate Shamir share index")
    return _gf_pow(a, 254)


def _gf_div(a: int, b: int) -> int:
    return _gf_mul(a, _gf_inv(b))
