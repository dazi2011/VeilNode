from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .chunks import reassemble_chunks, shuffle_chunks, split_chunks
from .compression import pack_input, unpack_payload
from .container import carrier_bytes, embed_payload, extract_payload, normalize_format, verify_container
from .crypto import (
    aes_decrypt,
    aes_encrypt,
    b64d,
    b64e,
    canonical_json,
    derive_message_key_v2,
    derive_password_key,
    derive_vkp_i,
    hkdf,
    kdf_params,
    random_b64,
    sha256,
    subkey,
    xchacha_decrypt,
    xchacha_encrypt,
)
from .errors import VeilDecryptError, VeilError
from .identity import PrivateIdentity, PublicIdentity
from .padding import padding_len
from .protocol import assert_supported, current_protocol, protocol_v2


DEFAULT_POLICY = {
    "node_name": "veil-node",
    "profile_version": 1,
    "protocol": current_protocol(),
    "chunk_size": 65536,
    "padding": "bucket",
    "bucket_size": 65536,
    "supported_containers": ["png", "bmp", "wav", "mp4", "zip", "pdf", "7z", "vmsg"],
    "kdf": kdf_params(),
    "receive_failure_messages": [
        "unable to open message",
        "operation failed",
        "message could not be recovered",
    ],
}

V2_PACKAGE_KIND = "veil-msg-v2"


@dataclass
class LayerBuild:
    role: str
    password: str
    password_salt: bytes
    pass_params: dict
    device_bound: bool
    layer_id: str
    layer_salt: bytes
    file_key: bytes
    manifest_nonce: bytes
    manifest_len: int
    blob: bytes
    envelopes: list[dict]
    auth_record: dict
    auth_id: str


@dataclass
class V2LayerBuild:
    role: str
    msg_id: bytes
    message_salt: bytes
    pass_params: dict
    receiver_id: str
    file_hash: bytes
    layer_id: str
    layer_salt: bytes
    file_key: bytes
    manifest_nonce: bytes
    manifest_len: int
    blob: bytes
    envelopes: list[dict]
    auth_record: dict
    auth_id: str


def load_policy(path: str | Path | None = None) -> dict:
    policy = dict(DEFAULT_POLICY)
    if path:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        policy.update(data)
    policy["kdf"] = kdf_params(policy.get("kdf"))
    policy.setdefault("protocol", current_protocol())
    policy.setdefault("profile_version", 1)
    assert_supported(policy.get("protocol"))
    return policy


def create_message(
    *,
    input_path: str | Path,
    output_path: str | Path,
    keypart_path: str | Path | None,
    auth_state_path: str | Path,
    recipients: Iterable[PublicIdentity],
    password: str,
    policy: dict | None = None,
    carrier_path: str | Path | None = None,
    container_format: str | None = None,
    decoy_input: str | Path | None = None,
    decoy_password: str | None = None,
    device_bound: bool = False,
    root_vkp_seed: bytes | None = None,
) -> dict:
    cfg = load_policy(None)
    if policy:
        cfg.update(policy)
        cfg["kdf"] = kdf_params(cfg.get("kdf"))
    fmt = normalize_format(container_format, carrier_path or output_path)
    if fmt not in set(cfg.get("supported_containers", [])):
        raise VeilError(f"container format not enabled by policy: {fmt}")
    recipient_list = list(recipients)
    if not recipient_list:
        raise VeilError("at least one recipient is required")
    if root_vkp_seed is not None:
        return _create_message_v2(
            input_path=input_path,
            output_path=output_path,
            auth_state_path=auth_state_path,
            recipients=recipient_list,
            password=password,
            policy=cfg,
            carrier_path=carrier_path,
            container_format=fmt,
            root_vkp_seed=root_vkp_seed,
            device_bound=device_bound,
            decoy_input=decoy_input,
            decoy_password=decoy_password,
        )
    if keypart_path is None:
        raise VeilError("external keypart path is required for v1 messages")

    builds = [
        _build_layer(
            role="real",
            input_path=input_path,
            password=password,
            recipients=recipient_list,
            policy=cfg,
            device_bound=device_bound,
        )
    ]
    if decoy_input:
        if not decoy_password:
            raise VeilError("decoy password is required when decoy input is used")
        builds.append(
            _build_layer(
                role="decoy",
                input_path=decoy_input,
                password=decoy_password,
                recipients=recipient_list,
                policy=cfg,
                device_bound=device_bound,
            )
        )

    aggregate, relative = _aggregate_layers(builds, cfg)
    carrier = carrier_bytes(fmt, carrier_path)
    embedded = embed_payload(carrier, aggregate, fmt)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(embedded.data)
    validation = verify_container(output, fmt)
    if not validation["ok"]:
        raise VeilError(f"container verification failed for {fmt}")

    keypart = {
        "kind": "veil-keypart",
        "protocol": current_protocol(),
        "records": [],
        "created_at": int(time.time()),
        "record_count": len(builds),
        "container_validation": validation,
        "container_sha256": b64e(sha256(embedded.data)),
    }
    auth_records = []
    for build in builds:
        rel_offset = relative[build.layer_id]
        sealed = _seal_keypart_record(
            build=build,
            locator={
                "offset": embedded.offset + rel_offset,
                "length": len(build.blob),
                "container_format": fmt,
                "container_mode": embedded.mode,
                "container_extra": embedded.extra,
                "output_size": len(embedded.data),
                "payload_sha256": b64e(sha256(build.blob)),
                "container_sha256": b64e(sha256(embedded.data)),
            },
        )
        keypart["records"].append(sealed)
        auth_records.append(build.auth_record)

    Path(keypart_path).parent.mkdir(parents=True, exist_ok=True)
    Path(keypart_path).write_text(json.dumps(keypart, indent=2), encoding="utf-8")
    Path(keypart_path).chmod(0o600)
    _write_auth_state(auth_state_path, auth_records)
    return {
        "output": str(output),
        "keypart": str(keypart_path),
        "auth_state": str(auth_state_path),
        "format": fmt,
        "layers": len(builds),
        "container_mode": embedded.mode,
    }


def receive_message(
    *,
    input_path: str | Path,
    keypart_path: str | Path,
    auth_state_path: str | Path,
    output_dir: str | Path,
    identity: PrivateIdentity,
    password: str,
    verify_only: bool = False,
) -> dict:
    try:
        keypart = json.loads(Path(keypart_path).read_text(encoding="utf-8"))
        assert_supported(keypart.get("protocol"))
        records = list(keypart.get("records", []))
    except Exception as exc:
        raise VeilDecryptError("unable to open message") from exc

    for record in records:
        try:
            result = _try_receive_record(
                record=record,
                input_path=input_path,
                auth_state_path=auth_state_path,
                output_dir=output_dir,
                identity=identity,
                password=password,
                verify_only=verify_only,
            )
            return result
        except Exception:
            continue
    raise VeilDecryptError("unable to open message")


def inspect_keypart(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        "kind": data.get("kind", "legacy-keypart"),
        "protocol": data.get("protocol", {"name": "veil-msg", "version": 1, "suite": "legacy-v1"}),
        "records": len(data.get("records", [])),
        "device_bound_records": sum(1 for r in data.get("records", []) if r.get("device_bound")),
        "created_at": data.get("created_at"),
        "container_validation": data.get("container_validation"),
    }


def message_protocol_version(path: str | Path) -> int:
    return 2 if _extract_v2_package(path, required=False) is not None else 1


def receive_message_v2(
    *,
    input_path: str | Path,
    root_vkp_seed: bytes,
    auth_state_path: str | Path,
    output_dir: str | Path,
    identity: PrivateIdentity,
    password: str,
    verify_only: bool = False,
) -> dict:
    try:
        package = _extract_v2_package(input_path, required=True)
        assert_supported(package.get("protocol"))
        if int(package.get("protocol", {}).get("version", 0)) != 2:
            raise ValueError("not v2")
        if package.get("receiver_id") != identity.public.node_id:
            raise ValueError("recipient mismatch")
        msg_id = b64d(package["msg_id"])
        message_salt = b64d(package["message_salt"])
        file_hash = b64d(package["file_hash"])
        receiver_id = package["receiver_id"].encode("utf-8")
        vkp_i = derive_vkp_i(root_vkp_seed, msg_id, file_hash, receiver_id)
        message_key = derive_message_key_v2(vkp_i, password, message_salt, package.get("kdf"))
        layer_id = package["layer_id"]
        layer_salt = b64d(package["layer_salt"])
        file_key = _unwrap_file_key(package.get("envelopes", []), identity, layer_id)
        auth_key = subkey(message_key, file_key, "offline-auth-state-v2", layer_salt)
        _verify_auth_state(auth_state_path, package["auth_id"], auth_key)

        blob = b64d(package["blob"])
        if b64e(sha256(blob)) != package.get("payload_sha256"):
            raise ValueError("payload hash mismatch")
        manifest_len = int(package["manifest_len"])
        manifest_ciphertext = blob[:manifest_len]
        chunk_payload = blob[manifest_len:]
        aad = canonical_json({"layer_id": layer_id, "role": package.get("role", "real"), "v": 2})
        manifest_key = subkey(message_key, file_key, "manifest-aes-256-gcm-v2", layer_salt)
        manifest_plain = aes_decrypt(manifest_key, b64d(package["manifest_nonce"]), manifest_ciphertext, aad=aad)
        manifest = json.loads(manifest_plain.decode("utf-8"))
        assert_supported(manifest.get("protocol"))
        if int(manifest.get("protocol", {}).get("version", 0)) != 2 or manifest.get("layer_id") != layer_id:
            raise ValueError("manifest mismatch")
        outer_ciphertext = _reassemble_chunks(chunk_payload, manifest)
        outer_key = subkey(message_key, file_key, "aes-256-gcm-outer-v2", layer_salt)
        inner_ciphertext = aes_decrypt(outer_key, b64d(manifest["outer_nonce"]), outer_ciphertext, aad=aad)
        content_key = subkey(message_key, file_key, "xchacha20-poly1305-content-v2", layer_salt)
        archive = xchacha_decrypt(content_key, b64d(manifest["inner_nonce"]), inner_ciphertext, aad=aad)
        if b64e(sha256(archive)) != manifest["archive_sha256"] or b64e(file_hash) != manifest["file_hash"]:
            raise ValueError("archive hash mismatch")
        if verify_only:
            return {
                "verified": True,
                "protocol_version": 2,
                "role": manifest.get("role"),
                "archive_meta": manifest.get("archive_meta", {}),
                "auth_state_consumed": False,
            }
        written = _transactional_unpack(archive, output_dir)
        _consume_auth_state(auth_state_path, package["auth_id"], auth_key)
        return {
            "protocol_version": 2,
            "role": manifest.get("role"),
            "archive_meta": manifest.get("archive_meta", {}),
            "written": [str(p) for p in written],
        }
    except VeilDecryptError:
        raise
    except Exception as exc:
        raise VeilDecryptError("unable to open message") from exc


def destroy_auth_state(path: str | Path) -> None:
    _write_json_atomic(path, {"records": [], "destroyed_at": int(time.time())})


def _create_message_v2(
    *,
    input_path: str | Path,
    output_path: str | Path,
    auth_state_path: str | Path,
    recipients: list[PublicIdentity],
    password: str,
    policy: dict,
    carrier_path: str | Path | None,
    container_format: str,
    root_vkp_seed: bytes,
    device_bound: bool,
    decoy_input: str | Path | None,
    decoy_password: str | None,
) -> dict:
    if len(recipients) != 1:
        raise VeilError("v2 root-keypart mode currently supports exactly one recipient")
    if decoy_input or decoy_password:
        raise VeilError("v2 root-keypart mode does not support decoy layers yet")
    if device_bound:
        raise VeilError("v2 root-keypart mode does not yet support device-bound password derivation")
    fmt = normalize_format(container_format, carrier_path or output_path)
    build = _build_layer_v2(
        role="real",
        input_path=input_path,
        password=password,
        recipient=recipients[0],
        policy=policy,
        root_vkp_seed=root_vkp_seed,
    )
    package = _v2_package(build, fmt)
    carrier = carrier_bytes(fmt, carrier_path)
    embedded = embed_payload(carrier, canonical_json(package), fmt)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(embedded.data)
    validation = verify_container(output, fmt)
    if not validation["ok"]:
        raise VeilError(f"container verification failed for {fmt}")
    _write_auth_state(auth_state_path, [build.auth_record])
    return {
        "output": str(output),
        "keypart": None,
        "auth_state": str(auth_state_path),
        "format": fmt,
        "protocol_version": 2,
        "root_keypart": True,
        "external_keypart": False,
        "msg_id": b64e(build.msg_id),
        "receiver_id": build.receiver_id,
        "container_mode": embedded.mode,
        "container_validation": validation,
    }


def _build_layer_v2(
    *,
    role: str,
    input_path: str | Path,
    password: str,
    recipient: PublicIdentity,
    policy: dict,
    root_vkp_seed: bytes,
) -> V2LayerBuild:
    archive, archive_meta = pack_input(input_path)
    file_hash = sha256(archive)
    msg_id = secrets.token_bytes(16)
    message_salt = secrets.token_bytes(16)
    receiver_id = recipient.node_id
    vkp_i = derive_vkp_i(root_vkp_seed, msg_id, file_hash, receiver_id.encode("utf-8"))
    pass_params = kdf_params(policy.get("kdf"))
    message_key = derive_message_key_v2(vkp_i, password, message_salt, pass_params)
    file_key = secrets.token_bytes(32)
    layer_id = random_b64(18)
    layer_salt = secrets.token_bytes(16)
    aad = canonical_json({"layer_id": layer_id, "role": role, "v": 2})

    content_key = subkey(message_key, file_key, "xchacha20-poly1305-content-v2", layer_salt)
    inner_nonce, inner_ciphertext = xchacha_encrypt(content_key, archive, aad=aad)
    outer_key = subkey(message_key, file_key, "aes-256-gcm-outer-v2", layer_salt)
    outer_nonce, outer_ciphertext = aes_encrypt(outer_key, inner_ciphertext, aad=aad)

    chunk_size = int(policy.get("chunk_size", 65536))
    chunks = split_chunks(outer_ciphertext, chunk_size)
    shuffle_key = subkey(message_key, file_key, "chunk-shuffle-v2", layer_salt)
    order, chunk_payload = shuffle_chunks(chunks, shuffle_key)
    pad_len = padding_len(len(chunk_payload), policy)

    manifest = {
        "v": 2,
        "protocol": protocol_v2(),
        "role": role,
        "layer_id": layer_id,
        "msg_id": b64e(msg_id),
        "receiver_id": receiver_id,
        "created_at": int(time.time()),
        "archive_meta": archive_meta,
        "archive_sha256": b64e(file_hash),
        "file_hash": b64e(file_hash),
        "inner_cipher": "XChaCha20-Poly1305",
        "inner_nonce": b64e(inner_nonce),
        "outer_cipher": "AES-256-GCM",
        "outer_nonce": b64e(outer_nonce),
        "chunk_size": chunk_size,
        "chunk_lengths": [len(c) for c in chunks],
        "chunk_order": order,
        "padding_len": pad_len,
    }
    manifest_key = subkey(message_key, file_key, "manifest-aes-256-gcm-v2", layer_salt)
    manifest_nonce, manifest_ciphertext = aes_encrypt(manifest_key, canonical_json(manifest), aad=aad)
    blob = manifest_ciphertext + chunk_payload + secrets.token_bytes(pad_len)
    auth_key = subkey(message_key, file_key, "offline-auth-state-v2", layer_salt)
    auth_id = random_b64(18)
    auth_record = _make_auth_record(auth_id, auth_key, layer_id)
    envelopes = [_wrap_file_key(file_key, layer_id, recipient)]

    return V2LayerBuild(
        role=role,
        msg_id=msg_id,
        message_salt=message_salt,
        pass_params=pass_params,
        receiver_id=receiver_id,
        file_hash=file_hash,
        layer_id=layer_id,
        layer_salt=layer_salt,
        file_key=file_key,
        manifest_nonce=manifest_nonce,
        manifest_len=len(manifest_ciphertext),
        blob=blob,
        envelopes=envelopes,
        auth_record=auth_record,
        auth_id=auth_id,
    )


def _v2_package(build: V2LayerBuild, fmt: str) -> dict:
    return {
        "kind": V2_PACKAGE_KIND,
        "protocol": protocol_v2(),
        "msg_id": b64e(build.msg_id),
        "message_salt": b64e(build.message_salt),
        "file_hash": b64e(build.file_hash),
        "receiver_id": build.receiver_id,
        "kdf": build.pass_params,
        "role": build.role,
        "layer_id": build.layer_id,
        "layer_salt": b64e(build.layer_salt),
        "manifest_nonce": b64e(build.manifest_nonce),
        "manifest_len": build.manifest_len,
        "payload_sha256": b64e(sha256(build.blob)),
        "blob": b64e(build.blob),
        "envelopes": build.envelopes,
        "auth_id": build.auth_id,
        "container_format": fmt,
        "created_at": int(time.time()),
    }


def _extract_v2_package(path: str | Path, *, required: bool) -> dict | None:
    raw = Path(path).read_bytes()
    marker = f'"kind":"{V2_PACKAGE_KIND}"'.encode("utf-8")
    start_at = 0
    while True:
        marker_pos = raw.find(marker, start_at)
        if marker_pos < 0:
            if required:
                raise VeilDecryptError("unable to open message")
            return None
        candidate = marker_pos
        while True:
            start = raw.rfind(b"{", 0, candidate)
            if start < 0:
                break
            end = _json_object_end(raw, start)
            if end is None or end <= marker_pos:
                candidate = start
                continue
            try:
                data = json.loads(raw[start:end].decode("utf-8"))
            except Exception:
                candidate = start
                continue
            if data.get("kind") == V2_PACKAGE_KIND:
                return data
            candidate = start
        start_at = marker_pos + len(marker)
        continue


def _json_object_end(raw: bytes, start: int) -> int | None:
    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(raw)):
        byte = raw[idx]
        if in_string:
            if escape:
                escape = False
            elif byte == 0x5C:
                escape = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte == 0x7B:
            depth += 1
        elif byte == 0x7D:
            depth -= 1
            if depth == 0:
                return idx + 1
    return None


def _build_layer(
    *,
    role: str,
    input_path: str | Path,
    password: str,
    recipients: list[PublicIdentity],
    policy: dict,
    device_bound: bool,
) -> LayerBuild:
    archive, archive_meta = pack_input(input_path)
    file_key = secrets.token_bytes(32)
    layer_id = random_b64(18)
    layer_salt = secrets.token_bytes(16)
    password_salt = secrets.token_bytes(16)
    pass_key = derive_password_key(password, password_salt, policy.get("kdf"), device_bound=device_bound)
    aad = canonical_json({"layer_id": layer_id, "role": role, "v": 1})

    content_key = subkey(pass_key.key, file_key, "xchacha20-poly1305-content", layer_salt)
    inner_nonce, inner_ciphertext = xchacha_encrypt(content_key, archive, aad=aad)
    outer_key = subkey(pass_key.key, file_key, "aes-256-gcm-outer", layer_salt)
    outer_nonce, outer_ciphertext = aes_encrypt(outer_key, inner_ciphertext, aad=aad)

    chunk_size = int(policy.get("chunk_size", 65536))
    chunks = split_chunks(outer_ciphertext, chunk_size)
    shuffle_key = subkey(pass_key.key, file_key, "chunk-shuffle", layer_salt)
    order, chunk_payload = shuffle_chunks(chunks, shuffle_key)
    pad_len = padding_len(len(chunk_payload), policy)

    manifest = {
        "v": 1,
        "protocol": current_protocol(),
        "role": role,
        "layer_id": layer_id,
        "created_at": int(time.time()),
        "archive_meta": archive_meta,
        "archive_sha256": b64e(sha256(archive)),
        "inner_cipher": "XChaCha20-Poly1305",
        "inner_nonce": b64e(inner_nonce),
        "outer_cipher": "AES-256-GCM",
        "outer_nonce": b64e(outer_nonce),
        "chunk_size": chunk_size,
        "chunk_lengths": [len(c) for c in chunks],
        "chunk_order": order,
        "padding_len": pad_len,
    }
    manifest_key = subkey(pass_key.key, file_key, "manifest-aes-256-gcm", layer_salt)
    manifest_nonce, manifest_ciphertext = aes_encrypt(manifest_key, canonical_json(manifest), aad=aad)
    blob = manifest_ciphertext + chunk_payload + secrets.token_bytes(pad_len)
    auth_key = subkey(pass_key.key, file_key, "offline-auth-state", layer_salt)
    auth_id = random_b64(18)
    auth_record = _make_auth_record(auth_id, auth_key, layer_id)
    envelopes = [_wrap_file_key(file_key, layer_id, recipient) for recipient in recipients]

    return LayerBuild(
        role=role,
        password=password,
        password_salt=password_salt,
        pass_params=pass_key.params,
        device_bound=device_bound,
        layer_id=layer_id,
        layer_salt=layer_salt,
        file_key=file_key,
        manifest_nonce=manifest_nonce,
        manifest_len=len(manifest_ciphertext),
        blob=blob,
        envelopes=envelopes,
        auth_record=auth_record,
        auth_id=auth_id,
    )


def _aggregate_layers(builds: list[LayerBuild], policy: dict) -> tuple[bytes, dict[str, int]]:
    order = list(builds)
    secrets.SystemRandom().shuffle(order)
    bucket = max(32, int(policy.get("bucket_size", 65536)) // 16)
    aggregate = bytearray()
    offsets: dict[str, int] = {}
    for build in order:
        gap = secrets.randbelow(bucket + 1)
        aggregate += secrets.token_bytes(gap)
        offsets[build.layer_id] = len(aggregate)
        aggregate += build.blob
    aggregate += secrets.token_bytes(secrets.randbelow(bucket + 1))
    return bytes(aggregate), offsets


def _seal_keypart_record(*, build: LayerBuild, locator: dict) -> dict:
    record_id = random_b64(18)
    seal_key = hkdf(build_password_key(build), salt=build.password_salt, info=b"veil/keypart/seal")
    plaintext = {
        "v": 1,
        "protocol": current_protocol(),
        "record_id": record_id,
        "role": build.role,
        "layer_id": build.layer_id,
        "layer_salt": b64e(build.layer_salt),
        "manifest_nonce": b64e(build.manifest_nonce),
        "manifest_len": build.manifest_len,
        "locator": locator,
        "envelopes": build.envelopes,
        "auth_id": build.auth_id,
    }
    nonce, ciphertext = aes_encrypt(seal_key, canonical_json(plaintext), aad=record_id.encode("ascii"))
    return {
        "id": record_id,
        "salt": b64e(build.password_salt),
        "kdf": build.pass_params,
        "device_bound": build.device_bound,
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }


def build_password_key(build: LayerBuild) -> bytes:
    return derive_password_key(
        build.password,
        build.password_salt,
        build.pass_params,
        device_bound=build.device_bound,
    ).key


def _try_receive_record(
    *,
    record: dict,
    input_path: str | Path,
    auth_state_path: str | Path,
    output_dir: str | Path,
    identity: PrivateIdentity,
    password: str,
    verify_only: bool,
) -> dict:
    pass_key = derive_password_key(
        password,
        b64d(record["salt"]),
        record.get("kdf"),
        device_bound=bool(record.get("device_bound")),
    )
    seal_key = hkdf(pass_key.key, salt=pass_key.salt, info=b"veil/keypart/seal")
    sealed = aes_decrypt(
        seal_key,
        b64d(record["nonce"]),
        b64d(record["ciphertext"]),
        aad=record["id"].encode("ascii"),
    )
    info = json.loads(sealed.decode("utf-8"))
    assert_supported(info.get("protocol"))
    layer_id = info["layer_id"]
    layer_salt = b64d(info["layer_salt"])
    file_key = _unwrap_file_key(info["envelopes"], identity, layer_id)
    auth_key = subkey(pass_key.key, file_key, "offline-auth-state", layer_salt)
    _verify_auth_state(auth_state_path, info["auth_id"], auth_key)

    locator = info["locator"]
    blob = extract_payload(input_path, int(locator["offset"]), int(locator["length"]))
    if locator.get("payload_sha256") and b64e(sha256(blob)) != locator["payload_sha256"]:
        raise VeilDecryptError("unable to open message")
    manifest_len = int(info["manifest_len"])
    manifest_ciphertext = blob[:manifest_len]
    chunk_payload = blob[manifest_len:]
    aad = canonical_json({"layer_id": layer_id, "role": info.get("role", "real"), "v": 1})
    manifest_key = subkey(pass_key.key, file_key, "manifest-aes-256-gcm", layer_salt)
    manifest_plain = aes_decrypt(
        manifest_key,
        b64d(info["manifest_nonce"]),
        manifest_ciphertext,
        aad=aad,
    )
    manifest = json.loads(manifest_plain.decode("utf-8"))
    assert_supported(manifest.get("protocol"))
    if manifest.get("layer_id") != layer_id:
        raise VeilDecryptError("unable to open message")
    outer_ciphertext = _reassemble_chunks(chunk_payload, manifest)
    outer_key = subkey(pass_key.key, file_key, "aes-256-gcm-outer", layer_salt)
    inner_ciphertext = aes_decrypt(outer_key, b64d(manifest["outer_nonce"]), outer_ciphertext, aad=aad)
    content_key = subkey(pass_key.key, file_key, "xchacha20-poly1305-content", layer_salt)
    archive = xchacha_decrypt(content_key, b64d(manifest["inner_nonce"]), inner_ciphertext, aad=aad)
    if b64e(sha256(archive)) != manifest["archive_sha256"]:
        raise VeilDecryptError("unable to open message")
    if verify_only:
        return {
            "verified": True,
            "role": manifest.get("role"),
            "archive_meta": manifest.get("archive_meta", {}),
            "auth_state_consumed": False,
        }
    written = _transactional_unpack(archive, output_dir)
    _consume_auth_state(auth_state_path, info["auth_id"], auth_key)
    return {
        "role": manifest.get("role"),
        "archive_meta": manifest.get("archive_meta", {}),
        "written": [str(p) for p in written],
    }


def _reassemble_chunks(chunk_payload: bytes, manifest: dict) -> bytes:
    lengths = [int(x) for x in manifest["chunk_lengths"]]
    order = [int(x) for x in manifest["chunk_order"]]
    return reassemble_chunks(chunk_payload, lengths, order)


def _transactional_unpack(archive: bytes, output_dir: str | Path) -> list[Path]:
    final = Path(output_dir).resolve()
    if final.exists():
        raise VeilError("output directory already exists")
    parent = final.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = parent / f".veil-recover-{final.name}-{random_b64(8)}"
    if staging.exists():
        raise VeilError("recovery staging path collision")
    written = unpack_payload(archive, staging)
    if final.exists():
        raise VeilError("output directory changed during recovery")
    os.replace(staging, final)
    return [final / path.relative_to(staging) for path in written]


def _wrap_file_key(file_key: bytes, layer_id: str, recipient: PublicIdentity) -> dict:
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared = ephemeral.exchange(recipient.public_object())
    kek = hkdf(shared, salt=layer_id.encode("utf-8"), info=b"veil/x25519/file-key-wrap")
    aad = canonical_json({"recipient": recipient.node_id, "layer_id": layer_id})
    nonce, wrapped = aes_encrypt(kek, file_key, aad=aad)
    return {
        "recipient": recipient.node_id,
        "ephemeral_public": b64e(ephemeral_public),
        "nonce": b64e(nonce),
        "wrapped_file_key": b64e(wrapped),
    }


def _unwrap_file_key(envelopes: list[dict], identity: PrivateIdentity, layer_id: str) -> bytes:
    for envelope in envelopes:
        if envelope.get("recipient") != identity.public.node_id:
            continue
        peer = x25519.X25519PublicKey.from_public_bytes(b64d(envelope["ephemeral_public"]))
        shared = identity.private_object().exchange(peer)
        kek = hkdf(shared, salt=layer_id.encode("utf-8"), info=b"veil/x25519/file-key-wrap")
        aad = canonical_json({"recipient": identity.public.node_id, "layer_id": layer_id})
        return aes_decrypt(kek, b64d(envelope["nonce"]), b64d(envelope["wrapped_file_key"]), aad=aad)
    raise VeilDecryptError("unable to open message")


def _make_auth_record(auth_id: str, auth_key: bytes, layer_id: str) -> dict:
    nonce, ciphertext = aes_encrypt(
        auth_key,
        canonical_json({"auth_id": auth_id, "layer_id": layer_id, "used": False, "created_at": int(time.time())}),
        aad=auth_id.encode("ascii"),
    )
    return {"id": auth_id, "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}


def _write_auth_state(path: str | Path, records: list[dict]) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(path, {"records": records, "created_at": int(time.time())})
    Path(path).chmod(0o600)


def _verify_auth_state(path: str | Path, auth_id: str, auth_key: bytes) -> None:
    state = json.loads(Path(path).read_text(encoding="utf-8"))
    for record in state.get("records", []):
        if record.get("id") != auth_id:
            continue
        plain = aes_decrypt(auth_key, b64d(record["nonce"]), b64d(record["ciphertext"]), aad=auth_id.encode("ascii"))
        data = json.loads(plain.decode("utf-8"))
        if data.get("used"):
            raise VeilDecryptError("unable to open message")
        return
    raise VeilDecryptError("unable to open message")


def _consume_auth_state(path: str | Path, auth_id: str, auth_key: bytes) -> None:
    state_path = Path(path)
    state = json.loads(state_path.read_text(encoding="utf-8"))
    kept = []
    consumed = False
    for record in state.get("records", []):
        if record.get("id") != auth_id:
            kept.append(record)
            continue
        plain = aes_decrypt(auth_key, b64d(record["nonce"]), b64d(record["ciphertext"]), aad=auth_id.encode("ascii"))
        data = json.loads(plain.decode("utf-8"))
        if data.get("used"):
            raise VeilDecryptError("unable to open message")
        consumed = True
    if not consumed:
        raise VeilDecryptError("unable to open message")
    state["records"] = kept
    state["updated_at"] = int(time.time())
    _write_json_atomic(state_path, state)


def _write_json_atomic(path: str | Path, data: dict) -> None:
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, dest)
