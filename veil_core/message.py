from __future__ import annotations

import json
import os
import secrets
import time
import hmac
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
from .replay import assert_not_seen, mark_seen
from .strategy.policy import EnvelopePolicy, policy_runtime_overrides
from .strategy.scorer import scan_fixed_signatures


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
PROTOCOL_FAMILY = "veil-offline-envelope"
CRYPTO_CORE_VERSION_22 = "2.2"


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


def _normalize_envelope_policy(envelope_policy: dict | EnvelopePolicy | None, fmt: str) -> EnvelopePolicy | None:
    if envelope_policy is None:
        return None
    policy = envelope_policy if isinstance(envelope_policy, EnvelopePolicy) else EnvelopePolicy.from_json(envelope_policy)
    policy.validate(expected_format=fmt)
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
    root_metadata: dict | None = None,
    crypto_core_version: str | None = None,
    low_signature: bool = False,
    signature_profile: str = "balanced",
    carrier_profile: dict | None = None,
    envelope_policy: dict | EnvelopePolicy | None = None,
) -> dict:
    cfg = load_policy(None)
    if policy:
        cfg.update(policy)
        cfg["kdf"] = kdf_params(cfg.get("kdf"))
    fmt = normalize_format(container_format, carrier_path or output_path)
    selected_envelope_policy = _normalize_envelope_policy(envelope_policy, fmt)
    if selected_envelope_policy is not None:
        cfg.update(policy_runtime_overrides(selected_envelope_policy))
    if fmt not in set(cfg.get("supported_containers", [])):
        raise VeilError(f"container format not enabled by policy: {fmt}")
    recipient_list = list(recipients)
    if not recipient_list:
        raise VeilError("at least one recipient is required")
    if root_vkp_seed is not None:
        requested_core = str(crypto_core_version or "2")
        if requested_core == CRYPTO_CORE_VERSION_22:
            return _create_message_v22(
                input_path=input_path,
                output_path=output_path,
                auth_state_path=auth_state_path,
                recipients=recipient_list,
                password=password,
                policy=cfg,
                carrier_path=carrier_path,
                container_format=fmt,
                root_vkp_seed=root_vkp_seed,
                root_metadata=root_metadata or {},
                device_bound=device_bound,
                decoy_input=decoy_input,
                decoy_password=decoy_password,
                low_signature=low_signature,
                signature_profile=signature_profile,
                carrier_profile=carrier_profile,
                envelope_policy=selected_envelope_policy,
            )
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
            root_metadata=root_metadata or {},
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
    embedded = embed_payload(carrier, aggregate, fmt, strategy=selected_envelope_policy.embed_strategy if selected_envelope_policy else None)
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
        "envelope_policy": selected_envelope_policy.to_json() if selected_envelope_policy else None,
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
    try:
        return 2 if _extract_v22_package(path, required=False) is not None or _extract_v2_package(path, required=False) is not None else 1
    except FileNotFoundError as exc:
        raise VeilDecryptError("Unable to open message.") from exc


def receive_message_v2(
    *,
    input_path: str | Path,
    root_vkp_seed: bytes,
    auth_state_path: str | Path,
    output_dir: str | Path,
    identity: PrivateIdentity,
    password: str,
    verify_only: bool = False,
    root_metadata: dict | None = None,
    seen_db_path: str | Path | None = None,
    no_replay_check: bool = False,
    allow_revoked_root: bool = False,
) -> dict:
    try:
        package22 = _extract_v22_package(input_path, required=False)
        if package22 is not None:
            return _receive_message_v22(
                input_path=input_path,
                package=package22,
                root_vkp_seed=root_vkp_seed,
                root_metadata=root_metadata or {},
                seen_db_path=seen_db_path,
                output_dir=output_dir,
                identity=identity,
                password=password,
                verify_only=verify_only,
                no_replay_check=no_replay_check,
                allow_revoked_root=allow_revoked_root,
            )
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
    root_metadata: dict | None,
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


def _create_message_v22(
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
    root_metadata: dict,
    device_bound: bool,
    decoy_input: str | Path | None,
    decoy_password: str | None,
    low_signature: bool,
    signature_profile: str,
    carrier_profile: dict | None,
    envelope_policy: EnvelopePolicy | None,
) -> dict:
    if len(recipients) != 1:
        raise VeilError("crypto core v2.2 root-keypart mode currently supports exactly one recipient")
    if device_bound:
        raise VeilError("crypto core v2.2 root-keypart mode does not support device-bound password derivation")
    status = str(root_metadata.get("status") or "active")
    if status != "active":
        raise VeilError("root is not active for sealing")
    fmt = normalize_format(container_format, carrier_path or output_path)
    common_msg_id = secrets.token_bytes(16)
    builds = [
        _build_layer_v2(
            role="real",
            input_path=input_path,
            password=password,
            recipient=recipients[0],
            policy=policy,
            root_vkp_seed=root_vkp_seed,
            msg_id=common_msg_id,
            core_version=CRYPTO_CORE_VERSION_22,
        )
    ]
    if decoy_input:
        if not decoy_password:
            raise VeilError("decoy password is required when decoy input is used")
        builds.append(
            _build_layer_v2(
                role="decoy",
                input_path=decoy_input,
                password=decoy_password,
                recipient=recipients[0],
                policy=policy,
                root_vkp_seed=root_vkp_seed,
                msg_id=common_msg_id,
                core_version=CRYPTO_CORE_VERSION_22,
            )
        )
    package = _v22_package(
        builds,
        fmt,
        root_vkp_seed=root_vkp_seed,
        root_metadata=root_metadata,
        low_signature=low_signature,
        signature_profile=signature_profile,
    )
    carrier = carrier_bytes(fmt, carrier_path)
    embedded = embed_payload(
        carrier,
        _json_for_embedding(package, low_signature=low_signature),
        fmt,
        strategy=envelope_policy.embed_strategy if envelope_policy else None,
    )
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(embedded.data)
    validation = verify_container(output, fmt)
    if not validation["ok"]:
        raise VeilError(f"container verification failed for {fmt}")
    signature_scan = scan_fixed_signatures(output)
    if low_signature and signature_scan["found_plain_signatures"]:
        raise VeilError("low-signature output contains fixed plaintext signature")
    if auth_state_path and not low_signature:
        _write_auth_state(auth_state_path, [build.auth_record for build in builds])
    return {
        "output": str(output),
        "keypart": None,
        "auth_state": None if low_signature else str(auth_state_path),
        "format": fmt,
        "protocol_family": PROTOCOL_FAMILY,
        "crypto_core_version": CRYPTO_CORE_VERSION_22,
        "root_keypart": True,
        "external_keypart": False,
        "msg_id": b64e(common_msg_id),
        "receiver_id": builds[0].receiver_id,
        "root_epoch": int(root_metadata.get("root_epoch", 0)),
        "root_fingerprint": root_metadata.get("fingerprint"),
        "low_signature": low_signature,
        "signature_profile": signature_profile,
        "carrier_profile_used": bool(carrier_profile),
        "container_mode": embedded.mode,
        "container_validation": validation,
        "envelope_policy": envelope_policy.to_json() if envelope_policy else None,
        "fixed_signature_scan": signature_scan,
    }


def _receive_message_v22(
    *,
    input_path: str | Path,
    package: dict,
    root_vkp_seed: bytes,
    root_metadata: dict,
    seen_db_path: str | Path | None,
    output_dir: str | Path,
    identity: PrivateIdentity,
    password: str,
    verify_only: bool,
    no_replay_check: bool,
    allow_revoked_root: bool,
) -> dict:
    if str(root_metadata.get("status") or "active") == "revoked" and not allow_revoked_root:
        raise VeilDecryptError("Unable to open message.")
    entries = _v22_entries(package)
    last_error: Exception | None = None
    for entry in entries:
        try:
            inner = _decrypt_v22_metadata(entry, root_vkp_seed)
            if inner.get("protocol_family") != PROTOCOL_FAMILY or str(inner.get("crypto_core_version")) != CRYPTO_CORE_VERSION_22:
                raise ValueError("core mismatch")
            if inner.get("receiver_id") != identity.public.node_id:
                raise ValueError("receiver mismatch")
            expected_fp = root_metadata.get("fingerprint") or inner.get("root_fingerprint")
            if inner.get("root_fingerprint") != expected_fp:
                raise ValueError("root fingerprint mismatch")
            if int(inner.get("root_epoch", -1)) != int(root_metadata.get("root_epoch", inner.get("root_epoch", -2))):
                raise ValueError("root epoch mismatch")
            msg_id = b64d(inner["msg_id"])
            root_hint = _hint(str(inner["root_fingerprint"]), msg_id)
            receiver_hint = _hint(str(inner["receiver_id"]), msg_id)
            if not hmac.compare_digest(root_hint, str(entry.get("root_hint") or "")):
                raise ValueError("root hint mismatch")
            if not hmac.compare_digest(receiver_hint, str(entry.get("receiver_hint") or "")):
                raise ValueError("receiver hint mismatch")
            result = _open_v22_inner(
                input_path=input_path,
                inner=inner,
                root_vkp_seed=root_vkp_seed,
                output_dir=output_dir,
                identity=identity,
                password=password,
                verify_only=verify_only,
                seen_db_path=seen_db_path,
                no_replay_check=no_replay_check,
            )
            return result
        except Exception as exc:
            last_error = exc
            continue
    raise VeilDecryptError("Unable to open message.") from last_error


def _open_v22_inner(
    *,
    input_path: str | Path,
    inner: dict,
    root_vkp_seed: bytes,
    output_dir: str | Path,
    identity: PrivateIdentity,
    password: str,
    verify_only: bool,
    seen_db_path: str | Path | None,
    no_replay_check: bool,
) -> dict:
    msg_id = b64d(inner["msg_id"])
    message_salt = b64d(inner["message_salt"])
    file_hash = b64d(inner["file_hash"])
    receiver_id = inner["receiver_id"].encode("utf-8")
    vkp_i = derive_vkp_i(root_vkp_seed, msg_id, file_hash, receiver_id)
    message_key = derive_message_key_v2(vkp_i, password, message_salt, inner.get("kdf"))
    layer_id = inner["layer_id"]
    layer_salt = b64d(inner["layer_salt"])
    file_key = _unwrap_file_key(inner.get("envelopes", []), identity, layer_id)
    blob = b64d(inner["blob"])
    if b64e(sha256(blob)) != inner.get("payload_sha256"):
        raise ValueError("payload hash mismatch")
    manifest_len = int(inner["manifest_len"])
    manifest_ciphertext = blob[:manifest_len]
    chunk_payload = blob[manifest_len:]
    aad = canonical_json({"layer_id": layer_id, "role": inner.get("role", "real"), "v": 2, "core": CRYPTO_CORE_VERSION_22})
    manifest_key = subkey(message_key, file_key, "manifest-aes-256-gcm-v2", layer_salt)
    manifest_plain = aes_decrypt(manifest_key, b64d(inner["manifest_nonce"]), manifest_ciphertext, aad=aad)
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
            "protocol_family": PROTOCOL_FAMILY,
            "crypto_core_version": CRYPTO_CORE_VERSION_22,
            "role": manifest.get("role"),
            "archive_meta": manifest.get("archive_meta", {}),
            "replay_checked": not no_replay_check,
        }
    db_path = Path(seen_db_path) if seen_db_path else None
    if db_path and not no_replay_check:
        assert_not_seen(db_path, inner["msg_id"])
    written = _transactional_unpack(archive, output_dir)
    if db_path and not no_replay_check:
        mark_seen(
            db_path,
            msg_id=inner["msg_id"],
            receiver_id=inner["receiver_id"],
            root_fingerprint=inner["root_fingerprint"],
            root_epoch=int(inner["root_epoch"]),
            file_hash=inner["file_hash"],
            message_fingerprint=b64e(sha256(Path(input_path).read_bytes())),
        )
    return {
        "protocol_family": PROTOCOL_FAMILY,
        "crypto_core_version": CRYPTO_CORE_VERSION_22,
        "role": manifest.get("role"),
        "archive_meta": manifest.get("archive_meta", {}),
        "written": [str(p) for p in written],
    }


def _build_layer_v2(
    *,
    role: str,
    input_path: str | Path,
    password: str,
    recipient: PublicIdentity,
    policy: dict,
    root_vkp_seed: bytes,
    msg_id: bytes | None = None,
    core_version: str | None = None,
) -> V2LayerBuild:
    archive, archive_meta = pack_input(input_path)
    file_hash = sha256(archive)
    msg_id = msg_id or secrets.token_bytes(16)
    message_salt = secrets.token_bytes(16)
    receiver_id = recipient.node_id
    vkp_i = derive_vkp_i(root_vkp_seed, msg_id, file_hash, receiver_id.encode("utf-8"))
    pass_params = kdf_params(policy.get("kdf"))
    message_key = derive_message_key_v2(vkp_i, password, message_salt, pass_params)
    file_key = secrets.token_bytes(32)
    layer_id = random_b64(18)
    layer_salt = secrets.token_bytes(16)
    aad_fields = {"layer_id": layer_id, "role": role, "v": 2}
    if core_version:
        aad_fields["core"] = core_version
    aad = canonical_json(aad_fields)

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


def _v22_package(
    builds: list[V2LayerBuild],
    fmt: str,
    *,
    root_vkp_seed: bytes,
    root_metadata: dict,
    low_signature: bool,
    signature_profile: str,
) -> dict:
    entries = [
        _v22_outer_entry(
            build,
            fmt,
            root_vkp_seed=root_vkp_seed,
            root_metadata=root_metadata,
            low_signature=low_signature,
            signature_profile=signature_profile,
        )
        for build in builds
    ]
    package = {
        "protocol_family": PROTOCOL_FAMILY,
        "crypto_core_version": CRYPTO_CORE_VERSION_22,
        "metadata_schema_id": entries[0]["metadata_schema_id"],
        "encrypted_metadata_len": entries[0]["encrypted_metadata_len"],
        "encrypted_metadata_nonce": entries[0]["encrypted_metadata_nonce"],
        "encrypted_metadata_tag": entries[0]["encrypted_metadata_tag"],
        "encrypted_metadata": entries[0]["encrypted_metadata"],
        "root_hint": entries[0]["root_hint"],
        "receiver_hint": entries[0]["receiver_hint"],
    }
    if len(entries) > 1:
        package["entries"] = entries
    return _shuffle_dict(package) if low_signature else package


def _v22_outer_entry(
    build: V2LayerBuild,
    fmt: str,
    *,
    root_vkp_seed: bytes,
    root_metadata: dict,
    low_signature: bool,
    signature_profile: str,
) -> dict:
    root_fp = str(root_metadata.get("fingerprint") or "")
    root_epoch = int(root_metadata.get("root_epoch", 0))
    root_id = str(root_metadata.get("root_id") or root_fp)
    flags = {
        "decoy": build.role == "decoy",
        "decoy_pad": "match",
        "replay_protected": True,
        "low_signature": low_signature,
    }
    inner = {
        "protocol_family": PROTOCOL_FAMILY,
        "crypto_core_version": CRYPTO_CORE_VERSION_22,
        "msg_id": b64e(build.msg_id),
        "message_salt": b64e(build.message_salt),
        "file_hash": b64e(build.file_hash),
        "receiver_id": build.receiver_id,
        "root_id": root_id,
        "root_fingerprint": root_fp,
        "root_epoch": root_epoch,
        "created_at": int(time.time()),
        "kdf_id": "argon2id",
        "kdf": build.pass_params,
        "flags": flags,
        "role": build.role,
        "layer_id": build.layer_id,
        "layer_salt": b64e(build.layer_salt),
        "manifest_nonce": b64e(build.manifest_nonce),
        "manifest_len": build.manifest_len,
        "payload_sha256": b64e(sha256(build.blob)),
        "blob": b64e(build.blob),
        "envelopes": build.envelopes,
        "container_format": fmt,
        "signature_profile": signature_profile,
    }
    schema_id = random_b64(9)
    aad_fields = {
        "protocol_family": PROTOCOL_FAMILY,
        "crypto_core_version": CRYPTO_CORE_VERSION_22,
        "metadata_schema_id": schema_id,
        "root_hint": _hint(root_fp, build.msg_id),
        "receiver_hint": _hint(build.receiver_id, build.msg_id),
    }
    metadata_key = _v22_metadata_key(root_vkp_seed, schema_id)
    nonce, ciphertext = aes_encrypt(
        metadata_key,
        canonical_json(_shuffle_dict(inner) if low_signature else inner),
        aad=canonical_json(aad_fields),
    )
    return _shuffle_dict(
        {
            **aad_fields,
            "encrypted_metadata_len": len(ciphertext),
            "encrypted_metadata_nonce": b64e(nonce),
            "encrypted_metadata_tag": b64e(ciphertext[-16:]),
            "encrypted_metadata": b64e(ciphertext[:-16]),
        }
    ) if low_signature else {
        **aad_fields,
        "encrypted_metadata_len": len(ciphertext),
        "encrypted_metadata_nonce": b64e(nonce),
        "encrypted_metadata_tag": b64e(ciphertext[-16:]),
        "encrypted_metadata": b64e(ciphertext[:-16]),
    }


def _decrypt_v22_metadata(entry: dict, root_vkp_seed: bytes) -> dict:
    aad_fields = {
        "protocol_family": entry.get("protocol_family"),
        "crypto_core_version": entry.get("crypto_core_version"),
        "metadata_schema_id": entry.get("metadata_schema_id"),
        "root_hint": entry.get("root_hint"),
        "receiver_hint": entry.get("receiver_hint"),
    }
    metadata_key = _v22_metadata_key(root_vkp_seed, str(entry["metadata_schema_id"]))
    ciphertext = b64d(entry["encrypted_metadata"]) + b64d(entry["encrypted_metadata_tag"])
    if int(entry.get("encrypted_metadata_len", -1)) != len(ciphertext):
        raise ValueError("metadata length mismatch")
    plain = aes_decrypt(metadata_key, b64d(entry["encrypted_metadata_nonce"]), ciphertext, aad=canonical_json(aad_fields))
    return json.loads(plain.decode("utf-8"))


def _v22_metadata_key(root_vkp_seed: bytes, schema_id: str) -> bytes:
    return hkdf(root_vkp_seed, salt=schema_id.encode("utf-8"), info=b"veil-offline-envelope-metadata-core-v2.2")


def _hint(value: str, msg_id: bytes) -> str:
    return b64e(hmac.digest(value.encode("utf-8"), msg_id, "sha256")[:12])


def _v22_entries(package: dict) -> list[dict]:
    entries = package.get("entries")
    if isinstance(entries, list) and entries:
        return entries
    return [package]


def _json_for_embedding(package: dict, *, low_signature: bool) -> bytes:
    if low_signature:
        return json.dumps(_shuffle_dict(_v22_alias_package(package)), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return canonical_json(package)


def _shuffle_dict(data):
    if isinstance(data, dict):
        items = list(data.items())
        secrets.SystemRandom().shuffle(items)
        return {key: _shuffle_dict(value) for key, value in items}
    if isinstance(data, list):
        return [_shuffle_dict(value) for value in data]
    return data


def _extract_v2_package(path: str | Path, *, required: bool) -> dict | None:
    package22 = _extract_v22_package(path, required=False)
    if package22 is not None:
        return None
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


def _extract_v22_package(path: str | Path, *, required: bool) -> dict | None:
    raw = Path(path).read_bytes()
    markers = [
        f'"crypto_core_version":"{CRYPTO_CORE_VERSION_22}"'.encode("utf-8"),
        f'"protocol_family":"{PROTOCOL_FAMILY}"'.encode("utf-8"),
    ]
    starts = sorted({pos for marker in markers for pos in _find_all(raw, marker)})
    fallback: dict | None = None
    for marker_pos in starts:
        candidate = marker_pos
        while True:
            start = raw.rfind(b"{", 0, candidate + 1)
            if start < 0:
                break
            end = _json_object_end(raw, start)
            if end is None or end <= marker_pos:
                candidate = start - 1
                continue
            try:
                data = json.loads(raw[start:end].decode("utf-8"))
            except Exception:
                candidate = start - 1
                continue
            if data.get("protocol_family") == PROTOCOL_FAMILY and str(data.get("crypto_core_version")) == CRYPTO_CORE_VERSION_22:
                if isinstance(data.get("entries"), list):
                    return data
                fallback = fallback or data
            candidate = start - 1
    if fallback is not None:
        return fallback
    alias = _extract_v22_alias_package(raw)
    if alias is not None:
        return alias
    if required:
        raise VeilDecryptError("Unable to open message.")
    return None


def _v22_alias_package(package: dict) -> dict:
    def alias_entry(entry: dict) -> dict:
        return {
            "a": entry["metadata_schema_id"],
            "b": entry["encrypted_metadata_len"],
            "c": entry["encrypted_metadata_nonce"],
            "d": entry["encrypted_metadata_tag"],
            "e": entry["encrypted_metadata"],
            "f": entry["root_hint"],
            "g": entry["receiver_hint"],
        }

    aliased = alias_entry(package)
    entries = package.get("entries")
    if isinstance(entries, list) and entries:
        aliased["h"] = [alias_entry(entry) for entry in entries]
    return aliased


def _unalias_v22_entry(entry: dict) -> dict:
    return {
        "protocol_family": PROTOCOL_FAMILY,
        "crypto_core_version": CRYPTO_CORE_VERSION_22,
        "metadata_schema_id": entry["a"],
        "encrypted_metadata_len": int(entry["b"]),
        "encrypted_metadata_nonce": entry["c"],
        "encrypted_metadata_tag": entry["d"],
        "encrypted_metadata": entry["e"],
        "root_hint": entry["f"],
        "receiver_hint": entry["g"],
    }


def _extract_v22_alias_package(raw: bytes) -> dict | None:
    for start in _find_all(raw, b"{"):
        end = _json_object_end(raw, start)
        if end is None:
            continue
        try:
            data = json.loads(raw[start:end].decode("utf-8"))
        except Exception:
            continue
        if not _looks_like_v22_alias(data):
            continue
        package = _unalias_v22_entry(data)
        entries = data.get("h")
        if isinstance(entries, list) and entries:
            package["entries"] = [_unalias_v22_entry(entry) for entry in entries if _looks_like_v22_alias(entry)]
        return package
    return None


def _looks_like_v22_alias(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    required = {"a", "b", "c", "d", "e", "f", "g"}
    if not required.issubset(data.keys()):
        return False
    return all(isinstance(data[key], (str, int)) for key in required)


def _find_all(raw: bytes, marker: bytes) -> list[int]:
    out = []
    start = 0
    while True:
        pos = raw.find(marker, start)
        if pos < 0:
            return out
        out.append(pos)
        start = pos + len(marker)


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
    try:
        written = unpack_payload(archive, staging)
        if final.exists():
            raise VeilError("output directory changed during recovery")
        os.replace(staging, final)
        return [final / path.relative_to(staging) for path in written]
    except Exception:
        if staging.exists():
            import shutil

            shutil.rmtree(staging, ignore_errors=True)
        raise


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
