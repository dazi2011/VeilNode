from __future__ import annotations

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .crypto import FAST_KDF, _xchacha20_subkey_and_nonce, b64e, derive_message_key_v2, derive_vkp_i, sha256
from .protocol import current_protocol, protocol_v2


VECTOR = {
    "name": "veil-xchacha20poly1305-v1",
    "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "nonce_hex": "000102030405060708090a0b0c0d0e0f1011121314151617",
    "aad": "veil-vector-v1",
    "plaintext": "Veil test vector",
    "expected_sha256_b64": "exsSIWRZx1sHfvT1YALeRPDwweeNq4ioZMgNkadMLNo",
}

VECTOR_V2 = {
    "name": "veil-root-vkp-derivation-v2",
    "expected_vkp_i_b64": "fsN9K9wATIYLTz2QOIhBP8fXzjIK-_W8-rwle47NtxI",
    "expected_message_key_b64": "i4daYhBlXtQxe42JGmlDNqanfXpp6EWv6YbXVXr9hoY",
}


def run_vectors() -> dict:
    key = bytes.fromhex(VECTOR["key_hex"])
    nonce = bytes.fromhex(VECTOR["nonce_hex"])
    aad = VECTOR["aad"].encode("utf-8")
    plaintext = VECTOR["plaintext"].encode("utf-8")
    sub_key, nonce12 = _xchacha20_subkey_and_nonce(key, nonce)
    ciphertext = ChaCha20Poly1305(sub_key).encrypt(nonce12, plaintext, aad)
    digest = b64e(sha256(ciphertext))
    expected = VECTOR["expected_sha256_b64"] or digest
    root_vkp = bytes(range(32))
    msg_id = bytes(range(16))
    file_hash = sha256(b"veil-v2-vector-payload")
    receiver_id = b"receiver-node-fingerprint"
    vkp_i = derive_vkp_i(root_vkp, msg_id, file_hash, receiver_id)
    message_key = derive_message_key_v2(vkp_i, "vector-pass", b"\x10" * 16, FAST_KDF)
    v2_ok = (
        b64e(vkp_i) == VECTOR_V2["expected_vkp_i_b64"]
        and b64e(message_key) == VECTOR_V2["expected_message_key_b64"]
    )
    return {
        "ok": digest == expected and v2_ok,
        "protocol": current_protocol(),
        "vectors": [
            {
                "name": VECTOR["name"],
                "ciphertext_sha256": digest,
                "expected_sha256": expected,
                "ciphertext_len": len(ciphertext),
            },
            {
                "name": VECTOR_V2["name"],
                "protocol": protocol_v2(),
                "vkp_i": b64e(vkp_i),
                "expected_vkp_i": VECTOR_V2["expected_vkp_i_b64"],
                "message_key": b64e(message_key),
                "expected_message_key": VECTOR_V2["expected_message_key_b64"],
                "ok": v2_ok,
            }
        ],
    }
