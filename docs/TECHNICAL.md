# VeilNode Technical Notes

VeilNode Suite is organized around one shared core: `veil-core` (`veil_core/` in this Python implementation).
Every client should call this core instead of reimplementing cryptography per platform.

## Naming

- Project: `VeilNode`
- Suite: `VeilNode Suite`
- Core library: `veil-core`
- Factory: `veil-factory`
- CLI node client: `veil-node`
- GUI client: `veil-gui`
- Message protocol: `veil-msg`
- Internal message envelope: `.vmsg`
- Identity file: `.vid`
- Keypart file: `.vkp`
- Root keypart seed: `.vkpseed`
- Node package: `.vpkg`

The repository slogan is:

```text
VeilNode — encrypted files disguised as ordinary data.
```

## Core Layers

- `crypto`: Argon2id, HKDF, AES-GCM, XChaCha20-Poly1305 compatibility layer, hashes and encodings.
- `compression`: archive pack/unpack boundary.
- `chunks`: payload splitting, key-derived shuffle and reassembly.
- `padding`: random and bucket padding.
- `container`: carrier generation, embedding, extraction, verification and capacity reporting.
- `identity`: local node identity and `.vid` public identity handling.
- `contacts`: contact import/list/show/remove.
- `message`: `veil-msg` construction and transactional recovery.
- `nodepkg`: `.vpkg` export/import/inspect.
- `protocol`: version and compatibility checks.
- `profile`: `dev`, `balanced`, `hardened` security levels.
- `platform`: `SecureStore`, `DeviceBinding`, `FileProvider` interface boundaries.
- `diagnostics`: doctor, audit and platform reports.
- `api`: `VeilAPI` facade for CLI, GUI and future mobile bindings.

## File Formats

### `.vid` Veil Identity

Public identity file. It contains node id, name, public key, creation timestamp and format kind. It does not contain a private key.

Current portable private identity storage remains local under the node home directory as encrypted JSON. Production platform clients should move private material through the relevant `SecureStore`.

### `.vkp` Veil Keypart

Protocol v1 per-message keypart file. It contains sealed records, protocol metadata, carrier validation and integrity hashes. It is not a complete key by itself.

Decrypting requires:

- message carrier,
- `.vkp`,
- auth state,
- message password,
- recipient private identity,
- matching protocol/profile logic,
- optional device binding material.

### `.vkpseed` Veil Root Keypart Seed

Protocol v2 long-term offline root seed. It is encrypted with the same Argon2id + AES-GCM password-protection pattern used for local secret material. `inspect` exposes only kind, version, creation time, KDF parameters and fingerprint; the seed is never printed.

For each v2 message:

```text
vkp_i = HKDF(root_vkp, salt=msg_id, info="veil-vkp-v2" || file_hash || receiver_id)
password_key = Argon2id(password, salt=message_salt, profile_params)
message_key = HKDF(vkp_i || password_key, salt=message_salt, info="veil-message-key-v2")
```

`msg_id` and `message_salt` are random per message. `root_vkp`, `vkp_i` and `message_key` are not written to the carrier. v2 currently embeds public recovery metadata in the carrier so a receiver can derive `vkp_i` without a per-message `.vkp`.

### `.vpkg` Veil Node Package

Node package for fixed clients. It contains public identity, encrypted private identity material, profile, contacts, adapter list and integrity tag.

Desktop clients can either generate dedicated wrappers or import `.vpkg`; mobile/NAS clients should prefer fixed client + `.vpkg`.

## Transactional Auth

The receive path is intentionally conservative:

1. Read auth state.
2. Decrypt the v1 keypart record or derive the v2 message key from `.vkpseed`.
3. Recover file key.
4. Extract payload.
5. Decrypt manifest and content.
6. Verify archive hash.
7. Write output into a staging directory.
8. Commit staging output atomically.
9. Consume auth state only after success.

`verify-only` stops before output commit and auth consumption.

## Container Adapters

Current stable adapters:

- ZIP stored member.
- PDF incremental stream object.
- MP4 `free` box.
- PNG ancillary chunk.
- WAV unknown RIFF chunk.
- BMP/7z tail append compatibility path.
- `.vmsg` opaque internal envelope. This is a Veil exchange format, not a disguise carrier.

The first production-hardening target should prioritize ZIP/PDF/MP4/PNG and avoid JPEG as a core carrier because lossy recompression can destroy hidden payloads.

## Test Vectors

`veil-node test-vector` verifies the stable XChaCha20-Poly1305 compatibility vector and the v2 root-keypart derivation vector:

```bash
veil-node test-vector
```

This is intended to become the cross-platform regression anchor for future Rust/Swift/Kotlin/WASM bindings.
