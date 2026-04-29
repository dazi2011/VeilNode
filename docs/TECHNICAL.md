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

The repository description is:

```text
VeilNode — offline envelope encryption for ordinary carrier files in high-review-pressure environments.
```

This is an engineering goal, not an absolute security guarantee. The project uses the terms low-signature, metadata minimization, local privacy hygiene and engineering risk score. It does not claim absolute non-identifiability or immunity to investigation.

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
- `api`: `VeilAPI` facade for CLI, GUI, mobile and NAS bindings.

## File Formats

### `.vid` Veil Identity

Public identity file. It contains node id, name, public key, creation timestamp and format kind. It does not contain a private key.

Portable private identity storage lives under the node home directory as encrypted JSON. Platform clients connect this boundary to the relevant `SecureStore`.

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

`msg_id` and `message_salt` are random per message. `root_vkp`, `vkp_i` and `message_key` are not written to the carrier. v2 embeds the public recovery metadata needed for the receiver to derive `vkp_i` without a per-message `.vkp`.

### Offline Envelope Crypto Core v2.2

`crypto_core_version = "2.2"` is the offline envelope crypto core version. It is independent from the VeilNode Suite package version and from `root_file_version`.

Root file v2 public metadata:

```json
{
  "type": "veil-root-vkpseed",
  "root_file_version": 2,
  "root_id": "stable random id",
  "root_epoch": 0,
  "created_at": 0,
  "rotated_at": null,
  "valid_from": null,
  "valid_until": null,
  "status": "active",
  "fingerprint": "...",
  "prev_fingerprint": null,
  "seal_params": {},
  "seed_encrypted": "...",
  "metadata_mac": "..."
}
```

The seed is encrypted at rest. `metadata_mac` is checked after decrypting the root so tampering with epoch, status or fingerprint is rejected. `inspect` never prints the seed.

v2.2 message outer metadata keeps only recovery hints and encrypted metadata fields:

```json
{
  "protocol_family": "veil-offline-envelope",
  "crypto_core_version": "2.2",
  "metadata_schema_id": "...",
  "encrypted_metadata_len": 0,
  "encrypted_metadata_nonce": "...",
  "encrypted_metadata_tag": "...",
  "root_hint": "...",
  "receiver_hint": "..."
}
```

Inner encrypted metadata includes `msg_id`, `message_salt`, `file_hash`, `receiver_id`, `root_id`, `root_fingerprint`, `root_epoch`, KDF parameters, flags and encrypted payload recovery data. It must not contain `root_vkp`, `vkp_i` or `message_key`.

Root lifecycle:

- `active`: may seal and open.
- `retired`: may open historical messages; does not seal by default.
- `revoked`: does not seal or open by default. `open --allow-revoked-root` is an explicit local recovery override.

Rotation derives a new root with HKDF using `info = b"veil-root-rotate-core-v2.2"`, increments `root_epoch` and records `prev_fingerprint`. Old roots are not deleted because old messages may require them.

Replay protection uses SQLite at `<home>/state/msg_seen.db`. v2.2 writes a seen record only after decryption, hash verification and output commit succeed. `--no-replay-check` exists for tests and local debugging only.

Shamir backup uses GF(256) threshold shares. A single share does not reveal the root seed; fewer than threshold shares fail recovery; mixed-root shares fail metadata and checksum validation.

Decoy mode stores independently authenticated real and decoy payload layers in one carrier. Correct real credentials open the real payload; correct decoy credentials open the decoy payload; other errors use the same generic failure path. This is coercion-resistance assistance, not perfect deniable encryption.

Low-signature mode is explicit (`--low-signature`) and supports conservative, balanced and aggressive profiles. It randomizes metadata ordering and carrier labels where supported and avoids fixed plaintext strings such as `VeilNode`, `veil-msg`, `root_vkp`, `vkp_i` and `message_key` in v2.2 low-signature carriers.

Carrier audit/compare/profile commands produce local engineering risk scores. They do not prove that a carrier is safe or impossible to classify as unusual.

### `.vpkg` Veil Node Package

Node package for fixed clients. It contains public identity, encrypted private identity material, profile, contacts, adapter list and integrity tag.

Desktop and mobile clients use `.vpkg` as the portable node package model. Linux and NAS GUI clients are no longer release targets; use the CLI on those systems.

## Transactional Auth

The receive path is transactional:

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

Stable adapters:

- ZIP stored member.
- PDF incremental stream object.
- MP4 `free` box.
- PNG ancillary chunk.
- WAV unknown RIFF chunk.
- BMP/7z tail append compatibility path.
- `.vmsg` opaque internal envelope for direct Veil exchange.

ZIP/PDF/MP4/PNG are the primary carrier set for dependable cross-platform exchange. JPEG is handled as an input payload rather than a core carrier because lossy recompression changes bytes by design.

## Test Vectors

`veil-node test-vector` verifies the stable XChaCha20-Poly1305 compatibility vector and the v2 root-keypart derivation vector:

```bash
veil-node test-vector
```

This vector set is the cross-platform regression anchor for Rust, Swift, Kotlin and WASM bindings.
