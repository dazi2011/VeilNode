# VeilNode Suite

[中文说明](README.zh-CN.md)

Technical details live in [docs/TECHNICAL.md](docs/TECHNICAL.md). Platform client status lives in [docs/PLATFORMS.md](docs/PLATFORMS.md).

VeilNode Suite is an offline multi-platform toolset for encrypted files disguised as ordinary data.
It contains:

- `veil-factory`: generates node wrappers and node policy files.
- `veil-node`: creates/imports identities, manages contacts, seals files into carriers and opens messages.
- `veil-msg`: a normal-looking carrier file plus either a v1 per-message `.vkp` keypart or v2 root-derived keypart metadata, with one-time auth state.

This implementation is intentionally offline. It does not call a server and does not require a network path for identity exchange.

## Install / Run

From this repository:

```bash
python3 -m veil_core --help
```

Install required packages with:

```bash
python3 -m veil_core --install-deps
```

You can also check without installing:

```bash
python3 -m veil_core --check-deps
```

For fully automatic dependency repair before a normal command:

```bash
VEIL_AUTO_INSTALL=1 python3 -m veil_core --help
```

Optional editable install:

```bash
python3 -m pip install -e .
veil-node --help
veil-factory --help
```

## Quick Start

The examples below assume the editable install above. If you do not install the package, replace `veil-node` with `python3 -m veil_core`.

```bash
export VEIL_FAST_KDF=1  # optional speed mode for local demos
mkdir -p .demo

veil-node --home .demo/alice identity create --name alice --password idpass --overwrite
veil-node --home .demo/alice identity export --out .demo/alice.vid
veil-node --home .demo/alice contact import .demo/alice.vid --alias alice

echo "secret" > .demo/secret.txt
python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY

veil-node --home .demo/alice seal \
  .demo/secret.txt \
  .demo/cover.zip \
  .demo/message.zip \
  --to alice \
  --password msgpass

veil-node --home .demo/alice open \
  .demo/message.zip \
  --keypart .demo/message.vkp \
  --out .demo/out \
  --password msgpass \
  --identity-password idpass
```

The same `auth-state` record is consumed after successful recovery, so a replay with the same files fails generically.

The generated files are:

```text
.demo/message.zip    # normal ZIP carrier
.demo/message.vkp    # Veil keypart, not a full key
.demo/message.vauth  # one-time auth state
```

## Offline Root Keypart Mode (v2)

Protocol v1 keeps the payload locator and recovery metadata in a per-message `.vkp`. Protocol v2 adds a long-term offline `root_vkp` seed: exchange it once through a separate secure channel, then each message derives its own in-memory `vkp_i` from `root_vkp + msg_id + message_salt + file_hash + receiver_id`. The generated carrier still needs the message password, recipient private identity and `.vauth`; it does not create a per-message `.vkp`.

Do not send the root keypart seed next to the carrier. If a root seed is exposed, rotate it and stop using old messages derived from that seed.

```bash
mkdir -p .demo

veil-node --home .demo/alice identity create --name alice --password idpass --overwrite
veil-node --home .demo/alice identity export --out .demo/alice.vid
veil-node --home .demo/alice contact import .demo/alice.vid --alias alice

veil-node keypart root create \
  --out .demo/alice_bob.root.vkpseed \
  --password rootpass

echo "secret" > .demo/secret.txt
python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY

veil-node --home .demo/alice seal \
  .demo/secret.txt \
  .demo/cover.zip \
  .demo/message.zip \
  --to alice \
  --password msgpass \
  --root-keypart .demo/alice_bob.root.vkpseed \
  --root-keypart-password rootpass \
  --no-external-keypart

veil-node --home .demo/alice open \
  .demo/message.zip \
  --root-keypart .demo/alice_bob.root.vkpseed \
  --root-keypart-password rootpass \
  --out .demo/out \
  --password msgpass \
  --identity-password idpass
```

Root keypart management:

```bash
veil-node keypart root inspect --in .demo/alice_bob.root.vkpseed
veil-node keypart root rotate --in old.vkpseed --out new.vkpseed --password rootpass
veil-node keypart root export-qr --in root.vkpseed --out root.txt --password rootpass
veil-node keypart root import --in root.txt --out imported.vkpseed --password rootpass
```

## Usage Guide

Identity and contacts:

```bash
veil-node --home ~/.veilnode/alice identity create --name alice --password idpass --overwrite
veil-node --home ~/.veilnode/alice identity export --out alice.vid
veil-node --home ~/.veilnode/alice identity import --in bob.vid --alias bob
veil-node --home ~/.veilnode/alice identity list
veil-node --home ~/.veilnode/alice identity health --identity-password idpass
veil-node --home ~/.veilnode/alice contact import bob.vid --alias bob
veil-node --home ~/.veilnode/alice contact list
veil-node --home ~/.veilnode/alice contact show --alias bob
```

Seal/open modes:

```bash
# v1: outputs message.vkp and message.vauth
veil-node --home ~/.veilnode/alice seal secret.zip cover.mp4 message.mp4 --to bob --password msgpass
veil-node --home ~/.veilnode/bob open message.mp4 --keypart message.vkp --out restored --password msgpass --identity-password idpass

# v2: reuses pre-shared root.vkpseed and does not output message.vkp
veil-node --home ~/.veilnode/alice seal secret.zip cover.mp4 message.mp4 --to bob --password msgpass \
  --root-keypart root.vkpseed --root-keypart-password rootpass --no-external-keypart
veil-node --home ~/.veilnode/bob open message.mp4 --root-keypart root.vkpseed --root-keypart-password rootpass \
  --out restored --password msgpass --identity-password idpass
```

Engineering and maintenance:

```bash
veil-node doctor
veil-node audit
veil-node capacity --carrier cover.zip --payload-size 1048576
veil-node verify-carrier --input message.zip --format zip
veil-node verify-only --input message.zip --keypart message.vkp --auth-state message.vauth --password msgpass --identity-password idpass
veil-node verify-only --input message.zip --root-keypart root.vkpseed --root-keypart-password rootpass --auth-state message.vauth --password msgpass --identity-password idpass
veil-node repair keypart --keypart message.vkp
veil-node migrate keypart --keypart message.vkp --out message.v1.vkp
veil-node profile levels
veil-node profile create --out hardened.profile.json --level hardened
veil-node nodepkg export --out alice.vpkg
veil-node package --out dist/veilnode.pyz
veil-node test-vector
veil-node secure-delete --path message.vkp --dry-run
```

Desktop and mobile client packages are provided for macOS, Windows, Linux, iOS/iPadOS and Android. macOS, Windows and Linux expose the shared seal/open flows through desktop GUI clients; iOS/iPadOS and Android ship native mobile client sources aligned around `.vpkg`, `.vid`, `.vkpseed` and shared-core workflows.

Export a fixed-client node package:

```bash
veil-node --home .demo/alice nodepkg export --out .demo/alice.vpkg
veil-node nodepkg inspect --in .demo/alice.vpkg
```

## Factory

Generate a node with its own command name, profile, aliases, chunk size, padding strategy and container allow-list:

```bash
veil-factory create-node \
  --name shade \
  --out-dir nodes \
  --chunk-size 32768 \
  --padding bucket \
  --bucket-size 65536 \
  --containers png,bmp,wav,mp4,zip,pdf,7z,vmsg \
  --param-style mixed \
  --init-identity-password idpass

./nodes/shade identity list
```

## Engineering Commands

Self-check the local runtime, protocol support, crypto backend and external tools:

```bash
veil-node doctor
```

Audit local identity/contact posture and private-file permissions:

```bash
veil-node --home .demo/alice audit
veil-node --home .demo/alice identity health --identity-password idpass
```

Create and inspect security profiles:

```bash
veil-node profile levels
veil-node profile create --out .demo/hardened.profile.json --name alice --level hardened
veil-node --profile .demo/hardened.profile.json profile show
```

Estimate a carrier strategy before sending:

```bash
veil-node capacity --format png --payload-size 1048576
veil-node capacity --carrier cover.pdf --payload-size 1048576
```

Verify a produced carrier still parses/opens according to local tools:

```bash
veil-node verify-carrier --input .demo/message.zip --format zip
```

Pre-verify a message without writing output and without consuming one-time auth:

```bash
veil-node --home .demo/alice verify-only \
  --input .demo/message.zip \
  --keypart .demo/message.vkp \
  --auth-state .demo/message.vauth \
  --password msgpass \
  --identity-password idpass
```

Repair or migrate metadata into a new artifact:

```bash
veil-node repair keypart --keypart .demo/message.vkp
veil-node migrate keypart --keypart .demo/message.vkp --out .demo/message.v1.vkp
veil-node repair scan --dir .demo
```

Manage contacts independently from identity commands:

```bash
veil-node --home .demo/alice contact import .demo/alice.vid --alias alice
veil-node --home .demo/alice contact list
veil-node --home .demo/alice contact show --alias alice
```

Build a portable Python zipapp:

```bash
veil-node package --out dist/veilnode.pyz
python3 dist/veilnode.pyz --help
```

Run stable crypto regression vectors:

```bash
veil-node test-vector
```

Safe deletion is deliberately explicit:

```bash
veil-node secure-delete --path .demo/message.vkp --dry-run
veil-node secure-delete --path .demo/message.vkp --yes --confirm-text DELETE
```

## Implemented Security Properties

- Stable protocol metadata: `veil-msg` protocol v1 and v2 with reader compatibility checks.
- Profile metadata with `dev`, `balanced` and `hardened` levels.
- Argon2id password derivation with configurable memory, iterations and lanes.
- HKDF subkeys for content encryption, manifest encryption, chunk shuffling, keypart sealing, auth state and file-key wrapping.
- Per-message random `file_key`.
- Protocol v2 offline root keypart mode: password-protected `.vkpseed`, per-message random `msg_id` and `message_salt`, HKDF-derived in-memory `vkp_i`, and no per-message `.vkp` output.
- XChaCha20-Poly1305 content encryption using an internal HChaCha20 step plus `cryptography`'s ChaCha20-Poly1305 AEAD.
- AES-256-GCM outer content encryption and encrypted manifest.
- X25519 recipient public-key file-key wrapping.
- Multi-recipient envelopes.
- Private identity stored locally, encrypted with the identity password.
- Keypart material is password-sealed and is not a complete decryption key by itself. In v2, the root seed must still be combined with message password, recipient identity and auth state.
- Offline one-time `auth_state`; successful recovery removes the matching auth record.
- Optional device binding through `--device-bind`.
- Decoy layer support with `--decoy-input` and `--decoy-password`.
- Failure-no-feedback receive path: wrong password, wrong keypart/root seed, wrong private key, used auth state, damaged manifest and damaged payload all return a generic failure.
- Payload chunking, deterministic key-derived shuffle, random gaps and random/bucket padding.
- Carrier support: PNG, BMP, WAV, MP4, ZIP, PDF, 7z and `.vmsg` internal envelopes.
- Transactional receive path: auth state is consumed only after decryption, hash verification and output commit succeed.
- Carrier verification after send with validation metadata saved in keypart for v1 or returned in the v2 seal report.
- Redaction helpers for logs and diagnostics.

## Library Architecture

The CLI is backed by a layered Python package:

- `crypto`: KDF, HKDF, AEAD and key utilities.
- `compression`: input archive packing/unpacking.
- `chunks`: split, shuffle and reassembly.
- `padding`: random and bucket padding strategies.
- `container` / `adapter`: carrier generation, embedding, extraction, capacity and verification.
- `message`: `veil-msg` construction and transactional recovery.
- `identity` / `contacts`: local identity and recipient contact management.
- `profile`: safety profiles and protocol-linked configuration.
- `protocol`: version, compatibility and suite metadata.
- `diagnostics`: doctor, audit, capacity and carrier checks.
- `repair`: recovery scans and metadata migration.
- `api`: a `VeilAPI` facade for CLI, GUI, mobile and NAS bindings.

## Carrier Notes

In v1, the carrier file does not contain a fixed VeilNode magic header and payload location is stored in the password-sealed keypart. In v2 root-keypart mode, the carrier contains public per-message recovery metadata (`msg_id`, `message_salt`, `file_hash`, `receiver_id` and encrypted payload package) so the receiver can derive `vkp_i` without a `.vkp`; it never contains `root_vkp`, `vkp_i` or `message_key`.

Embedding strategies:

- PNG: random legal ancillary chunk.
- WAV: random unknown RIFF chunk.
- MP4: normal `free` box.
- ZIP: stored member with random name, so ZIP remains valid even for large payloads.
- PDF: incremental stream object update.
- BMP and 7z: tail append, which common readers tolerate.
- vmsg: opaque internal envelope for cross-platform exchange and regression tests.

MP4 generation integrates with `ffmpeg`. 7z carrier generation integrates with the `7z` command.

## Security Model

VeilNode combines offline operation, authenticated encryption, public-key file-key wrapping, password-derived key material, per-message auth state and container-preserving adapters. It is designed for private file exchange where the carrier should continue to behave like ordinary data while recovery remains gated by multiple independent materials.

- v1 keeps locator metadata outside the carrier in the password-sealed `.vkp`.
- v2 replaces per-message `.vkp` transfer with a password-protected `.vkpseed` and per-message HKDF derivation.
- `.vkpseed`, identity passwords, auth state and carrier files should travel through separate channels where practical.
- Root keypart seeds are long-lived shared material; rotate them as part of routine key hygiene.
- Secure Enclave, TPM, YubiKey and OS Keychain integrations are represented in the platform adapter model, while the portable release path uses password-protected local identity storage plus optional local device binding.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Regression coverage:

- PNG encrypt/decrypt round trip.
- One-time auth replay failure.
- Decoy password recovery.
- Multi-recipient recovery.
- All supported carrier formats remain extractable/openable locally.
- Factory-generated node wrapper and profile.
- Protocol metadata and keypart validation.
- v2 root keypart creation, v2 seal/open, wrong root seed, wrong password, auth replay, v1/v2 compatibility hints and repeated-message uniqueness.
- Doctor, audit, profile, contact, capacity, verify-only, verify-carrier, repair, migrate, package and test-vector commands.
- Unified `VeilAPI` facade.

`secure-delete` uses explicit runtime confirmation; automated coverage includes refusal and dry-run paths.
