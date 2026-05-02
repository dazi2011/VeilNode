# VeilNode Suite

[中文说明](README.zh-CN.md)

Technical details live in [docs/TECHNICAL.md](docs/TECHNICAL.md). Platform client status lives in [docs/PLATFORMS.md](docs/PLATFORMS.md).

VeilNode Suite is an offline file-envelope toolset. It seals encrypted payloads into ordinary carrier files, verifies that the carrier still parses, and keeps the cryptographic core separate from carrier-format policy.

The current offline envelope core is `crypto_core_version = "2.2"`. That value is a message/core compatibility marker, not the VeilNode Suite package version. Legacy protocol v1/v2 readers remain compatible, but `crypto_core_version = "1.0"` is not a supported or selectable crypto core.

VeilNode does not claim that output is impossible to detect. Its language and scoring are deliberately narrower: low-signature engineering, metadata minimization, carrier fidelity checks, and local engineering risk scores.

## Core Boundary

The adaptive policy layer never invents cryptography. It must not change:

- `root_vkp`
- HKDF
- Argon2id
- AEAD
- `msg_id`
- `message_salt`
- `file_hash`
- root-derived `vkp_i` and `message_key` derivation

It may choose only envelope and carrier behavior: embedding strategy, chunk profile, padding profile, encrypted metadata layout, locator strategy, carrier placement, and candidate ranking.

## Install

```bash
python3 -m pip install -e .
veil-node --help
```

For local demos you can reduce KDF cost:

```bash
export VEIL_FAST_KDF=1
```

## Command Shape

The CLI is organized around nouns:

```text
veil-node identity ...
veil-node contact ...
veil-node keypart root ...
veil-node seal INPUT CARRIER OUTPUT ...
veil-node open MESSAGE --out DIR ...
veil-node carrier audit|compare|profile ...
veil-node strategy features|generate|select|score|collect|train|model|scan-signature ...
veil-node package --release --out dist/release
```

New tutorials should use `seal` / `open` and `strategy ...`; older ad-hoc examples should be treated as compatibility notes only.

## Adaptive Quick Start

```bash
mkdir -p .demo

veil-node --home .demo/alice identity create \
  --name alice \
  --password idpass \
  --overwrite

veil-node --home .demo/alice identity export \
  --out .demo/alice.vid

veil-node --home .demo/alice contact import \
  .demo/alice.vid \
  --alias alice

veil-node keypart root create \
  --out .demo/root.vkpseed \
  --password rootpass \
  --label alice-bob

echo "secret" > .demo/secret.txt

python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY

veil-node strategy features \
  --carrier .demo/cover.zip \
  --payload .demo/secret.txt \
  --json

veil-node strategy generate \
  --carrier .demo/cover.zip \
  --payload .demo/secret.txt \
  --count 20 \
  --json

veil-node strategy select \
  --carrier .demo/cover.zip \
  --payload .demo/secret.txt \
  --count 20 \
  --json

veil-node --home .demo/alice seal \
  .demo/secret.txt \
  .demo/cover.zip \
  .demo/message.zip \
  --to alice \
  --password msgpass \
  --root-keypart .demo/root.vkpseed \
  --root-keypart-password rootpass \
  --crypto-core 2.2 \
  --low-signature \
  --adaptive-policy \
  --policy-candidates 20 \
  --policy-out .demo/selected.policy.json

veil-node carrier audit \
  --input .demo/message.zip \
  --json

veil-node carrier compare \
  --before .demo/cover.zip \
  --after .demo/message.zip \
  --json

veil-node strategy scan-signature \
  --input .demo/message.zip \
  --json

veil-node --home .demo/alice open \
  .demo/message.zip \
  --root-keypart .demo/root.vkpseed \
  --root-keypart-password rootpass \
  --out .demo/out \
  --password msgpass \
  --identity-password idpass
```

All open failures default to:

```text
Unable to open message.
```

## Adaptive Envelope Policy Engine

The engine lives in `veil_core/strategy/`.

- `features.py`: extracts carrier and payload engineering features.
- `policy.py`: validates `EnvelopePolicy` and rejects secret-like fields.
- `registry.py`: lists legal strategy names and constraints.
- `generator.py`: creates candidate policies from features and capacity.
- `selector.py`: dry-runs candidates, verifies carriers, audits, compares, scores, and selects the lowest local engineering risk.
- `scorer.py`: scores size, entropy, structure, metadata, parser validity, payload ratio, and fixed plaintext signatures.
- `dataset.py`: writes secret-free JSONL training rows.
- `trainer.py` / `model.py`: train and inspect the portable heuristic ranker.

Policy, dataset, and model files must not contain root seeds, `root_vkp`, `vkp_i`, `message_key`, passwords, or private identity material. The model ranks policies; it never decides final output without local verify/audit/compare/score.

## Strategy Commands

```bash
veil-node strategy list --format zip
veil-node strategy policy inspect --in selected.policy.json
veil-node strategy score --before cover.zip --after message.zip --policy selected.policy.json --json
veil-node strategy collect --samples-dir samples --payloads-dir payloads --out dataset.jsonl --candidates-per-sample 30
veil-node strategy train --dataset dataset.jsonl --out model.json
veil-node strategy model inspect --in model.json
```

`--policy-in` uses a saved policy, but still validates the policy and carrier. `--policy-model` can rank candidates, but the verifier and scorer remain authoritative.

## Clients And Packaging

Release targets are macOS DMG, Windows ZIP, Android debug-signed APK when Android SDK/Gradle/JDK are available, and iOS/iPadOS IPA when a real Apple Developer account and provisioning profile are available. Linux and NAS GUI/web targets have been removed from release support; use the shared CLI on those systems.

Windows ZIP includes `VeilNodeGui.bat` plus `BuildExe.bat`, which can build a local `veil-node.exe` on a Windows host with PyInstaller. Built release artifacts belong in `dist/` or GitHub Releases, not in the source tree.

## Verification

```bash
python3 -m unittest discover -s tests -v
python3 -m veil_core doctor
python3 -m veil_core test-vector
```
