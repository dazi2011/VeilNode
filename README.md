# VeilNode Suite

> Offline envelope encryption for ordinary carrier files.
> Suite **0.3.2** · crypto core **2.2** · 107 / 107 unit tests pass.

[中文文档](README.zh-CN.md) · [Technical notes](docs/TECHNICAL.md) · [Platform matrix](docs/PLATFORMS.md)

VeilNode Suite seals encrypted payloads inside ordinary-looking carrier files
(zip, png, mp4, pdf, wav, …), verifies that the carrier still parses, and keeps
the cryptographic core deliberately separate from carrier-format policy.
The Suite consists of:

- **`veil-core`** — Python implementation: crypto, message format, adaptive
  envelope policy, doctor, test vectors. The single source of truth.
- **CLI** — `veil-node`, `veil-factory` shipped from `veil-core`.
- **Desktop GUI** — native SwiftUI app on macOS, Tk wrapper on Windows.
- **Mobile companion apps** — native iOS / iPadOS (SwiftUI) and native
  Android (Java) apps. They are honest companions: they import, hash and
  preview carriers, and they hand you the matching CLI commands. They do not
  ship a Python crypto core and they never decrypt on-device.

VeilNode does not claim "undetectable". It uses the narrower engineering
language: low-signature, metadata minimization, carrier-fidelity checks, and
local engineering risk scores.

## Crypto core boundary

The adaptive policy layer never invents cryptography. The following are
**fixed by core** and cannot be modified by any policy or model:

`root_vkp` · HKDF · Argon2id · AEAD · `msg_id` · `message_salt` ·
`file_hash` · root-derived `vkp_i` and `message_key` derivation.

The policy layer can choose only envelope and carrier behaviour: embedding
strategy, chunk profile, padding profile, encrypted metadata layout, locator
strategy, carrier placement, and candidate ranking.

`crypto_core_version = "2.2"` is a message / core compatibility marker. It is
**not** the suite package version. v1 / v2 readers remain compatible;
`crypto_core_version = "1.0"` is no longer a selectable crypto core.

## Install

```bash
python3 -m pip install -e .
veil-node --help
veil-node doctor
```

For local demos you can speed up the KDF:

```bash
export VEIL_FAST_KDF=1
```

## Command shape

Verbs are organised around nouns:

```text
veil-node identity ...
veil-node contact ...
veil-node keypart root ...
veil-node seal INPUT CARRIER OUTPUT ...
veil-node open MESSAGE --out DIR ...
veil-node carrier audit | compare | profile ...
veil-node strategy features | generate | select | score | scan-signature ...
veil-node strategy collect | train | model | policy ...
veil-node package --release --out dist/release
```

New documentation uses `seal` / `open` / `strategy …`. Older ad-hoc usages
should be treated as compatibility notes.

## Adaptive envelope quick start

```bash
mkdir -p .demo

veil-node --home .demo/alice identity create \
  --name alice --password idpass --overwrite

veil-node --home .demo/alice identity export --out .demo/alice.vid
veil-node --home .demo/alice contact import .demo/alice.vid --alias alice

veil-node keypart root create \
  --out .demo/root.vkpseed --password rootpass --label alice-bob

echo "secret" > .demo/secret.txt
python3 - <<'PY'
import zipfile
with zipfile.ZipFile(".demo/cover.zip", "w") as zf:
    zf.writestr("readme.txt", "ordinary cover file\n")
PY

veil-node strategy select \
  --carrier .demo/cover.zip --payload .demo/secret.txt \
  --count 20 --json

veil-node --home .demo/alice seal \
  .demo/secret.txt .demo/cover.zip .demo/message.zip \
  --to alice --password msgpass \
  --root-keypart .demo/root.vkpseed --root-keypart-password rootpass \
  --crypto-core 2.2 --low-signature \
  --adaptive-policy --policy-candidates 20 \
  --policy-out .demo/selected.policy.json

veil-node carrier audit --input .demo/message.zip --json
veil-node carrier compare --before .demo/cover.zip --after .demo/message.zip --json
veil-node strategy scan-signature --input .demo/message.zip --json

veil-node --home .demo/alice open \
  .demo/message.zip --out .demo/out \
  --password msgpass --identity-password idpass \
  --root-keypart .demo/root.vkpseed --root-keypart-password rootpass
```

All open failures default to a single generic message:

```text
Unable to open message.
```

This is intentional — the CLI never tells the caller why a message could not
be opened, to avoid leaking key, padding or carrier signal.

## Adaptive Envelope Policy Engine

Lives in `veil_core/strategy/`:

| File | Role |
| --- | --- |
| `features.py` | Carrier and payload engineering features. |
| `policy.py` | Validates `EnvelopePolicy`. Rejects secret-like fields. |
| `registry.py` | Legal strategy names and constraints. |
| `generator.py` | Candidate policies from features and capacity. |
| `selector.py` | Dry-run, verify, audit, compare, score and select lowest local engineering risk. |
| `scorer.py` | Size, entropy, structure, metadata, parser validity, payload ratio, fixed plaintext signatures. |
| `dataset.py` | Secret-free JSONL training rows. |
| `trainer.py` / `model.py` | Train and inspect a portable heuristic ranker. |

Policies, datasets and models must not contain root seeds, `root_vkp`,
`vkp_i`, `message_key`, passwords or private identity material.
The model ranks policies; it never overrides verify / audit / compare / score.

```bash
veil-node strategy list --format zip
veil-node strategy policy inspect --in selected.policy.json
veil-node strategy score --before cover.zip --after message.zip \
  --policy selected.policy.json --json
veil-node strategy collect --samples-dir samples --payloads-dir payloads \
  --out dataset.jsonl --candidates-per-sample 30
veil-node strategy train --dataset dataset.jsonl --out model.json
veil-node strategy model inspect --in model.json
```

## Clients

| Platform | Path | Status | Built artifact |
| --- | --- | --- | --- |
| macOS | `clients/macos/` | Native SwiftUI desktop app, embeds `veil-core`. | `VeilNode-macOS.dmg` |
| Windows | `clients/windows/` | Tk desktop GUI + zipapp + `BuildExe.bat`. | `VeilNode-Windows.zip` |
| iOS / iPadOS | `clients/ios/` | SwiftUI companion app: import, SHA-256, copy CLI commands. | `VeilNode-iOS-iPadOS.ipa` (signed only) |
| Android | `clients/android/` | Native Java companion app: import, SHA-256, copy CLI commands. | `VeilNode-Android-debug.apk` |
| Linux | — | CLI only. | use `veil-node` |
| NAS | — | CLI only. | use `veil-node` |

Mobile companion apps are deliberately not crypto stacks. The Python core
cannot be safely embedded on iOS without major work, so the apps focus on
what they *can* do well: import via Files / SAF, hash via system crypto,
display the matching CLI commands.

## One-click build helpers

The release bundle ships every helper for every host:

| Script | Builds | Requires |
| --- | --- | --- |
| `clients/windows/BuildExe.bat` | `veil-node.exe` | Windows host, Python, PyInstaller |
| `clients/android/BuildApk.sh` | `VeilNode-Android-debug.apk` | macOS / Linux host, JDK 17+, Gradle, Android SDK |
| `clients/android/BuildApk.bat` | `VeilNode-Android-debug.apk` | Windows host, JDK 17+, Gradle, Android SDK |
| `clients/ios/BuildIpa.sh` | `VeilNode-iOS-iPadOS.ipa` | macOS host, Xcode, `xcodegen`, `VEILNODE_DEVELOPMENT_TEAM` |

All helpers operate on the source tree in place, so unzipping
`VeilNode-Windows.zip` (or cloning this repo) and calling the appropriate
script produces the binary.

## Release packaging

```bash
veil-node package --release --out dist/release
```

The release manifest reports built and blocked artifacts:

- `VeilNode-macOS.dmg` — built when SwiftPM and `hdiutil` are available.
- `VeilNode-Windows.zip` — portable cross-platform bundle (GUI + zipapp +
  every `Build*` helper + the source tree, so any platform's `Build*` script
  can run from inside it).
- `VeilNode-Android-debug.apk` — debug-signed APK when JDK + Gradle +
  Android SDK are available.
- `VeilNode-iOS-iPadOS.ipa` — built only when
  `VEILNODE_DEVELOPMENT_TEAM` is set and Xcode can create or use a
  provisioning profile. We never fabricate unsigned IPAs.

Built release artifacts belong in `dist/` or GitHub Releases — never in the
source tree. `.gitignore` already excludes them.

## Verification

```bash
python3 -m unittest discover -s tests -v   # 107 tests
python3 -m veil_core doctor
python3 -m veil_core test-vector
```
