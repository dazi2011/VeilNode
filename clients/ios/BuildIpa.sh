#!/usr/bin/env bash
# One-click signed IPA builder for VeilNode iOS / iPadOS.
# Requirements: macOS host with Xcode, xcodegen on PATH, and a real Apple
# Developer account configured in Xcode. Set VEILNODE_DEVELOPMENT_TEAM to the
# 10-character Apple Team ID; without it Xcode cannot create a provisioning
# profile and this script will refuse to fabricate an unsigned IPA.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PROJECT="$ROOT/clients/ios"
DIST="${VEIL_IPA_DIST:-$ROOT/dist/ios}"
mkdir -p "$DIST"

if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "error: xcodebuild not found on PATH (run on a macOS host with Xcode)" >&2
  exit 1
fi
if ! command -v xcodegen >/dev/null 2>&1; then
  echo "error: xcodegen not found on PATH (brew install xcodegen)" >&2
  exit 1
fi

TEAM="${VEILNODE_DEVELOPMENT_TEAM:-${DEVELOPMENT_TEAM:-}}"
if [ -z "$TEAM" ]; then
  echo "error: set VEILNODE_DEVELOPMENT_TEAM to your Apple Developer Team ID" >&2
  echo "       this script will not produce an unsigned or fake IPA" >&2
  exit 1
fi

cd "$PROJECT"
xcodegen generate

DERIVED="$(mktemp -d)"
trap 'rm -rf "$DERIVED"' EXIT

xcodebuild \
  -project VeilNodeiOS.xcodeproj \
  -scheme VeilNodeiOS \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -derivedDataPath "$DERIVED" \
  -allowProvisioningUpdates \
  CODE_SIGN_STYLE=Automatic \
  DEVELOPMENT_TEAM="$TEAM" \
  build

APP="$DERIVED/Build/Products/Release-iphoneos/VeilNode.app"
if [ ! -d "$APP" ]; then
  echo "error: xcodebuild finished but VeilNode.app was not produced" >&2
  exit 1
fi

PAYLOAD="$(mktemp -d)"
trap 'rm -rf "$DERIVED" "$PAYLOAD"' EXIT
mkdir -p "$PAYLOAD/Payload"
cp -R "$APP" "$PAYLOAD/Payload/VeilNode.app"
TARGET="$DIST/VeilNode-iOS-iPadOS.ipa"
rm -f "$TARGET"
(cd "$PAYLOAD" && zip -qr "$TARGET" Payload)
echo "Built: $TARGET"
echo "Install (Apple Configurator or Xcode Devices)."
