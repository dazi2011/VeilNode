#!/usr/bin/env bash
# One-click UNSIGNED IPA builder for VeilNode iOS / iPadOS.
# This produces a Payload/VeilNode.app .ipa with no code signature.
# It cannot be installed directly on a stock iOS device; use a sideload
# tool (AltStore, Sideloadly, etc.) to apply your own signature, or run on
# a jailbroken device. Use BuildIpa.sh for a properly signed IPA.
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

cd "$PROJECT"
xcodegen generate

DERIVED="$(mktemp -d)"
PAYLOAD="$(mktemp -d)"
trap 'rm -rf "$DERIVED" "$PAYLOAD"' EXIT

xcodebuild \
  -project VeilNodeiOS.xcodeproj \
  -scheme VeilNodeiOS \
  -configuration Release \
  -sdk iphoneos \
  -destination 'generic/platform=iOS' \
  -derivedDataPath "$DERIVED" \
  CODE_SIGNING_ALLOWED=NO \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  build

APP="$DERIVED/Build/Products/Release-iphoneos/VeilNode.app"
if [ ! -d "$APP" ]; then
  echo "error: xcodebuild finished but VeilNode.app was not produced" >&2
  exit 1
fi

mkdir -p "$PAYLOAD/Payload"
cp -R "$APP" "$PAYLOAD/Payload/VeilNode.app"
TARGET="$DIST/VeilNode-iOS-iPadOS-unsigned.ipa"
rm -f "$TARGET"
(cd "$PAYLOAD" && zip -qr "$TARGET" Payload)
echo "Built: $TARGET"
echo "Note: this IPA is unsigned. Sideload tools (AltStore, Sideloadly) or a"
echo "      jailbroken device are required to install on iOS hardware."
