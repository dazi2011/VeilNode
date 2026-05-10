#!/usr/bin/env bash
# One-click debug APK builder for VeilNode Android.
# Requirements: JDK 17+ and Gradle on PATH; Android SDK at $ANDROID_HOME or
# ~/Library/Android/sdk (macOS) / ~/Android/Sdk (Linux).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PROJECT="$ROOT/clients/android"
DIST="${VEIL_APK_DIST:-$ROOT/dist/android}"
mkdir -p "$DIST"

if ! command -v gradle >/dev/null 2>&1; then
  echo "error: gradle not found on PATH" >&2
  exit 1
fi

if [ -z "${JAVA_HOME:-}" ]; then
  for candidate in \
    /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
    /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home \
    /usr/lib/jvm/temurin-21-jdk-amd64 \
    /usr/lib/jvm/temurin-17-jdk-amd64; do
    if [ -x "$candidate/bin/java" ]; then
      export JAVA_HOME="$candidate"
      break
    fi
  done
fi

if [ -z "${ANDROID_HOME:-}" ]; then
  for candidate in \
    "$HOME/Library/Android/sdk" \
    "$HOME/Android/Sdk"; do
    if [ -d "$candidate" ]; then
      export ANDROID_HOME="$candidate"
      export ANDROID_SDK_ROOT="$candidate"
      break
    fi
  done
fi

cd "$PROJECT"
gradle :app:assembleDebug --no-daemon --console=plain
APK="$PROJECT/app/build/outputs/apk/debug/app-debug.apk"
if [ ! -f "$APK" ]; then
  echo "error: gradle finished but app-debug.apk was not produced" >&2
  exit 1
fi
cp "$APK" "$DIST/VeilNode-Android-debug.apk"
echo "Built: $DIST/VeilNode-Android-debug.apk"
echo "Install: adb install -r \"$DIST/VeilNode-Android-debug.apk\""
