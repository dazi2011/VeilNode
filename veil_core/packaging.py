from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
import zipapp
from pathlib import Path


def build_zipapp(out: str | Path) -> dict:
    root = Path(__file__).resolve().parents[1]
    target = Path(out).resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / "veilnode-app"
        shutil.copytree(root / "veil_core", staging / "veil_core")
        zipapp.create_archive(
            staging,
            target=target,
            interpreter="/usr/bin/env python3",
            main="veil_core.bootstrap:bootstrap_then_main",
        )
    return {"package": str(target), "type": "zipapp", "run": f"python3 {target}"}


def build_release_artifacts(out_dir: str | Path) -> dict:
    root = Path(__file__).resolve().parents[1]
    dist = Path(out_dir).resolve()
    dist.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, dict] = {}
    zipapp_path = dist / "veil-node.pyz"
    artifacts["python_zipapp"] = build_zipapp(zipapp_path)
    artifacts["windows_zip"] = _build_windows_zip(root, dist, zipapp_path)
    artifacts["macos_dmg"] = _build_macos_dmg(root, dist)
    artifacts["android_apk"] = _build_android_apk(root, dist)
    artifacts["ios_ipa"] = _build_ios_ipa(root, dist)
    if os.environ.get("VEILNODE_BUILD_UNSIGNED_IPA") == "1":
        artifacts["ios_ipa_unsigned"] = _build_ios_ipa_unsigned(root, dist)
    manifest = {
        "release_dir": str(dist),
        "suite_version_source": "pyproject.toml",
        "crypto_core_version": "2.2",
        "unsupported_gui_targets": ["linux", "nas"],
        "artifact_repository_policy": "release artifacts are generated under dist/ and should not be committed to source control",
        "artifacts": artifacts,
    }
    (dist / "release-manifest.json").write_text(__import__("json").dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _build_windows_zip(root: Path, dist: Path, zipapp_path: Path) -> dict:
    target = dist / "VeilNode-Windows.zip"
    skip_dir_parts = {"__pycache__", ".gradle", "build", ".build"}
    skip_suffixes = {".pyc"}
    written: set[str] = set()

    def add(source: Path, archive_name: str) -> None:
        if archive_name in written or not source.exists():
            return
        written.add(archive_name)
        zf.write(source, archive_name)

    def add_tree(source_root: Path, archive_prefix: str) -> None:
        if not source_root.exists():
            return
        for entry in sorted(source_root.rglob("*")):
            if not entry.is_file():
                continue
            rel = entry.relative_to(source_root)
            if any(part in skip_dir_parts for part in rel.parts):
                continue
            if entry.suffix in skip_suffixes:
                continue
            add(entry, f"{archive_prefix}/{rel.as_posix()}")

    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        add(zipapp_path, "VeilNode/veil-node.pyz")
        add(root / "bin/veil-node", "VeilNode/bin/veil-node")
        add(root / "bin/veil-factory", "VeilNode/bin/veil-factory")
        add_tree(root / "veil_core", "VeilNode/veil_core")
        add_tree(root / "clients/windows", "VeilNode/clients/windows")
        add_tree(root / "clients/android", "VeilNode/clients/android")
        add_tree(root / "clients/ios", "VeilNode/clients/ios")
        add_tree(root / "clients/macos", "VeilNode/clients/macos")
        add_tree(root / "clients/common", "VeilNode/clients/common")
        for doc in [
            root / "README.md",
            root / "README.zh-CN.md",
            root / "docs/TECHNICAL.md",
            root / "docs/TECHNICAL.zh-CN.md",
            root / "docs/PLATFORMS.md",
            root / "docs/PLATFORMS.zh-CN.md",
            root / "pyproject.toml",
            root / "Package.swift",
        ]:
            if doc.exists():
                add(doc, f"VeilNode/{doc.relative_to(root).as_posix()}")
    return {
        "package": str(target),
        "type": "zip",
        "status": "built",
        "note": "Portable cross-platform bundle. Windows: VeilNodeGui.bat / BuildExe.bat. Android: BuildApk.bat / BuildApk.sh. iOS: BuildIpa.sh.",
    }


def _build_macos_dmg(root: Path, dist: Path) -> dict:
    swift = shutil.which("swift")
    hdiutil = shutil.which("hdiutil")
    if not swift or not hdiutil:
        return {
            "package": None,
            "type": "dmg",
            "status": "blocked",
            "reason": "swift and hdiutil are required on macOS to build the DMG",
        }
    build = subprocess.run([swift, "build", "-c", "release"], cwd=root, text=True, capture_output=True)
    if build.returncode != 0:
        return {"package": None, "type": "dmg", "status": "blocked", "reason": build.stderr[-2000:]}
    executable = root / ".build/release/VeilNode"
    if not executable.exists():
        return {"package": None, "type": "dmg", "status": "blocked", "reason": "Swift release executable was not produced"}
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / "dmg-root"
        app = staging / "VeilNode.app"
        macos = app / "Contents/MacOS"
        resources = app / "Contents/Resources/VeilNodeCore"
        macos.mkdir(parents=True)
        resources.mkdir(parents=True)
        shutil.copy2(executable, macos / "VeilNode")
        shutil.copytree(
            root / "veil_core",
            resources / "veil_core",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        for doc in [root / "README.md", root / "README.zh-CN.md"]:
            shutil.copy2(doc, resources / doc.name)
        shutil.copytree(root / "docs", resources / "docs")
        helpers = staging / "BuildHelpers"
        helpers.mkdir(parents=True)
        for helper in [
            root / "clients/android/BuildApk.sh",
            root / "clients/android/BuildApk.bat",
            root / "clients/ios/BuildIpa.sh",
            root / "clients/ios/BuildIpaUnsigned.sh",
            root / "clients/windows/BuildExe.bat",
        ]:
            if helper.exists():
                shutil.copy2(helper, helpers / helper.name)
        (helpers / "README.md").write_text(
            "VeilNode build helpers\n"
            "======================\n\n"
            "Run on the host that matches the target:\n\n"
            "- BuildApk.sh         -> macOS or Linux host with JDK 17+, Gradle, Android SDK\n"
            "- BuildApk.bat        -> Windows host with JDK 17+, Gradle, Android SDK\n"
            "- BuildIpa.sh         -> macOS host with Xcode, xcodegen, Apple Developer team\n"
            "- BuildIpaUnsigned.sh -> macOS host with Xcode, xcodegen (unsigned IPA, sideload only)\n"
            "- BuildExe.bat        -> Windows host with Python and PyInstaller\n\n"
            "All scripts work against this same source tree, so unzip the source\n"
            "(or clone the repo) and call them in place.\n",
            encoding="utf-8",
        )
        (app / "Contents/Info.plist").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>VeilNode</string>
<key>CFBundleIdentifier</key><string>org.veilnode.suite</string>
<key>CFBundleName</key><string>VeilNode</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.3.2</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
""",
            encoding="utf-8",
        )
        target = dist / "VeilNode-macOS.dmg"
        if target.exists():
            target.unlink()
        dmg = subprocess.run(
            [hdiutil, "create", "-volname", "VeilNode", "-srcfolder", str(staging), "-ov", "-format", "UDZO", str(target)],
            text=True,
            capture_output=True,
        )
        if dmg.returncode != 0:
            return {"package": None, "type": "dmg", "status": "blocked", "reason": dmg.stderr[-2000:]}
    return {"package": str(target), "type": "dmg", "status": "built", "signed": False, "notarized": False}


def _build_android_apk(root: Path, dist: Path) -> dict:
    project = root / "clients/android"
    if not (project / "settings.gradle").exists():
        return _mobile_blocked(root, "android", "Gradle Android project files are not present")
    gradle = shutil.which("gradle")
    if not gradle:
        return _mobile_blocked(root, "android", "Gradle is required to build the Android APK")
    java = _find_working_java()
    if not java:
        return _mobile_blocked(root, "android", "No working Java runtime is available for Gradle")

    env = os.environ.copy()
    env["JAVA_HOME"] = str(java["home"])
    env.setdefault("ANDROID_HOME", str(Path.home() / "Library/Android/sdk"))
    env.setdefault("ANDROID_SDK_ROOT", env["ANDROID_HOME"])
    cmd = [gradle, "-p", str(project), ":app:assembleDebug", "--no-daemon", "--console=plain"]
    if java.get("arch") == "x86_64":
        cmd = ["arch", "-x86_64", *cmd]
    build = subprocess.run(cmd, cwd=root, text=True, capture_output=True, env=env)
    if build.returncode != 0:
        return {
            "package": None,
            "type": "apk",
            "status": "blocked",
            "source_present": True,
            "reason": _summarize_failure(build.stdout + build.stderr),
        }
    apk = project / "app/build/outputs/apk/debug/app-debug.apk"
    if not apk.exists():
        return _mobile_blocked(root, "android", "Gradle finished but did not produce app-debug.apk")
    target = dist / "VeilNode-Android-debug.apk"
    shutil.copy2(apk, target)
    return {
        "package": str(target),
        "type": "apk",
        "status": "built",
        "signing": "android_debug_keystore",
        "note": "Debug-signed APK for direct testing; store release signing is intentionally not fabricated.",
    }


def _build_ios_ipa(root: Path, dist: Path) -> dict:
    project_dir = root / "clients/ios"
    project_file = project_dir / "VeilNodeiOS.xcodeproj"
    if not project_file.exists():
        xcodegen = shutil.which("xcodegen")
        if not xcodegen or not (project_dir / "project.yml").exists():
            return _mobile_blocked(root, "ios", "Xcode iOS project/workspace is not present")
        generated = subprocess.run([xcodegen, "generate"], cwd=project_dir, text=True, capture_output=True)
        if generated.returncode != 0:
            return _mobile_blocked(root, "ios", generated.stderr[-2000:])

    xcodebuild = shutil.which("xcodebuild")
    team = os.environ.get("VEILNODE_DEVELOPMENT_TEAM") or os.environ.get("DEVELOPMENT_TEAM")
    if not xcodebuild:
        return _mobile_blocked(root, "ios", "xcodebuild is required to build the IPA")
    if not team:
        return _mobile_blocked(root, "ios", "Set VEILNODE_DEVELOPMENT_TEAM to a valid Apple Developer Team ID before exporting a signed IPA")

    build = subprocess.run(
        [
            xcodebuild,
            "-project",
            str(project_file),
            "-target",
            "VeilNodeiOS",
            "-configuration",
            "Release",
            "-sdk",
            "iphoneos",
            "CODE_SIGN_STYLE=Automatic",
            f"DEVELOPMENT_TEAM={team}",
            "-allowProvisioningUpdates",
            "build",
        ],
        cwd=project_dir,
        text=True,
        capture_output=True,
    )
    if build.returncode != 0:
        return {
            "package": None,
            "type": "ipa",
            "status": "blocked",
            "source_present": True,
            "reason": _summarize_failure(build.stdout + build.stderr),
        }

    app = project_dir / "build/Release-iphoneos/VeilNode.app"
    if not app.exists():
        return _mobile_blocked(root, "ios", "xcodebuild finished but did not produce Release-iphoneos/VeilNode.app")
    target = dist / "VeilNode-iOS-iPadOS.ipa"
    if target.exists():
        target.unlink()
    with tempfile.TemporaryDirectory() as tmp:
        payload = Path(tmp) / "Payload"
        payload.mkdir()
        shutil.copytree(app, payload / "VeilNode.app")
        shutil.make_archive(str(target.with_suffix("")), "zip", tmp)
        Path(str(target.with_suffix("")) + ".zip").rename(target)
    return {
        "package": str(target),
        "type": "ipa",
        "status": "built",
        "signing": "apple_development",
        "team": team,
    }


def _build_ios_ipa_unsigned(root: Path, dist: Path) -> dict:
    project_dir = root / "clients/ios"
    project_file = project_dir / "VeilNodeiOS.xcodeproj"
    if not project_file.exists():
        xcodegen = shutil.which("xcodegen")
        if not xcodegen or not (project_dir / "project.yml").exists():
            return _mobile_blocked(root, "ios", "Xcode iOS project/workspace is not present")
        generated = subprocess.run([xcodegen, "generate"], cwd=project_dir, text=True, capture_output=True)
        if generated.returncode != 0:
            return _mobile_blocked(root, "ios", generated.stderr[-2000:])

    xcodebuild = shutil.which("xcodebuild")
    if not xcodebuild:
        return _mobile_blocked(root, "ios", "xcodebuild is required to build the unsigned IPA")

    with tempfile.TemporaryDirectory() as derived:
        build = subprocess.run(
            [
                xcodebuild,
                "-project",
                str(project_file),
                "-scheme",
                "VeilNodeiOS",
                "-configuration",
                "Release",
                "-sdk",
                "iphoneos",
                "-destination",
                "generic/platform=iOS",
                "-derivedDataPath",
                derived,
                "CODE_SIGNING_ALLOWED=NO",
                "CODE_SIGN_IDENTITY=",
                "CODE_SIGNING_REQUIRED=NO",
                "build",
            ],
            cwd=project_dir,
            text=True,
            capture_output=True,
        )
        if build.returncode != 0:
            return {
                "package": None,
                "type": "ipa",
                "signing": "unsigned",
                "status": "blocked",
                "source_present": True,
                "reason": _summarize_failure(build.stdout + build.stderr),
            }

        app = Path(derived) / "Build/Products/Release-iphoneos/VeilNode.app"
        if not app.exists():
            return _mobile_blocked(root, "ios", "xcodebuild finished but did not produce VeilNode.app")
        target = dist / "VeilNode-iOS-iPadOS-unsigned.ipa"
        if target.exists():
            target.unlink()
        with tempfile.TemporaryDirectory() as payload_dir:
            payload = Path(payload_dir) / "Payload"
            payload.mkdir()
            shutil.copytree(app, payload / "VeilNode.app")
            shutil.make_archive(str(target.with_suffix("")), "zip", payload_dir)
            Path(str(target.with_suffix("")) + ".zip").rename(target)
    return {
        "package": str(target),
        "type": "ipa",
        "signing": "unsigned",
        "status": "built",
        "note": "Unsigned IPA. Cannot install on stock iOS without a sideload tool (AltStore / Sideloadly) or a jailbroken device.",
    }


def _find_working_java() -> dict | None:
    candidates = []
    env_home = os.environ.get("JAVA_HOME")
    if env_home:
        candidates.append((Path(env_home), None))
    candidates.extend(
        [
            (Path.home() / ".local/jdks/temurin-21-x64.jdk/Contents/Home", "x86_64"),
            (Path("/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home"), None),
            (Path("/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"), None),
            (Path("/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home"), None),
        ]
    )
    seen = set()
    for home, arch in candidates:
        if home in seen:
            continue
        seen.add(home)
        java = home / "bin/java"
        if not java.exists():
            continue
        cmd = [str(java), "-version"]
        if arch == "x86_64":
            cmd = ["arch", "-x86_64", *cmd]
        result = subprocess.run(cmd, text=True, capture_output=True)
        if result.returncode == 0:
            return {"home": home, "arch": arch}
    return None


def _summarize_failure(output: str) -> str:
    interesting = []
    for line in output.splitlines():
        if any(marker in line for marker in ("error:", "BUILD FAILED", "No Account", "No profiles", "Could not", "failed")):
            interesting.append(_sanitize_path(line))
    if interesting:
        return "\n".join(interesting[-12:])
    return _sanitize_path(output[-1200:])


def _sanitize_path(text: str) -> str:
    root = str(Path.home())
    return text.replace(root, "~")


def _mobile_blocked(root: Path, platform: str, reason: str) -> dict:
    client_dir = root / f"clients/{platform}"
    return {
        "package": None,
        "type": "apk" if platform == "android" else "ipa",
        "status": "blocked",
        "source_present": client_dir.exists(),
        "reason": reason,
    }
