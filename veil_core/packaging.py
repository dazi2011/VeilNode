from __future__ import annotations

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
    artifacts["android_apk"] = _mobile_blocked(root, "android", "Gradle Android project files are not present")
    artifacts["ios_ipa"] = _mobile_blocked(root, "ios", "Xcode iOS project/workspace and signing profile are not present")
    manifest = {
        "release_dir": str(dist),
        "suite_version_source": "pyproject.toml",
        "crypto_core_version": "2.2",
        "artifacts": artifacts,
    }
    (dist / "release-manifest.json").write_text(__import__("json").dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _build_windows_zip(root: Path, dist: Path, zipapp_path: Path) -> dict:
    target = dist / "VeilNode-Windows.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(zipapp_path, "veil-node.pyz")
        for path in [root / "clients/windows/VeilNodeGui.pyw", root / "clients/windows/VeilNodeGui.bat", root / "clients/windows/README.md"]:
            if path.exists():
                zf.write(path, f"VeilNode/{path.name}")
        for package_file in (root / "veil_core").rglob("*.py"):
            zf.write(package_file, f"VeilNode/veil_core/{package_file.relative_to(root / 'veil_core')}")
    return {
        "package": str(target),
        "type": "zip",
        "status": "built",
        "note": "Portable Windows ZIP includes the GUI launcher and Python zipapp; native .exe requires a Windows/PyInstaller build host.",
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
        shutil.copytree(root / "veil_core", resources / "veil_core")
        (app / "Contents/Info.plist").write_text(
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>VeilNode</string>
<key>CFBundleIdentifier</key><string>org.veilnode.suite</string>
<key>CFBundleName</key><string>VeilNode</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.3.1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
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


def _mobile_blocked(root: Path, platform: str, reason: str) -> dict:
    client_dir = root / f"clients/{platform}"
    return {
        "package": None,
        "type": "apk" if platform == "android" else "ipa",
        "status": "blocked",
        "source_present": client_dir.exists(),
        "reason": reason,
    }
