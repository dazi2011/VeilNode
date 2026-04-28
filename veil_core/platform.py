from __future__ import annotations

import json
import os
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class SecureStore(Protocol):
    def save(self, key: str, value: bytes) -> None: ...
    def load(self, key: str) -> bytes | None: ...
    def delete(self, key: str) -> None: ...


class DeviceBinding(Protocol):
    def capability(self) -> dict: ...
    def bind(self, material: bytes) -> bytes: ...


class FileProvider(Protocol):
    def read(self, path: str | Path) -> bytes: ...
    def write(self, path: str | Path, data: bytes) -> None: ...


@dataclass
class LocalFileProvider:
    def read(self, path: str | Path) -> bytes:
        return Path(path).read_bytes()

    def write(self, path: str | Path, data: bytes) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


class FileSystemSecureStore:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, key: str, value: bytes) -> None:
        path = self._path(key)
        path.write_bytes(value)
        path.chmod(0o600)

    def load(self, key: str) -> bytes | None:
        path = self._path(key)
        return path.read_bytes() if path.exists() else None

    def delete(self, key: str) -> None:
        path = self._path(key)
        if path.exists():
            path.unlink()

    def _path(self, key: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in key)
        return self.root / f"{safe}.bin"


class PortableDeviceBinding:
    def capability(self) -> dict:
        system = platform.system().lower()
        return {
            "platform": system,
            "secure_enclave": system in {"darwin"},
            "tpm": system in {"windows", "linux"} and (shutil.which("tpm2_getrandom") is not None),
            "yubikey": shutil.which("ykman") is not None,
            "android_strongbox": False,
            "implemented_mode": "portable-derived-binding",
        }

    def bind(self, material: bytes) -> bytes:
        import hashlib

        host = "|".join([platform.node(), platform.system(), platform.machine(), str(os.getuid() if hasattr(os, "getuid") else "")])
        return hashlib.sha256(host.encode("utf-8") + b"\x00" + material).digest()


def platform_report() -> dict:
    binding = PortableDeviceBinding()
    return {
        "platform": platform.platform(),
        "secure_store": _secure_store_name(),
        "device_binding": binding.capability(),
        "file_provider": "local-filesystem",
    }


def _secure_store_name() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macOS Keychain adapter planned; portable filesystem store active"
    if system == "windows":
        return "Windows DPAPI/Credential Manager adapter planned; portable filesystem store active"
    if system == "linux":
        return "Secret Service/KWallet adapter planned; portable filesystem store active"
    return "portable filesystem store"
