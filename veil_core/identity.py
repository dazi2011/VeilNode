from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .crypto import (
    aes_decrypt,
    aes_encrypt,
    b64d,
    b64e,
    canonical_json,
    derive_password_key,
    fingerprint,
    kdf_params,
)
from .errors import VeilError


@dataclass(frozen=True)
class PublicIdentity:
    node_id: str
    name: str
    public_key: bytes
    created_at: int

    @classmethod
    def from_file(cls, path: str | Path) -> "PublicIdentity":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            node_id=data["node_id"],
            name=data.get("name", data["node_id"]),
            public_key=b64d(data["public_key"]),
            created_at=int(data.get("created_at", 0)),
        )

    def to_json(self) -> dict:
        return {
            "kind": "veil-id",
            "node_id": self.node_id,
            "name": self.name,
            "public_key": b64e(self.public_key),
            "created_at": self.created_at,
        }

    def public_object(self) -> x25519.X25519PublicKey:
        return x25519.X25519PublicKey.from_public_bytes(self.public_key)


@dataclass(frozen=True)
class PrivateIdentity:
    public: PublicIdentity
    private_key: bytes

    def private_object(self) -> x25519.X25519PrivateKey:
        return x25519.X25519PrivateKey.from_private_bytes(self.private_key)


def default_home(name: str | None = None) -> Path:
    base = Path(os.environ.get("VEIL_HOME") or Path.home() / ".veilnode")
    return base / name if name else base


class IdentityStore:
    def __init__(self, home: str | Path):
        self.home = Path(home)
        self.contacts = self.home / "contacts"
        self.private_path = self.home / "identity.private.json"
        self.public_path = self.home / "identity.public.json"

    def ensure(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self.contacts.mkdir(parents=True, exist_ok=True)

    def create(self, name: str, password: str, *, overwrite: bool = False, kdf: dict | None = None) -> PublicIdentity:
        self.ensure()
        if self.private_path.exists() and not overwrite:
            raise VeilError(f"identity already exists in {self.home}")
        private = x25519.X25519PrivateKey.generate()
        private_raw = private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_raw = private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        public = PublicIdentity(
            node_id=fingerprint(public_raw),
            name=name,
            public_key=public_raw,
            created_at=int(time.time()),
        )
        salt = os.urandom(16)
        pass_key = derive_password_key(password, salt, kdf_params(kdf))
        aad = canonical_json({"node_id": public.node_id, "purpose": "identity-private"})
        nonce, ciphertext = aes_encrypt(pass_key.key, private_raw, aad=aad)
        private_record = {
            "kind": "veil-private-identity",
            "node_id": public.node_id,
            "name": name,
            "public_key": b64e(public_raw),
            "created_at": public.created_at,
            "kdf": pass_key.params,
            "salt": b64e(salt),
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
        }
        self.private_path.write_text(json.dumps(private_record, indent=2), encoding="utf-8")
        self.private_path.chmod(0o600)
        self.public_path.write_text(json.dumps(public.to_json(), indent=2), encoding="utf-8")
        return public

    def load_public(self) -> PublicIdentity:
        if not self.public_path.exists():
            raise VeilError(f"no public identity in {self.home}")
        return PublicIdentity.from_file(self.public_path)

    def load_private(self, password: str) -> PrivateIdentity:
        if not self.private_path.exists():
            raise VeilError(f"no private identity in {self.home}")
        data = json.loads(self.private_path.read_text(encoding="utf-8"))
        public = PublicIdentity(
            node_id=data["node_id"],
            name=data.get("name", data["node_id"]),
            public_key=b64d(data["public_key"]),
            created_at=int(data.get("created_at", 0)),
        )
        try:
            pass_key = derive_password_key(password, b64d(data["salt"]), data["kdf"])
            aad = canonical_json({"node_id": public.node_id, "purpose": "identity-private"})
            private_raw = aes_decrypt(pass_key.key, b64d(data["nonce"]), b64d(data["ciphertext"]), aad=aad)
        except Exception as exc:
            raise VeilError("unable to unlock identity") from exc
        return PrivateIdentity(public=public, private_key=private_raw)

    def export_public(self, out: str | Path) -> PublicIdentity:
        public = self.load_public()
        Path(out).write_text(json.dumps(public.to_json(), indent=2), encoding="utf-8")
        return public

    def import_public(self, path: str | Path, alias: str | None = None) -> PublicIdentity:
        self.ensure()
        public = PublicIdentity.from_file(path)
        name = alias or public.name or public.node_id
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)
        dest = self.contacts / f"{safe}.vid"
        shutil.copyfile(path, dest)
        return public

    def resolve_recipient(self, value: str) -> PublicIdentity:
        direct = Path(value)
        if direct.exists():
            return PublicIdentity.from_file(direct)
        contact = self.contacts / f"{value}.vid"
        if contact.exists():
            return PublicIdentity.from_file(contact)
        raise VeilError(f"recipient not found: {value}")

    def list_identities(self) -> dict:
        self.ensure()
        result = {"private": None, "contacts": []}
        if self.public_path.exists():
            result["private"] = self.load_public().to_json()
        contact_paths = sorted(self.contacts.glob("*.vid")) + sorted(self.contacts.glob("*.json"))
        seen = set()
        for path in contact_paths:
            if path.stem in seen:
                continue
            seen.add(path.stem)
            public = PublicIdentity.from_file(path)
            result["contacts"].append({"alias": path.stem, **public.to_json()})
        return result
