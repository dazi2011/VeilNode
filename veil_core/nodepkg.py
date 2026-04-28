from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

from .crypto import b64e, canonical_json, sha256
from .errors import VeilError
from .identity import IdentityStore
from .protocol import current_protocol


NODEPKG_KIND = "veil-node-package"


def export_nodepkg(store: IdentityStore, out: str | Path, profile: dict, *, include_contacts: bool = True) -> dict:
    store.ensure()
    if not store.private_path.exists() or not store.public_path.exists():
        raise VeilError("node package export requires a local identity")
    contacts = []
    if include_contacts and store.contacts.exists():
        for path in sorted(store.contacts.glob("*.vid")) + sorted(store.contacts.glob("*.json")):
            contacts.append(json.loads(path.read_text(encoding="utf-8")))
    payload = {
        "kind": NODEPKG_KIND,
        "version": 1,
        "created_at": int(time.time()),
        "protocol": current_protocol(),
        "public_identity": json.loads(store.public_path.read_text(encoding="utf-8")),
        "encrypted_private_identity": json.loads(store.private_path.read_text(encoding="utf-8")),
        "profile": profile,
        "contacts": contacts,
        "adapters": profile.get("supported_containers", []),
        "auth_state_seed": None,
    }
    payload["integrity"] = {"sha256": b64e(sha256(canonical_json({k: v for k, v in payload.items() if k != "integrity"})))}
    target = Path(out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    target.chmod(0o600)
    return {"nodepkg": str(target), "node_id": payload["public_identity"]["node_id"], "contacts": len(contacts)}


def import_nodepkg(store: IdentityStore, path: str | Path, *, overwrite: bool = False) -> dict:
    source = Path(path)
    data = json.loads(source.read_text(encoding="utf-8"))
    if data.get("kind") != NODEPKG_KIND:
        raise VeilError("not a VeilNode .vpkg file")
    expected = data.get("integrity", {}).get("sha256")
    actual = b64e(sha256(canonical_json({k: v for k, v in data.items() if k != "integrity"})))
    if expected and expected != actual:
        raise VeilError("node package integrity check failed")
    store.ensure()
    if (store.private_path.exists() or store.public_path.exists()) and not overwrite:
        raise VeilError("identity already exists; use --overwrite to import node package")
    store.public_path.write_text(json.dumps(data["public_identity"], indent=2, ensure_ascii=False), encoding="utf-8")
    store.private_path.write_text(json.dumps(data["encrypted_private_identity"], indent=2, ensure_ascii=False), encoding="utf-8")
    store.private_path.chmod(0o600)
    imported_contacts = 0
    for contact in data.get("contacts", []):
        alias = contact.get("name") or contact.get("node_id")
        if not alias:
            continue
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in alias)
        (store.contacts / f"{safe}.vid").write_text(json.dumps(contact, indent=2, ensure_ascii=False), encoding="utf-8")
        imported_contacts += 1
    return {"imported": str(source), "node_id": data["public_identity"]["node_id"], "contacts": imported_contacts}


def inspect_nodepkg(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        "kind": data.get("kind"),
        "version": data.get("version"),
        "node_id": data.get("public_identity", {}).get("node_id"),
        "profile": data.get("profile", {}).get("profile_id") or data.get("profile", {}).get("security_level"),
        "contacts": len(data.get("contacts", [])),
        "adapters": data.get("adapters", []),
        "integrity_present": "integrity" in data,
    }
