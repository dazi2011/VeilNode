from __future__ import annotations

from pathlib import Path

from .errors import VeilError
from .identity import IdentityStore, PublicIdentity


class ContactBook:
    def __init__(self, store: IdentityStore):
        self.store = store
        self.store.ensure()

    def add(self, path: str | Path, alias: str | None = None) -> dict:
        public = self.store.import_public(path, alias)
        return {"alias": alias or public.name, "contact": public.to_json()}

    def list(self) -> dict:
        return {"contacts": self.store.list_identities()["contacts"]}

    def show(self, alias: str) -> dict:
        public = self.store.resolve_recipient(alias)
        return public.to_json()

    def remove(self, alias: str, *, confirm: bool = False, dry_run: bool = False) -> dict:
        path = self.store.contacts / f"{alias}.vid"
        if not path.exists():
            legacy = self.store.contacts / f"{alias}.json"
            path = legacy if legacy.exists() else path
        if not path.exists():
            raise VeilError(f"contact not found: {alias}")
        if dry_run:
            return {"would_remove": str(path), "removed": False}
        if not confirm:
            raise VeilError("refusing to remove contact without --yes")
        path.unlink()
        return {"removed": str(path)}
