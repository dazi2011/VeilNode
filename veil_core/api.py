from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .container import capacity_report, verify_container
from .diagnostics import audit, doctor
from .identity import IdentityStore, PublicIdentity
from .message import create_message, receive_message
from .profile import build_profile, load_profile


class VeilAPI:
    def __init__(self, *, home: str | Path, profile_path: str | Path | None = None, profile: dict | None = None):
        self.home = Path(home)
        self.profile = profile or load_profile(profile_path, build_profile())
        self.identity = IdentityStore(self.home)

    def create_identity(self, name: str, password: str, *, overwrite: bool = False) -> dict:
        return self.identity.create(name, password, overwrite=overwrite, kdf=self.profile.get("kdf")).to_json()

    def send(
        self,
        *,
        input_path: str | Path,
        output_path: str | Path,
        keypart_path: str | Path | None,
        auth_state_path: str | Path,
        recipients: Iterable[PublicIdentity],
        password: str,
        container_format: str,
        root_vkp_seed: bytes | None = None,
    ) -> dict:
        return create_message(
            input_path=input_path,
            output_path=output_path,
            keypart_path=keypart_path,
            auth_state_path=auth_state_path,
            recipients=recipients,
            password=password,
            policy=self.profile,
            container_format=container_format,
            root_vkp_seed=root_vkp_seed,
        )

    def receive(
        self,
        *,
        input_path: str | Path,
        keypart_path: str | Path,
        auth_state_path: str | Path,
        output_dir: str | Path,
        identity_password: str,
        password: str,
        verify_only: bool = False,
        root_vkp_seed: bytes | None = None,
    ) -> dict:
        private = self.identity.load_private(identity_password)
        if root_vkp_seed is not None:
            from .message import receive_message_v2

            return receive_message_v2(
                input_path=input_path,
                root_vkp_seed=root_vkp_seed,
                auth_state_path=auth_state_path,
                output_dir=output_dir,
                identity=private,
                password=password,
                verify_only=verify_only,
            )
        return receive_message(
            input_path=input_path,
            keypart_path=keypart_path,
            auth_state_path=auth_state_path,
            output_dir=output_dir,
            identity=private,
            password=password,
            verify_only=verify_only,
        )

    def doctor(self) -> dict:
        return doctor(self.home, self.profile)

    def audit(self) -> dict:
        return audit(self.home, self.profile)

    def capacity(self, path: str | Path | None, fmt: str | None, payload_size: int | None = None) -> dict:
        return capacity_report(path, fmt, payload_size=payload_size)

    def verify_carrier(self, path: str | Path, fmt: str | None = None) -> dict:
        return verify_container(path, fmt)
