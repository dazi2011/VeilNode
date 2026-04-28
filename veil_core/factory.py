from __future__ import annotations

import json
import os
import random
import stat
from pathlib import Path

from .crypto import FAST_KDF, kdf_params, random_b64
from .identity import IdentityStore, default_home
from .message import DEFAULT_POLICY
from .profile import build_profile


COMMAND_WORDS = [
    ("send", ["pack", "mask", "emit", "cast"]),
    ("receive", ["unmask", "recover", "read", "draw"]),
    ("identity", ["persona", "id", "self", "who"]),
    ("keypart", ["share", "part", "ticket", "shard"]),
    ("auth", ["state", "once", "gate", "burn"]),
]

OPTION_WORDS = {
    "input": ["--source", "--infile", "--matter", "--plain"],
    "output": ["--drop", "--outfile", "--vessel", "--result"],
    "keypart": ["--ticket", "--shard", "--share", "--fragment"],
    "auth_state": ["--gate", "--once", "--burn-state", "--session"],
    "recipient": ["--to", "--peer", "--target", "--public"],
    "password": ["--phrase", "--secret", "--passcode", "--word"],
    "carrier": ["--cover", "--shell", "--container", "--mask"],
    "format": ["--shape", "--kind", "--skin", "--container-format"],
}


def create_node(
    *,
    name: str,
    out_dir: str | Path,
    chunk_size: int,
    padding: str,
    bucket_size: int,
    containers: list[str],
    param_style: str,
    init_identity_password: str | None = None,
    fast_kdf: bool = False,
) -> dict:
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    home = default_home(name)
    aliases = {canonical: random.choice(words) for canonical, words in COMMAND_WORDS}
    option_aliases = {canonical: random.choice(words) for canonical, words in OPTION_WORDS.items()}
    policy = build_profile(name=name, security_level="dev" if fast_kdf else "balanced", containers=containers)
    policy.update(
        {
            "chunk_size": int(chunk_size),
            "padding": padding,
            "bucket_size": int(bucket_size),
            "param_style": param_style,
            "command_aliases": aliases,
            "option_aliases": option_aliases,
            "error_token": random_b64(9),
            "kdf": FAST_KDF if fast_kdf else kdf_params(),
            "receive_failure_messages": _failure_messages(name),
        }
    )
    profile = out / f"{name}.profile.json"
    profile.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    script = out / name
    project_root = Path(__file__).resolve().parents[1]
    script.write_text(
        "\n".join(
            [
                "#!/usr/bin/env python3",
                "import sys",
                f"sys.path.insert(0, {str(project_root)!r})",
                "from veil_core.cli import main",
                "if __name__ == '__main__':",
                f"    main(default_profile={str(profile)!r}, default_home={str(home)!r})",
                "",
            ]
        ),
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    created_identity = None
    if init_identity_password:
        store = IdentityStore(home)
        created_identity = store.create(name, init_identity_password, overwrite=True, kdf=policy["kdf"]).to_json()
    return {
        "node": str(script),
        "profile": str(profile),
        "home": str(home),
        "aliases": aliases,
        "option_aliases": option_aliases,
        "identity": created_identity,
    }


def write_policy(
    *,
    out: str | Path,
    name: str,
    chunk_size: int,
    padding: str,
    bucket_size: int,
    containers: list[str],
    fast_kdf: bool = False,
) -> dict:
    policy = build_profile(name=name, security_level="dev" if fast_kdf else "balanced", containers=containers)
    policy.update(
        {
            "chunk_size": int(chunk_size),
            "padding": padding,
            "bucket_size": int(bucket_size),
            "kdf": FAST_KDF if fast_kdf else kdf_params(),
        }
    )
    path = Path(out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    return policy


def _failure_messages(name: str) -> list[str]:
    stems = [
        "unable to open message",
        "operation failed",
        "message could not be recovered",
        "input rejected",
    ]
    random.shuffle(stems)
    return [f"{msg} [{name}:{random_b64(4)}]" for msg in stems[:3]]
