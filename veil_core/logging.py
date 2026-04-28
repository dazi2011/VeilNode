from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any


SENSITIVE_KEYS = {
    "password",
    "identity_password",
    "private_key",
    "file_key",
    "ciphertext",
    "wrapped_file_key",
    "salt",
    "nonce",
}


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("<redacted>" if k in SENSITIVE_KEYS else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        home = str(Path.home())
        if home in value:
            return value.replace(home, "~")
    return value


def event(name: str, **fields: Any) -> dict[str, Any]:
    return {"ts": int(time.time()), "event": name, **redact(fields)}


def emit_verbose(verbose: bool, name: str, **fields: Any) -> None:
    if verbose:
        print(json.dumps(event(name, **fields), ensure_ascii=False), file=sys.stderr)
