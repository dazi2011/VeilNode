from __future__ import annotations

import importlib
import os
import subprocess
import sys


REQUIRED = {
    "cryptography": "cryptography>=45",
}


def bootstrap_then_main() -> None:
    _bootstrap()


def factory_bootstrap_then_main() -> None:
    sys.argv = [sys.argv[0], "factory", *sys.argv[1:]]
    _bootstrap()


def _bootstrap() -> None:
    args = list(sys.argv[1:])
    install_requested = "--install-deps" in args
    check_requested = "--check-deps" in args
    args = [arg for arg in args if arg not in {"--install-deps", "--check-deps"}]
    missing = missing_dependencies()

    if check_requested and not install_requested:
        if missing:
            print("missing dependencies:")
            for spec in missing:
                print(f"  {spec}")
            raise SystemExit(1)
        print("all dependencies available")
        raise SystemExit(0)

    if missing and (install_requested or os.environ.get("VEIL_AUTO_INSTALL") == "1"):
        install_dependencies(missing)
        missing = missing_dependencies()

    if install_requested and not args:
        if missing:
            print("dependency installation failed or dependencies are still unavailable:", file=sys.stderr)
            for spec in missing:
                print(f"  {spec}", file=sys.stderr)
            raise SystemExit(1)
        print("dependencies installed and available")
        raise SystemExit(0)

    if missing:
        print("Veil dependency check failed.", file=sys.stderr)
        print("Run this once with the same Python:", file=sys.stderr)
        print(f"  {sys.executable} -m veil_core --install-deps", file=sys.stderr)
        print("Or install manually:", file=sys.stderr)
        print(f"  {sys.executable} -m pip install {' '.join(missing)}", file=sys.stderr)
        raise SystemExit(1)

    from .cli import main

    main(args)


def missing_dependencies() -> list[str]:
    missing: list[str] = []
    for module, spec in REQUIRED.items():
        try:
            importlib.import_module(module)
        except Exception:
            missing.append(spec)
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305  # noqa: F401
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # noqa: F401
    except Exception:
        if REQUIRED["cryptography"] not in missing:
            missing.append(REQUIRED["cryptography"])
    return missing


def install_dependencies(specs: list[str]) -> None:
    _ensure_pip()
    cmd = [sys.executable, "-m", "pip", "install"]
    if not _in_virtualenv() and os.environ.get("VEIL_PIP_USER", "1") != "0":
        cmd.append("--user")
    cmd.extend(specs)
    print("installing dependencies with:")
    print("  " + " ".join(cmd))
    subprocess.check_call(cmd)


def _ensure_pip() -> None:
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL)
        return
    except Exception:
        pass
    import ensurepip

    ensurepip.bootstrap(upgrade=True)


def _in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)
