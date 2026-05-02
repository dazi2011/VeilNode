from __future__ import annotations

import argparse
import getpass
import json
import random
import sys
from pathlib import Path

from .contacts import ContactBook
from .carrier_tools import carrier_audit, carrier_compare, create_carrier_profile, inspect_carrier_profile
from .container import SUPPORTED_FORMATS
from .diagnostics import audit as audit_home
from .diagnostics import capacity as capacity_report
from .diagnostics import doctor, verify_carrier
from .errors import VeilDecryptError, VeilError
from .factory import create_node, write_policy
from .identity import IdentityStore, default_home as identity_default_home
from .keypart import (
    create_root_vkp_seed,
    export_root_vkp_seed,
    import_root_vkp_seed,
    import_root_to_store,
    inspect_root_vkp_seed,
    list_root_store,
    open_root_vkp_seed,
    open_root_vkp_seed_info,
    recover_root_vkp_seed,
    remove_root_from_store,
    resolve_root_from_store,
    rotate_root_vkp_seed,
    seal_root_vkp_seed,
    set_root_vkp_seed_status,
    show_root_in_store,
    split_root_vkp_seed,
)
from .message import (
    create_message,
    destroy_auth_state,
    inspect_keypart,
    load_policy,
    message_protocol_version,
    receive_message,
    receive_message_v2,
)
from .nodepkg import export_nodepkg, import_nodepkg, inspect_nodepkg
from .packaging import build_release_artifacts, build_zipapp
from .permissions import home_permission_report
from .profile import SECURITY_LEVELS, build_profile, profile_summary, write_profile
from .repair import migrate_keypart, recovery_scan, repair_keypart
from .replay import forget_seen, list_seen, seen_db_path, vacuum_seen
from .safety import secure_delete
from .strategy.dataset import collect_dataset
from .strategy.features import extract_features
from .strategy.generator import generate_policies
from .strategy.model import inspect_model
from .strategy.policy import EnvelopePolicy
from .strategy.policy import inspect_policy as inspect_envelope_policy
from .strategy.policy import load_policy_file as load_envelope_policy_file
from .strategy.policy import save_policy_file as save_envelope_policy_file
from .strategy.registry import list_strategies
from .strategy.scorer import scan_fixed_signatures, score_json
from .strategy.selector import select_policy
from .strategy.trainer import train as train_strategy_model
from .testvectors import run_vectors


RESERVED_SUBCOMMANDS = {
    "identity",
    "send",
    "seal",
    "receive",
    "open",
    "keypart",
    "auth",
    "contact",
    "profile",
    "doctor",
    "audit",
    "capacity",
    "verify-carrier",
    "verify-only",
    "repair",
    "migrate",
    "carrier",
    "secure-delete",
    "package",
    "test-vector",
    "strategy",
    "nodepkg",
    "factory",
}


def main(argv: list[str] | None = None, *, default_profile: str | None = None, default_home: str | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    profile_path = _preparse_profile(argv) or default_profile
    policy = load_policy(profile_path)
    home_path = default_home or str(identity_default_home(policy.get("node_name", "default")))
    parser = _build_parser(policy, profile_path, home_path)
    args = parser.parse_args(argv)
    if args.profile:
        policy = load_policy(args.profile)
    if args.home:
        home_path = args.home
    try:
        result = _dispatch(args, policy, Path(home_path))
    except VeilDecryptError as exc:
        if getattr(args, "debug_reason", False):
            reason = exc.__cause__ or exc
            print(f"Unable to open message. debug_reason={reason}", file=sys.stderr)
        else:
            print("Unable to open message.", file=sys.stderr)
        raise SystemExit(2)
    except VeilError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
    if result is not None:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def factory_main() -> None:
    main(["factory", *sys.argv[1:]], default_home=str(identity_default_home("factory")))


def _preparse_profile(argv: list[str]) -> str | None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--profile")
    known, _ = parser.parse_known_args(argv)
    return known.profile


def _build_parser(policy: dict, profile_path: str | None, home_path: str) -> argparse.ArgumentParser:
    aliases = policy.get("command_aliases", {})
    parser = argparse.ArgumentParser(
        prog=policy.get("node_name") or "veil",
        description="Offline polymorphic steganographic envelope CLI",
    )
    parser.add_argument("--profile", default=profile_path, help="node policy/profile JSON")
    parser.add_argument("--home", default=home_path, help="identity home directory")
    parser.add_argument("--verbose", action="store_true", help="emit redacted diagnostic events")
    sub = parser.add_subparsers(dest="command", required=True)

    identity = sub.add_parser("identity", aliases=_alias(aliases, "identity"), help="create/import/export identities")
    identity_sub = identity.add_subparsers(dest="identity_command", required=True)
    identity_create = identity_sub.add_parser("create")
    identity_create.add_argument("--name", required=True)
    identity_create.add_argument("--password")
    identity_create.add_argument("--overwrite", action="store_true")
    identity_export = identity_sub.add_parser("export")
    identity_export.add_argument("--out", "-o", required=True)
    identity_import = identity_sub.add_parser("import")
    identity_import.add_argument("--in", dest="input", required=True)
    identity_import.add_argument("--alias")
    identity_sub.add_parser("list")
    identity_health = identity_sub.add_parser("health")
    identity_health.add_argument("--identity-password")

    send = sub.add_parser("send", aliases=_alias(aliases, "send"), help="encrypt and embed a message")
    send.add_argument(*_opts(policy, "input", "--input", "-i"), dest="input", required=True)
    send.add_argument(*_opts(policy, "output", "--output", "-o"), dest="output", required=True)
    send.add_argument(*_opts(policy, "keypart", "--keypart", "-k"), dest="keypart")
    send.add_argument(*_opts(policy, "auth_state", "--auth-state", "-a"), dest="auth_state", required=True)
    send.add_argument(*_opts(policy, "recipient", "--recipient", "-r"), dest="recipient", action="append", required=True)
    send.add_argument(*_opts(policy, "password", "--password", "-p"), dest="password")
    send.add_argument(*_opts(policy, "carrier", "--carrier", "-c"), dest="carrier")
    send.add_argument(*_opts(policy, "format", "--format", "-f"), dest="format", choices=sorted(SUPPORTED_FORMATS))
    send.add_argument("--decoy-input")
    send.add_argument("--decoy-password")
    send.add_argument("--device-bind", action="store_true")
    send.add_argument("--root-keypart")
    send.add_argument("--root-keypart-password")
    send.add_argument("--root-label")
    send.add_argument("--root-fingerprint")
    send.add_argument("--root-store")
    send.add_argument("--no-external-keypart", action="store_true")
    send.add_argument("--crypto-core", choices=["2", "2.2"], default="2")
    send.add_argument("--low-signature", action="store_true")
    send.add_argument("--signature-profile", choices=["conservative", "balanced", "aggressive"], default="balanced")
    send.add_argument("--carrier-profile")
    send.add_argument("--adaptive-policy", action="store_true")
    send.add_argument("--policy-candidates", type=int, default=50)
    send.add_argument("--policy-out")
    send.add_argument("--policy-in")
    send.add_argument("--policy-model")
    send.add_argument("--work-dir")
    send.add_argument("--keep-temp-debug", action="store_true")
    send.add_argument("--redact-logs", action="store_true", default=True)
    send.add_argument("--no-redact-logs", action="store_true")

    seal = sub.add_parser("seal", help="VeilNode positional send: seal INPUT COVER OUTPUT --to CONTACT")
    seal.add_argument("input")
    seal.add_argument("carrier")
    seal.add_argument("output")
    seal.add_argument("--to", dest="recipient", action="append", required=True)
    seal.add_argument("--password", "-p")
    seal.add_argument("--keypart", "-k")
    seal.add_argument("--auth-state", "-a")
    seal.add_argument("--format", "-f", choices=sorted(SUPPORTED_FORMATS))
    seal.add_argument("--device-bind", action="store_true")
    seal.add_argument("--root-keypart")
    seal.add_argument("--root-keypart-password")
    seal.add_argument("--root-label")
    seal.add_argument("--root-fingerprint")
    seal.add_argument("--root-store")
    seal.add_argument("--no-external-keypart", action="store_true")
    seal.add_argument("--crypto-core", choices=["2", "2.2"], default="2")
    seal.add_argument("--low-signature", action="store_true")
    seal.add_argument("--signature-profile", choices=["conservative", "balanced", "aggressive"], default="balanced")
    seal.add_argument("--carrier-profile")
    seal.add_argument("--adaptive-policy", action="store_true")
    seal.add_argument("--policy-candidates", type=int, default=50)
    seal.add_argument("--policy-out")
    seal.add_argument("--policy-in")
    seal.add_argument("--policy-model")
    seal.add_argument("--decoy-input")
    seal.add_argument("--decoy-password")
    seal.add_argument("--decoy-pad-match", choices=["real", "fixed", "random"], default="real")
    seal.add_argument("--work-dir")
    seal.add_argument("--keep-temp-debug", action="store_true")
    seal.add_argument("--redact-logs", action="store_true", default=True)
    seal.add_argument("--no-redact-logs", action="store_true")

    receive = sub.add_parser("receive", aliases=_alias(aliases, "receive"), help="recover a message")
    receive.add_argument(*_opts(policy, "input", "--input", "-i"), dest="input", required=True)
    receive.add_argument(*_opts(policy, "output", "--output", "-o"), dest="output", required=True)
    receive.add_argument(*_opts(policy, "keypart", "--keypart", "-k"), dest="keypart", required=True)
    receive.add_argument(*_opts(policy, "auth_state", "--auth-state", "-a"), dest="auth_state", required=True)
    receive.add_argument(*_opts(policy, "password", "--password", "-p"), dest="password")
    receive.add_argument("--identity-password")
    receive.add_argument("--verify-only", action="store_true", help="decrypt and verify without writing output or consuming auth")
    receive.add_argument("--no-replay-check", action="store_true")
    receive.add_argument("--debug-reason", action="store_true")

    open_cmd = sub.add_parser("open", help="VeilNode positional receive: open MESSAGE --keypart FILE --out DIR")
    open_cmd.add_argument("input")
    open_cmd.add_argument("--out", dest="output", required=True)
    open_cmd.add_argument("--keypart", "-k")
    open_cmd.add_argument("--root-keypart")
    open_cmd.add_argument("--root-keypart-password")
    open_cmd.add_argument("--root-store")
    open_cmd.add_argument("--root-fingerprint")
    open_cmd.add_argument("--auth-state", "-a")
    open_cmd.add_argument("--password", "-p")
    open_cmd.add_argument("--identity-password")
    open_cmd.add_argument("--verify-only", action="store_true")
    open_cmd.add_argument("--allow-revoked-root", action="store_true")
    open_cmd.add_argument("--no-replay-check", action="store_true")
    open_cmd.add_argument("--debug-reason", action="store_true")

    keypart = sub.add_parser("keypart", aliases=_alias(aliases, "keypart"), help="manage opaque keypart files")
    keypart_sub = keypart.add_subparsers(dest="keypart_command", required=True)
    keypart_inspect = keypart_sub.add_parser("inspect")
    keypart_inspect.add_argument(*_opts(policy, "keypart", "--keypart", "-k"), dest="keypart", required=True)
    keypart_root = keypart_sub.add_parser("root", help="manage offline root keypart seeds")
    keypart_root_sub = keypart_root.add_subparsers(dest="root_command", required=True)
    keypart_root_create = keypart_root_sub.add_parser("create")
    keypart_root_create.add_argument("--out", required=True)
    keypart_root_create.add_argument("--password")
    keypart_root_create.add_argument("--label")
    keypart_root_inspect = keypart_root_sub.add_parser("inspect")
    keypart_root_inspect.add_argument("--in", dest="input", required=True)
    keypart_root_rotate = keypart_root_sub.add_parser("rotate")
    keypart_root_rotate.add_argument("--in", dest="input", required=True)
    keypart_root_rotate.add_argument("--out", required=True)
    keypart_root_rotate.add_argument("--password")
    keypart_root_retire = keypart_root_sub.add_parser("retire")
    keypart_root_retire.add_argument("--in", dest="input", required=True)
    keypart_root_retire.add_argument("--out", required=True)
    keypart_root_retire.add_argument("--password")
    keypart_root_revoke = keypart_root_sub.add_parser("revoke")
    keypart_root_revoke.add_argument("--in", dest="input", required=True)
    keypart_root_revoke.add_argument("--out", required=True)
    keypart_root_revoke.add_argument("--password")
    keypart_root_export = keypart_root_sub.add_parser("export-qr")
    keypart_root_export.add_argument("--in", dest="input", required=True)
    keypart_root_export.add_argument("--out", required=True)
    keypart_root_export.add_argument("--password")
    keypart_root_import = keypart_root_sub.add_parser("import")
    keypart_root_import.add_argument("--in", dest="input", required=True)
    keypart_root_import.add_argument("--out")
    keypart_root_import.add_argument("--password")
    keypart_root_import.add_argument("--label")
    keypart_root_import.add_argument("--root-store")
    keypart_root_list = keypart_root_sub.add_parser("list")
    keypart_root_list.add_argument("--root-store")
    keypart_root_show = keypart_root_sub.add_parser("show")
    keypart_root_show.add_argument("--fingerprint", required=True)
    keypart_root_show.add_argument("--root-store")
    keypart_root_remove = keypart_root_sub.add_parser("remove")
    keypart_root_remove.add_argument("--fingerprint", required=True)
    keypart_root_remove.add_argument("--root-store")
    keypart_root_remove.add_argument("--yes", action="store_true")
    keypart_root_split = keypart_root_sub.add_parser("split")
    keypart_root_split.add_argument("--in", dest="input", required=True)
    keypart_root_split.add_argument("--password")
    keypart_root_split.add_argument("--shares", type=int, required=True)
    keypart_root_split.add_argument("--threshold", type=int, required=True)
    keypart_root_split.add_argument("--out-dir", required=True)
    keypart_root_recover = keypart_root_sub.add_parser("recover")
    keypart_root_recover.add_argument("--shares", nargs="+", required=True)
    keypart_root_recover.add_argument("--out", required=True)
    keypart_root_recover.add_argument("--password")

    auth = sub.add_parser("auth", aliases=_alias(aliases, "auth"), help="manage one-time auth state")
    auth_sub = auth.add_subparsers(dest="auth_command", required=True)
    auth_destroy = auth_sub.add_parser("destroy")
    auth_destroy.add_argument(*_opts(policy, "auth_state", "--auth-state", "-a"), dest="auth_state", required=True)
    auth_seen = auth_sub.add_parser("seen")
    auth_seen_sub = auth_seen.add_subparsers(dest="seen_command", required=True)
    auth_seen_sub.add_parser("list")
    auth_seen_forget = auth_seen_sub.add_parser("forget")
    auth_seen_forget.add_argument("--msg-id", required=True)
    auth_seen_forget.add_argument("--yes", action="store_true")
    auth_seen_sub.add_parser("vacuum")

    contact = sub.add_parser("contact", help="manage recipient contacts")
    contact_sub = contact.add_subparsers(dest="contact_command", required=True)
    contact_add = contact_sub.add_parser("add")
    contact_add.add_argument("--in", dest="input", required=True)
    contact_add.add_argument("--alias")
    contact_import = contact_sub.add_parser("import")
    contact_import.add_argument("input")
    contact_import.add_argument("--alias")
    contact_sub.add_parser("list")
    contact_show = contact_sub.add_parser("show")
    contact_show.add_argument("--alias", required=True)
    contact_remove = contact_sub.add_parser("remove")
    contact_remove.add_argument("--alias", required=True)
    contact_remove.add_argument("--dry-run", action="store_true")
    contact_remove.add_argument("--yes", action="store_true")

    profile_cmd = sub.add_parser("profile", help="create/show profile safety configurations")
    profile_sub = profile_cmd.add_subparsers(dest="profile_command", required=True)
    profile_sub.add_parser("levels")
    profile_show = profile_sub.add_parser("show")
    profile_show.add_argument("--file")
    profile_create = profile_sub.add_parser("create")
    profile_create.add_argument("--out", required=True)
    profile_create.add_argument("--name", default=policy.get("node_name", "veil-node"))
    profile_create.add_argument("--level", choices=sorted(SECURITY_LEVELS), default="balanced")
    profile_create.add_argument("--containers", default="png,bmp,wav,mp4,zip,pdf,7z,vmsg")

    doctor_cmd = sub.add_parser("doctor", help="run local self checks")
    doctor_cmd.add_argument("--format", choices=["json"], default="json")

    audit_cmd = sub.add_parser("audit", help="audit local security posture")
    audit_cmd.add_argument("--format", choices=["json"], default="json")

    capacity_cmd = sub.add_parser("capacity", help="estimate carrier capacity and strategy")
    capacity_cmd.add_argument("--carrier")
    capacity_cmd.add_argument("--format", "-f", choices=sorted(SUPPORTED_FORMATS))
    capacity_cmd.add_argument("--payload-size", type=int)

    verify_carrier_cmd = sub.add_parser("verify-carrier", help="verify a carrier still opens/parses")
    verify_carrier_cmd.add_argument("--input", "-i", required=True)
    verify_carrier_cmd.add_argument("--format", "-f", choices=sorted(SUPPORTED_FORMATS))

    verify_only = sub.add_parser("verify-only", help="pre-verify a message without output or auth consumption")
    verify_only.add_argument("--input", "-i", required=True)
    verify_only.add_argument("--keypart", "-k")
    verify_only.add_argument("--root-keypart")
    verify_only.add_argument("--root-keypart-password")
    verify_only.add_argument("--root-store")
    verify_only.add_argument("--root-fingerprint")
    verify_only.add_argument("--auth-state", "-a")
    verify_only.add_argument("--password", "-p")
    verify_only.add_argument("--identity-password")
    verify_only.add_argument("--allow-revoked-root", action="store_true")
    verify_only.add_argument("--no-replay-check", action="store_true")
    verify_only.add_argument("--debug-reason", action="store_true")

    repair = sub.add_parser("repair", help="inspect and normalize recoverable local artifacts")
    repair_sub = repair.add_subparsers(dest="repair_command", required=True)
    repair_keypart_cmd = repair_sub.add_parser("keypart")
    repair_keypart_cmd.add_argument("--keypart", "-k", required=True)
    repair_keypart_cmd.add_argument("--out")
    repair_scan = repair_sub.add_parser("scan")
    repair_scan.add_argument("--dir", default=".")
    repair_scan.add_argument("--low-signature", action="store_true")

    migrate = sub.add_parser("migrate", help="migrate protocol metadata into a new artifact")
    migrate_sub = migrate.add_subparsers(dest="migrate_command", required=True)
    migrate_keypart_cmd = migrate_sub.add_parser("keypart")
    migrate_keypart_cmd.add_argument("--keypart", "-k", required=True)
    migrate_keypart_cmd.add_argument("--out", required=True)
    migrate_message_cmd = migrate_sub.add_parser("message")
    migrate_message_cmd.add_argument("--input", required=True)
    migrate_message_cmd.add_argument("--out", required=True)
    migrate_message_cmd.add_argument("--to-crypto-core", choices=["2.2"], required=True)
    migrate_root_cmd = migrate_sub.add_parser("root")
    migrate_root_cmd.add_argument("--in", dest="input", required=True)
    migrate_root_cmd.add_argument("--out", required=True)
    migrate_root_cmd.add_argument("--password")
    migrate_root_cmd.add_argument("--to-root-file-version", choices=["2"], required=True)

    carrier_cmd = sub.add_parser("carrier", help="audit, compare, and profile carrier files")
    carrier_sub = carrier_cmd.add_subparsers(dest="carrier_command", required=True)
    carrier_audit_cmd = carrier_sub.add_parser("audit")
    carrier_audit_cmd.add_argument("--input", required=True)
    carrier_audit_cmd.add_argument("--json", action="store_true")
    carrier_compare_cmd = carrier_sub.add_parser("compare")
    carrier_compare_cmd.add_argument("--before", required=True)
    carrier_compare_cmd.add_argument("--after", required=True)
    carrier_compare_cmd.add_argument("--json", action="store_true")
    carrier_profile = carrier_sub.add_parser("profile")
    carrier_profile_sub = carrier_profile.add_subparsers(dest="profile_command", required=True)
    carrier_profile_create = carrier_profile_sub.add_parser("create")
    carrier_profile_create.add_argument("--samples", required=True)
    carrier_profile_create.add_argument("--out", required=True)
    carrier_profile_inspect = carrier_profile_sub.add_parser("inspect")
    carrier_profile_inspect.add_argument("--in", dest="input", required=True)

    strategy_cmd = sub.add_parser("strategy", help="adaptive envelope policy engine")
    strategy_sub = strategy_cmd.add_subparsers(dest="strategy_command", required=True)
    strategy_features = strategy_sub.add_parser("features")
    strategy_features.add_argument("--carrier", required=True)
    strategy_features.add_argument("--payload", required=True)
    strategy_features.add_argument("--json", action="store_true")
    strategy_policy = strategy_sub.add_parser("policy")
    strategy_policy_sub = strategy_policy.add_subparsers(dest="policy_command", required=True)
    strategy_policy_inspect = strategy_policy_sub.add_parser("inspect")
    strategy_policy_inspect.add_argument("--in", dest="input", required=True)
    strategy_list = strategy_sub.add_parser("list")
    strategy_list.add_argument("--format")
    strategy_generate = strategy_sub.add_parser("generate")
    strategy_generate.add_argument("--carrier", required=True)
    strategy_generate.add_argument("--payload", required=True)
    strategy_generate.add_argument("--count", type=int, default=50)
    strategy_generate.add_argument("--json", action="store_true")
    strategy_score = strategy_sub.add_parser("score")
    strategy_score.add_argument("--before", required=True)
    strategy_score.add_argument("--after", required=True)
    strategy_score.add_argument("--policy", required=True)
    strategy_score.add_argument("--json", action="store_true")
    strategy_select = strategy_sub.add_parser("select")
    strategy_select.add_argument("--carrier", required=True)
    strategy_select.add_argument("--payload", required=True)
    strategy_select.add_argument("--count", type=int, default=50)
    strategy_select.add_argument("--policy-model")
    strategy_select.add_argument("--json", action="store_true")
    strategy_collect = strategy_sub.add_parser("collect")
    strategy_collect.add_argument("--samples-dir", required=True)
    strategy_collect.add_argument("--payloads-dir", required=True)
    strategy_collect.add_argument("--out", required=True)
    strategy_collect.add_argument("--candidates-per-sample", type=int, default=30)
    strategy_train = strategy_sub.add_parser("train")
    strategy_train.add_argument("--dataset", required=True)
    strategy_train.add_argument("--out", required=True)
    strategy_model = strategy_sub.add_parser("model")
    strategy_model_sub = strategy_model.add_subparsers(dest="model_command", required=True)
    strategy_model_inspect = strategy_model_sub.add_parser("inspect")
    strategy_model_inspect.add_argument("--in", dest="input", required=True)
    strategy_scan = strategy_sub.add_parser("scan-signature")
    strategy_scan.add_argument("--input", required=True)
    strategy_scan.add_argument("--json", action="store_true")

    safe = sub.add_parser("secure-delete", help="overwrite and delete a local file with explicit confirmation")
    safe.add_argument("--path", required=True)
    safe.add_argument("--dry-run", action="store_true")
    safe.add_argument("--yes", action="store_true")
    safe.add_argument("--confirm-text")

    package = sub.add_parser("package", help="build a cross-platform Python zipapp")
    package.add_argument("--out", required=True)
    package.add_argument("--release", action="store_true", help="build release artifact set into --out directory")

    sub.add_parser("test-vector", help="run stable cryptographic regression vectors")

    nodepkg = sub.add_parser("nodepkg", help="export/import/inspect .vpkg node packages")
    nodepkg_sub = nodepkg.add_subparsers(dest="nodepkg_command", required=True)
    nodepkg_export = nodepkg_sub.add_parser("export")
    nodepkg_export.add_argument("--out", required=True)
    nodepkg_export.add_argument("--no-contacts", action="store_true")
    nodepkg_import = nodepkg_sub.add_parser("import")
    nodepkg_import.add_argument("--in", dest="input", required=True)
    nodepkg_import.add_argument("--overwrite", action="store_true")
    nodepkg_inspect = nodepkg_sub.add_parser("inspect")
    nodepkg_inspect.add_argument("--in", dest="input", required=True)

    factory = sub.add_parser("factory", help="generate node programs and policies")
    factory_sub = factory.add_subparsers(dest="factory_command", required=True)
    node = factory_sub.add_parser("create-node")
    node.add_argument("--name", required=True)
    node.add_argument("--out-dir", default="nodes")
    node.add_argument("--chunk-size", type=int, default=65536)
    node.add_argument("--padding", choices=["none", "random", "bucket"], default="bucket")
    node.add_argument("--bucket-size", type=int, default=65536)
    node.add_argument("--containers", default="png,bmp,wav,mp4,zip,pdf,7z,vmsg")
    node.add_argument("--param-style", choices=["long", "short", "mixed"], default="mixed")
    node.add_argument("--init-identity-password")
    node.add_argument("--fast-kdf", action="store_true")
    policy_cmd = factory_sub.add_parser("write-policy")
    policy_cmd.add_argument("--out", required=True)
    policy_cmd.add_argument("--name", default="veil-node")
    policy_cmd.add_argument("--chunk-size", type=int, default=65536)
    policy_cmd.add_argument("--padding", choices=["none", "random", "bucket"], default="bucket")
    policy_cmd.add_argument("--bucket-size", type=int, default=65536)
    policy_cmd.add_argument("--containers", default="png,bmp,wav,mp4,zip,pdf,7z,vmsg")
    policy_cmd.add_argument("--fast-kdf", action="store_true")
    return parser


def _alias(aliases: dict, canonical: str) -> list[str]:
    alias = aliases.get(canonical)
    if alias in RESERVED_SUBCOMMANDS:
        return []
    return [alias] if alias and alias != canonical else []


def _opts(policy: dict, canonical: str, *defaults: str) -> list[str]:
    options = list(defaults)
    alias = policy.get("option_aliases", {}).get(canonical)
    if alias and alias not in options:
        options.append(alias)
    return options


def _dispatch(args: argparse.Namespace, policy: dict, home: Path) -> dict | None:
    store = IdentityStore(home)
    command = _canonical_command(args.command, policy)
    if command == "identity":
        return _identity(args, store, policy)
    if command == "send":
        password = _secret(args.password, "message password")
        recipients = [store.resolve_recipient(value) for value in args.recipient]
        root_seed = None
        root_metadata = None
        keypart_path = args.keypart
        if args.root_keypart or args.root_label or args.root_fingerprint or args.root_store:
            if args.keypart:
                raise VeilError("v2 root-keypart mode does not write an external --keypart")
            root = _open_root_from_args(args, home)
            root_seed = root.seed
            root_metadata = root.metadata
            if root.status != "active":
                raise VeilError("root is not active for sealing")
        elif args.no_external_keypart:
            raise VeilError("--no-external-keypart requires --root-keypart")
        elif not keypart_path:
            raise VeilError("send requires --keypart for v1 messages or --root-keypart for v2 messages")
        carrier_profile = _load_json_file(args.carrier_profile) if args.carrier_profile else None
        envelope_policy = _envelope_policy_from_args(args, carrier_path=args.carrier, payload_path=args.input)
        result = create_message(
            input_path=args.input,
            output_path=args.output,
            keypart_path=keypart_path,
            auth_state_path=args.auth_state,
            recipients=recipients,
            password=password,
            policy=policy,
            carrier_path=args.carrier,
            container_format=args.format,
            decoy_input=args.decoy_input,
            decoy_password=args.decoy_password,
            device_bound=args.device_bind,
            root_vkp_seed=root_seed,
            root_metadata=root_metadata,
            crypto_core_version=args.crypto_core,
            low_signature=args.low_signature,
            signature_profile=args.signature_profile,
            carrier_profile=carrier_profile,
            envelope_policy=envelope_policy,
        )
        if args.policy_out and envelope_policy is not None:
            result["policy_out"] = save_envelope_policy_file(envelope_policy, args.policy_out)
        return result
    if command == "seal":
        password = _secret(args.password, "message password")
        recipients = [store.resolve_recipient(value) for value in args.recipient]
        output = Path(args.output)
        root_seed = None
        root_metadata = None
        keypart_path = args.keypart or output.with_suffix(".vkp")
        if args.root_keypart or args.root_label or args.root_fingerprint or args.root_store:
            if args.keypart:
                raise VeilError("v2 root-keypart mode does not write an external --keypart")
            root = _open_root_from_args(args, home)
            root_seed = root.seed
            root_metadata = root.metadata
            if root.status != "active":
                raise VeilError("root is not active for sealing")
            keypart_path = None
        elif args.no_external_keypart:
            raise VeilError("--no-external-keypart requires --root-keypart")
        auth_state = args.auth_state or output.with_suffix(".vauth")
        if args.crypto_core == "2.2" and args.low_signature:
            state_dir = home / "state"
            state_dir.mkdir(parents=True, exist_ok=True)
            auth_state = state_dir / f"auth-{random.getrandbits(64):016x}.json"
        carrier_profile = _load_json_file(args.carrier_profile) if args.carrier_profile else None
        envelope_policy = _envelope_policy_from_args(args, carrier_path=args.carrier, payload_path=args.input)
        result = create_message(
            input_path=args.input,
            output_path=output,
            keypart_path=keypart_path,
            auth_state_path=auth_state,
            recipients=recipients,
            password=password,
            policy=policy,
            carrier_path=args.carrier,
            container_format=args.format,
            decoy_input=args.decoy_input,
            decoy_password=args.decoy_password,
            device_bound=args.device_bind,
            root_vkp_seed=root_seed,
            root_metadata=root_metadata,
            crypto_core_version=args.crypto_core,
            low_signature=args.low_signature,
            signature_profile=args.signature_profile,
            carrier_profile=carrier_profile,
            envelope_policy=envelope_policy,
        )
        if args.policy_out and envelope_policy is not None:
            result["policy_out"] = save_envelope_policy_file(envelope_policy, args.policy_out)
        return result
    if command == "receive":
        password = _secret(args.password, "message password")
        identity_password = _secret(args.identity_password, "identity password")
        private = store.load_private(identity_password)
        return receive_message(
            input_path=args.input,
            keypart_path=args.keypart,
            auth_state_path=args.auth_state,
            output_dir=args.output,
            identity=private,
            password=password,
            verify_only=args.verify_only,
        )
    if command == "open":
        password = _secret(args.password, "message password")
        identity_password = _secret(args.identity_password, "identity password")
        private = store.load_private(identity_password)
        detected_version = message_protocol_version(args.input)
        if args.root_keypart and args.keypart:
            raise VeilError("choose either --root-keypart or --keypart, not both")
        if args.root_keypart or args.root_fingerprint or args.root_store:
            if detected_version == 1:
                raise VeilError("This is a v1 external-keypart message. Use --keypart instead.")
            root = _open_root_from_args(args, home)
            if root.status == "revoked" and not args.allow_revoked_root:
                raise VeilDecryptError("Unable to open message.")
            return receive_message_v2(
                input_path=args.input,
                root_vkp_seed=root.seed,
                root_metadata=root.metadata,
                auth_state_path=args.auth_state or Path(args.input).with_suffix(".vauth"),
                output_dir=args.output,
                identity=private,
                password=password,
                verify_only=args.verify_only,
                seen_db_path=seen_db_path(home),
                no_replay_check=args.no_replay_check,
                allow_revoked_root=args.allow_revoked_root,
            )
        if detected_version == 2 and args.keypart:
            raise VeilError("This is a v2 root-keypart message. Use --root-keypart instead.")
        if not args.keypart:
            raise VeilError("open requires --keypart for v1 messages or --root-keypart for v2 messages")
        return receive_message(
            input_path=args.input,
            keypart_path=args.keypart,
            auth_state_path=args.auth_state or Path(args.keypart).with_suffix(".vauth"),
            output_dir=args.output,
            identity=private,
            password=password,
            verify_only=args.verify_only,
        )
    if command == "keypart":
        if args.keypart_command == "inspect":
            return inspect_keypart(args.keypart)
        if args.keypart_command == "root":
            return _root_keypart(args, policy, home)
    if command == "auth":
        if args.auth_command == "destroy":
            destroy_auth_state(args.auth_state)
            return {"destroyed": args.auth_state}
        if args.auth_command == "seen":
            db = seen_db_path(home)
            if args.seen_command == "list":
                return list_seen(db)
            if args.seen_command == "forget":
                return forget_seen(db, args.msg_id, confirm=args.yes)
            if args.seen_command == "vacuum":
                return vacuum_seen(db)
    if command == "contact":
        return _contact(args, store)
    if command == "profile":
        return _profile(args, policy)
    if command == "doctor":
        return doctor(home, policy)
    if command == "audit":
        return audit_home(home, policy)
    if command == "capacity":
        return capacity_report(args.carrier, args.format, args.payload_size)
    if command == "verify-carrier":
        return verify_carrier(args.input, args.format)
    if command == "verify-only":
        password = _secret(args.password, "message password")
        identity_password = _secret(args.identity_password, "identity password")
        private = store.load_private(identity_password)
        detected_version = message_protocol_version(args.input)
        if args.root_keypart or args.root_fingerprint or args.root_store:
            if detected_version == 1:
                raise VeilError("This is a v1 external-keypart message. Use --keypart instead.")
            root = _open_root_from_args(args, home)
            if root.status == "revoked" and not args.allow_revoked_root:
                raise VeilDecryptError("Unable to open message.")
            return receive_message_v2(
                input_path=args.input,
                root_vkp_seed=root.seed,
                root_metadata=root.metadata,
                auth_state_path=args.auth_state or Path(args.input).with_suffix(".vauth"),
                output_dir=home / ".verify-only-unused",
                identity=private,
                password=password,
                verify_only=True,
                seen_db_path=seen_db_path(home),
                no_replay_check=args.no_replay_check,
                allow_revoked_root=args.allow_revoked_root,
            )
        if detected_version == 2 and args.keypart:
            raise VeilError("This is a v2 root-keypart message. Use --root-keypart instead.")
        if not args.keypart:
            raise VeilError("verify-only requires --keypart for v1 messages or --root-keypart for v2 messages")
        return receive_message(
            input_path=args.input,
            keypart_path=args.keypart,
            auth_state_path=args.auth_state,
            output_dir=home / ".verify-only-unused",
            identity=private,
            password=password,
            verify_only=True,
        )
    if command == "repair":
        return _repair(args)
    if command == "migrate":
        return _migrate(args)
    if command == "carrier":
        return _carrier(args)
    if command == "strategy":
        return _strategy(args)
    if command == "secure-delete":
        if args.yes and args.confirm_text != "DELETE":
            raise VeilError("secure-delete requires --confirm-text DELETE when --yes is used")
        return secure_delete(args.path, confirm=args.yes, dry_run=args.dry_run)
    if command == "package":
        if args.release:
            return build_release_artifacts(args.out)
        return build_zipapp(args.out)
    if command == "test-vector":
        return run_vectors()
    if command == "nodepkg":
        return _nodepkg(args, store, policy)
    if command == "factory":
        return _factory(args)
    raise VeilError(f"unknown command: {args.command}")


def _identity(args: argparse.Namespace, store: IdentityStore, policy: dict) -> dict:
    if args.identity_command == "create":
        password = _secret(args.password, "identity password")
        return store.create(args.name, password, overwrite=args.overwrite, kdf=policy.get("kdf")).to_json()
    if args.identity_command == "export":
        return store.export_public(args.out).to_json()
    if args.identity_command == "import":
        public = store.import_public(args.input, args.alias)
        return {"imported": public.to_json(), "alias": args.alias or public.name}
    if args.identity_command == "list":
        return store.list_identities()
    if args.identity_command == "health":
        report = {"permissions": home_permission_report(store.home), "identity": store.list_identities()["private"]}
        if args.identity_password:
            private = store.load_private(args.identity_password)
            report["unlock"] = {"ok": True, "node_id": private.public.node_id}
        return report
    raise VeilError(f"unknown identity command: {args.identity_command}")


def _contact(args: argparse.Namespace, store: IdentityStore) -> dict:
    book = ContactBook(store)
    if args.contact_command in {"add", "import"}:
        return book.add(args.input, args.alias)
    if args.contact_command == "list":
        return book.list()
    if args.contact_command == "show":
        return book.show(args.alias)
    if args.contact_command == "remove":
        return book.remove(args.alias, confirm=args.yes, dry_run=args.dry_run)
    raise VeilError(f"unknown contact command: {args.contact_command}")


def _root_keypart(args: argparse.Namespace, policy: dict, home: Path) -> dict:
    if args.root_command == "create":
        password = _secret(args.password, "root keypart password")
        return seal_root_vkp_seed(create_root_vkp_seed(), password, args.out, policy.get("kdf"), label=args.label)
    if args.root_command == "inspect":
        return inspect_root_vkp_seed(args.input)
    if args.root_command == "rotate":
        password = _secret(args.password, "root keypart password")
        return rotate_root_vkp_seed(args.input, args.out, password, policy.get("kdf"))
    if args.root_command == "retire":
        password = _secret(args.password, "root keypart password")
        return set_root_vkp_seed_status(args.input, args.out, password, "retired", policy.get("kdf"))
    if args.root_command == "revoke":
        password = _secret(args.password, "root keypart password")
        return set_root_vkp_seed_status(args.input, args.out, password, "revoked", policy.get("kdf"))
    if args.root_command == "export-qr":
        password = _secret(args.password, "root keypart password")
        return export_root_vkp_seed(args.input, password, args.out)
    if args.root_command == "import":
        password = _secret(args.password, "root keypart password")
        if args.out:
            return import_root_vkp_seed(args.input, args.out, password, policy.get("kdf"), label=args.label)
        return import_root_to_store(args.input, password, home=home, root_store=args.root_store, label=args.label, kdf=policy.get("kdf"))
    if args.root_command == "list":
        return list_root_store(home=home, root_store=args.root_store)
    if args.root_command == "show":
        return show_root_in_store(args.fingerprint, home=home, root_store=args.root_store)
    if args.root_command == "remove":
        return remove_root_from_store(args.fingerprint, home=home, root_store=args.root_store, confirm=args.yes)
    if args.root_command == "split":
        password = _secret(args.password, "root keypart password")
        return split_root_vkp_seed(args.input, password, shares=args.shares, threshold=args.threshold, out_dir=args.out_dir)
    if args.root_command == "recover":
        password = _secret(args.password, "root keypart password")
        return recover_root_vkp_seed(args.shares, args.out, password, policy.get("kdf"))
    raise VeilError(f"unknown keypart root command: {args.root_command}")


def _nodepkg(args: argparse.Namespace, store: IdentityStore, policy: dict) -> dict:
    if args.nodepkg_command == "export":
        return export_nodepkg(store, args.out, policy, include_contacts=not args.no_contacts)
    if args.nodepkg_command == "import":
        return import_nodepkg(store, args.input, overwrite=args.overwrite)
    if args.nodepkg_command == "inspect":
        return inspect_nodepkg(args.input)
    raise VeilError(f"unknown nodepkg command: {args.nodepkg_command}")


def _profile(args: argparse.Namespace, policy: dict) -> dict:
    if args.profile_command == "levels":
        return {"levels": SECURITY_LEVELS}
    if args.profile_command == "show":
        if args.file:
            return profile_summary(load_policy(args.file))
        return profile_summary(policy)
    if args.profile_command == "create":
        profile = build_profile(
            name=args.name,
            security_level=args.level,
            containers=_containers(args.containers),
        )
        write_profile(args.out, profile)
        return {"profile": args.out, "summary": profile_summary(profile)}
    raise VeilError(f"unknown profile command: {args.profile_command}")


def _repair(args: argparse.Namespace) -> dict:
    if args.repair_command == "keypart":
        return repair_keypart(args.keypart, args.out)
    if args.repair_command == "scan":
        return recovery_scan(args.dir)
    raise VeilError(f"unknown repair command: {args.repair_command}")


def _migrate(args: argparse.Namespace) -> dict:
    if args.migrate_command == "keypart":
        return migrate_keypart(args.keypart, args.out)
    if args.migrate_command == "message":
        src = Path(args.input)
        dest = Path(args.out)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(src.read_bytes())
        return {
            "input": str(src),
            "output": str(dest),
            "to_crypto_core": args.to_crypto_core,
            "note": "message bytes copied; cryptographic re-sealing to 2.2 requires the original open credentials",
        }
    if args.migrate_command == "root":
        password = _secret(args.password, "root keypart password")
        root = open_root_vkp_seed_info(args.input, password)
        return seal_root_vkp_seed(root.seed, password, args.out, metadata=root.metadata)
    raise VeilError(f"unknown migrate command: {args.migrate_command}")


def _carrier(args: argparse.Namespace) -> dict:
    if args.carrier_command == "audit":
        return carrier_audit(args.input, as_json=args.json)
    if args.carrier_command == "compare":
        return carrier_compare(args.before, args.after, as_json=args.json)
    if args.carrier_command == "profile":
        if args.profile_command == "create":
            return create_carrier_profile(args.samples, args.out)
        if args.profile_command == "inspect":
            return inspect_carrier_profile(args.input)
    raise VeilError(f"unknown carrier command: {args.carrier_command}")


def _strategy(args: argparse.Namespace) -> dict:
    if args.strategy_command == "features":
        return extract_features(args.carrier, args.payload)
    if args.strategy_command == "policy":
        if args.policy_command == "inspect":
            return inspect_envelope_policy(args.input)
    if args.strategy_command == "list":
        return list_strategies(args.format)
    if args.strategy_command == "generate":
        return generate_policies(args.carrier, args.payload, count=args.count, low_signature=True)
    if args.strategy_command == "score":
        return score_json(args.before, args.after, args.policy)
    if args.strategy_command == "select":
        return select_policy(args.carrier, args.payload, count=args.count, model_path=args.policy_model, low_signature=True)
    if args.strategy_command == "collect":
        return collect_dataset(args.samples_dir, args.payloads_dir, args.out, candidates_per_sample=args.candidates_per_sample)
    if args.strategy_command == "train":
        return train_strategy_model(args.dataset, args.out)
    if args.strategy_command == "model":
        if args.model_command == "inspect":
            return inspect_model(args.input)
    if args.strategy_command == "scan-signature":
        return scan_fixed_signatures(args.input)
    raise VeilError(f"unknown strategy command: {args.strategy_command}")


def _factory(args: argparse.Namespace) -> dict:
    containers = _containers(args.containers)
    if args.factory_command == "create-node":
        return create_node(
            name=args.name,
            out_dir=args.out_dir,
            chunk_size=args.chunk_size,
            padding=args.padding,
            bucket_size=args.bucket_size,
            containers=containers,
            param_style=args.param_style,
            init_identity_password=args.init_identity_password,
            fast_kdf=args.fast_kdf,
        )
    if args.factory_command == "write-policy":
        policy = write_policy(
            out=args.out,
            name=args.name,
            chunk_size=args.chunk_size,
            padding=args.padding,
            bucket_size=args.bucket_size,
            containers=containers,
            fast_kdf=args.fast_kdf,
        )
        return {"policy": args.out, "config": policy}
    raise VeilError(f"unknown factory command: {args.factory_command}")


def _canonical_command(command: str, policy: dict) -> str:
    aliases = policy.get("command_aliases", {})
    for canonical, alias in aliases.items():
        if command == alias:
            return canonical
    return command


def _containers(raw: str) -> list[str]:
    values = [x.strip().lower().lstrip(".") for x in raw.split(",") if x.strip()]
    invalid = [x for x in values if x not in SUPPORTED_FORMATS]
    if invalid:
        raise VeilError(f"unsupported containers: {', '.join(invalid)}")
    return values


def _secret(value: str | None, label: str) -> str:
    if value is not None:
        return value
    return getpass.getpass(f"{label}: ")


def _open_root_from_args(args: argparse.Namespace, home: Path):
    password = _secret(getattr(args, "root_keypart_password", None), "root keypart password")
    root_path = getattr(args, "root_keypart", None)
    if root_path:
        return open_root_vkp_seed_info(root_path, password)
    return resolve_root_from_store(
        password=password,
        home=home,
        root_store=getattr(args, "root_store", None),
        fingerprint_value=getattr(args, "root_fingerprint", None),
        label=getattr(args, "root_label", None),
    )


def _load_json_file(path: str | None) -> dict | None:
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _envelope_policy_from_args(args: argparse.Namespace, *, carrier_path: str | Path | None, payload_path: str | Path):
    if getattr(args, "policy_in", None):
        policy = load_envelope_policy_file(args.policy_in)
        policy.validate()
        if carrier_path:
            validation = verify_carrier(carrier_path, policy.carrier_format)
            if not validation.get("ok"):
                raise VeilError("policy-in carrier failed verify-carrier")
        return policy
    if getattr(args, "adaptive_policy", False):
        if not carrier_path:
            raise VeilError("--adaptive-policy requires an explicit carrier file")
        selected = select_policy(
            carrier_path,
            payload_path,
            count=max(1, int(getattr(args, "policy_candidates", 50))),
            model_path=getattr(args, "policy_model", None),
            low_signature=True,
        )
        return EnvelopePolicy.from_json(selected["selected_policy"])
    return None
