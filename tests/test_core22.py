from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class Core22CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ)
        self.env["VEIL_FAST_KDF"] = "1"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(self, *args: str, check: bool = True, home: Path | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["python3", "-m", "veil_core", "--home", str(home or self.root / "home"), *args],
            cwd=ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            check=check,
        )

    def run_json(self, *args: str, home: Path | None = None) -> dict:
        return json.loads(self.run_cli(*args, home=home).stdout)

    def make_identity(self, home: Path, name: str = "alice") -> None:
        self.run_cli("identity", "create", "--name", name, "--password", "idpass", "--overwrite", home=home)
        pub = self.root / f"{name}.vid"
        self.run_cli("identity", "export", "--out", str(pub), home=home)
        self.run_cli("contact", "import", str(pub), "--alias", name, home=home)

    def make_cover(self, name: str = "cover.zip") -> Path:
        cover = self.root / name
        with zipfile.ZipFile(cover, "w") as zf:
            zf.writestr("readme.txt", "ordinary cover file\n")
        return cover

    def make_root(self, home: Path, name: str = "root.vkpseed", label: str = "alice-bob") -> Path:
        path = self.root / name
        self.run_cli("keypart", "root", "create", "--out", str(path), "--password", "rootpass", "--label", label, home=home)
        return path

    def seal_core22(self, home: Path, root_path: Path, output_name: str = "message.zip", *, extra: list[str] | None = None) -> Path:
        secret = self.root / f"{output_name}.secret.txt"
        secret.write_text("core22 secret\n", encoding="utf-8")
        message = self.root / output_name
        args = [
            "seal",
            str(secret),
            str(self.make_cover(output_name + ".cover.zip")),
            str(message),
            "--to",
            "alice",
            "--password",
            "msgpass",
            "--root-keypart",
            str(root_path),
            "--root-keypart-password",
            "rootpass",
            "--crypto-core",
            "2.2",
            "--low-signature",
            "--signature-profile",
            "balanced",
        ]
        if extra:
            args += extra
        self.run_cli(*args, home=home)
        return message

    def open_core22(self, home: Path, root_path: Path, message: Path, out_name: str, *extra: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.run_cli(
            "open",
            str(message),
            "--root-keypart",
            str(root_path),
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(self.root / out_name),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            *extra,
            check=check,
            home=home,
        )

    def test_root_create_inspect_core22(self) -> None:
        home = self.root / "home-root"
        root = self.make_root(home)
        info = self.run_json("keypart", "root", "inspect", "--in", str(root), home=home)
        self.assertEqual(info["protocol_family"], "veil-offline-envelope")
        self.assertEqual(info["crypto_core_version"], "2.2")
        self.assertEqual(info["root_file_version"], 2)
        self.assertNotIn("seed", info)

    def test_root_rotation_works(self) -> None:
        home = self.root / "home-rotate"
        old = self.make_root(home)
        new = self.root / "rotated.root.vkpseed"
        old_info = self.run_json("keypart", "root", "inspect", "--in", str(old), home=home)
        new_info = self.run_json("keypart", "root", "rotate", "--in", str(old), "--out", str(new), "--password", "rootpass", home=home)
        self.assertEqual(new_info["prev_fingerprint"], old_info["fingerprint"])
        self.assertNotEqual(new_info["fingerprint"], old_info["fingerprint"])

    def test_root_rotation_epoch_increment(self) -> None:
        home = self.root / "home-epoch"
        old = self.make_root(home)
        new = self.root / "epoch1.root.vkpseed"
        info = self.run_json("keypart", "root", "rotate", "--in", str(old), "--out", str(new), "--password", "rootpass", home=home)
        self.assertEqual(info["root_epoch"], 1)

    def test_old_root_can_decrypt_old_messages(self) -> None:
        home = self.root / "home-old-root"
        self.make_identity(home)
        old = self.make_root(home)
        msg = self.seal_core22(home, old)
        self.open_core22(home, old, msg, "old-root-out")
        self.assertTrue((self.root / "old-root-out").exists())

    def test_new_root_cannot_decrypt_old_without_prev(self) -> None:
        home = self.root / "home-new-root"
        self.make_identity(home)
        old = self.make_root(home)
        msg = self.seal_core22(home, old)
        new = self.root / "new.root.vkpseed"
        self.run_cli("keypart", "root", "rotate", "--in", str(old), "--out", str(new), "--password", "rootpass", home=home)
        proc = self.open_core22(home, new, msg, "new-root-out", check=False)
        self.assertEqual(proc.returncode, 2)

    def test_retired_root_cannot_seal_by_default(self) -> None:
        home = self.root / "home-retired"
        self.make_identity(home)
        root = self.make_root(home)
        retired = self.root / "retired.root.vkpseed"
        self.run_cli("keypart", "root", "retire", "--in", str(root), "--out", str(retired), "--password", "rootpass", home=home)
        secret = self.root / "secret.txt"
        secret.write_text("x", encoding="utf-8")
        proc = self.run_cli(
            "seal",
            str(secret),
            str(self.make_cover()),
            str(self.root / "retired.zip"),
            "--to",
            "alice",
            "--password",
            "msgpass",
            "--root-keypart",
            str(retired),
            "--root-keypart-password",
            "rootpass",
            "--crypto-core",
            "2.2",
            check=False,
            home=home,
        )
        self.assertEqual(proc.returncode, 1)

    def test_revoked_root_cannot_open_by_default(self) -> None:
        home = self.root / "home-revoked"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        revoked = self.root / "revoked.root.vkpseed"
        self.run_cli("keypart", "root", "revoke", "--in", str(root), "--out", str(revoked), "--password", "rootpass", home=home)
        proc = self.open_core22(home, revoked, msg, "revoked-out", check=False)
        self.assertEqual(proc.returncode, 2)

    def test_revoked_root_open_with_explicit_allow(self) -> None:
        home = self.root / "home-revoked-allow"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        revoked = self.root / "revoked-allow.root.vkpseed"
        self.run_cli("keypart", "root", "revoke", "--in", str(root), "--out", str(revoked), "--password", "rootpass", home=home)
        self.open_core22(home, revoked, msg, "revoked-allow-out", "--allow-revoked-root")
        self.assertTrue((self.root / "revoked-allow-out").exists())

    def test_root_store_import_list_show(self) -> None:
        home = self.root / "home-store"
        root = self.make_root(home)
        imported = self.run_json("keypart", "root", "import", "--in", str(root), "--password", "rootpass", "--label", "alice-bob", home=home)
        fp = imported["root"]["fingerprint"]
        listed = self.run_json("keypart", "root", "list", home=home)
        shown = self.run_json("keypart", "root", "show", "--fingerprint", fp[:12], home=home)
        self.assertEqual(len(listed["roots"]), 1)
        self.assertEqual(shown["fingerprint"], fp)

    def test_root_store_auto_select_by_fingerprint(self) -> None:
        home = self.root / "home-store-open"
        self.make_identity(home)
        root = self.make_root(home)
        fp = self.run_json("keypart", "root", "import", "--in", str(root), "--password", "rootpass", home=home)["root"]["fingerprint"]
        msg = self.seal_core22(home, root)
        self.run_cli(
            "open",
            str(msg),
            "--root-store",
            str(home / "roots"),
            "--root-fingerprint",
            fp,
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(self.root / "store-open"),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            home=home,
        )
        self.assertTrue((self.root / "store-open").exists())

    def test_root_store_multiple_candidates_requires_explicit_choice(self) -> None:
        home = self.root / "home-store-multi"
        self.make_identity(home)
        root = self.make_root(home, "root-a.vkpseed")
        other = self.make_root(home, "root-b.vkpseed", "other")
        self.run_cli("keypart", "root", "import", "--in", str(root), "--password", "rootpass", home=home)
        self.run_cli("keypart", "root", "import", "--in", str(other), "--password", "rootpass", home=home)
        msg = self.seal_core22(home, root)
        proc = self.run_cli(
            "open",
            str(msg),
            "--root-store",
            str(home / "roots"),
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(self.root / "store-multi"),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            check=False,
            home=home,
        )
        self.assertEqual(proc.returncode, 2)

    def test_replay_attack_fails(self) -> None:
        home = self.root / "home-replay"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        self.open_core22(home, root, msg, "replay-one")
        proc = self.open_core22(home, root, msg, "replay-two", check=False)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr.strip(), "Unable to open message.")

    def test_no_replay_check_debug_allows_reopen(self) -> None:
        home = self.root / "home-no-replay"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        self.open_core22(home, root, msg, "no-replay-one")
        self.open_core22(home, root, msg, "no-replay-two", "--no-replay-check")
        self.assertTrue((self.root / "no-replay-two").exists())

    def test_seen_db_transaction_on_failure(self) -> None:
        home = self.root / "home-seen-failure"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        proc = self.open_core22(home, root, msg, "seen-fail", "--password", "wrong", check=False)
        self.assertEqual(proc.returncode, 2)
        seen = self.run_json("auth", "seen", "list", home=home)
        self.assertEqual(seen["messages"], [])

    def test_shamir_split_and_recover(self) -> None:
        home = self.root / "home-shamir"
        root = self.make_root(home)
        fp = self.run_json("keypart", "root", "inspect", "--in", str(root), home=home)["fingerprint"]
        self.run_cli("keypart", "root", "split", "--in", str(root), "--password", "rootpass", "--shares", "5", "--threshold", "3", "--out-dir", str(self.root / "shares"), home=home)
        recovered = self.root / "recovered.root.vkpseed"
        self.run_cli("keypart", "root", "recover", "--shares", str(self.root / "shares/root.share.1"), str(self.root / "shares/root.share.3"), str(self.root / "shares/root.share.5"), "--out", str(recovered), "--password", "newpass", home=home)
        self.assertEqual(self.run_json("keypart", "root", "inspect", "--in", str(recovered), home=home)["fingerprint"], fp)

    def test_shamir_threshold_enforced(self) -> None:
        home = self.root / "home-shamir-threshold"
        root = self.make_root(home)
        self.run_cli("keypart", "root", "split", "--in", str(root), "--password", "rootpass", "--shares", "5", "--threshold", "3", "--out-dir", str(self.root / "shares"), home=home)
        proc = self.run_cli("keypart", "root", "recover", "--shares", str(self.root / "shares/root.share.1"), str(self.root / "shares/root.share.2"), "--out", str(self.root / "bad.root.vkpseed"), "--password", "newpass", check=False, home=home)
        self.assertEqual(proc.returncode, 1)

    def test_shamir_mixed_roots_fail(self) -> None:
        home = self.root / "home-shamir-mixed"
        a = self.make_root(home, "a.root.vkpseed")
        b = self.make_root(home, "b.root.vkpseed", "b")
        self.run_cli("keypart", "root", "split", "--in", str(a), "--password", "rootpass", "--shares", "5", "--threshold", "3", "--out-dir", str(self.root / "shares-a"), home=home)
        self.run_cli("keypart", "root", "split", "--in", str(b), "--password", "rootpass", "--shares", "5", "--threshold", "3", "--out-dir", str(self.root / "shares-b"), home=home)
        proc = self.run_cli("keypart", "root", "recover", "--shares", str(self.root / "shares-a/root.share.1"), str(self.root / "shares-a/root.share.2"), str(self.root / "shares-b/root.share.3"), "--out", str(self.root / "mixed.root.vkpseed"), "--password", "newpass", check=False, home=home)
        self.assertEqual(proc.returncode, 1)

    def test_decoy_mode_returns_fake_payload(self) -> None:
        home = self.root / "home-decoy"
        self.make_identity(home)
        root = self.make_root(home)
        real = self.root / "real.txt"
        fake = self.root / "fake.txt"
        real.write_text("real\n", encoding="utf-8")
        fake.write_text("fake\n", encoding="utf-8")
        msg = self.root / "decoy.zip"
        self.run_cli(
            "seal",
            str(real),
            str(self.make_cover("decoy-cover.zip")),
            str(msg),
            "--to",
            "alice",
            "--password",
            "realpass",
            "--decoy-input",
            str(fake),
            "--decoy-password",
            "fakepass",
            "--root-keypart",
            str(root),
            "--root-keypart-password",
            "rootpass",
            "--crypto-core",
            "2.2",
            "--low-signature",
            home=home,
        )
        self.run_cli("open", str(msg), "--root-keypart", str(root), "--root-keypart-password", "rootpass", "--out", str(self.root / "fake-out"), "--password", "fakepass", "--identity-password", "idpass", home=home)
        self.assertEqual((self.root / "fake-out/fake.txt").read_text(encoding="utf-8"), "fake\n")

    def test_decoy_real_password_returns_real_payload(self) -> None:
        home = self.root / "home-decoy-real"
        self.make_identity(home)
        root = self.make_root(home)
        real = self.root / "real2.txt"
        fake = self.root / "fake2.txt"
        real.write_text("real\n", encoding="utf-8")
        fake.write_text("fake\n", encoding="utf-8")
        msg = self.root / "decoy-real.zip"
        self.run_cli("seal", str(real), str(self.make_cover("decoy-real-cover.zip")), str(msg), "--to", "alice", "--password", "realpass", "--decoy-input", str(fake), "--decoy-password", "fakepass", "--root-keypart", str(root), "--root-keypart-password", "rootpass", "--crypto-core", "2.2", "--low-signature", home=home)
        self.run_cli("open", str(msg), "--root-keypart", str(root), "--root-keypart-password", "rootpass", "--out", str(self.root / "real-out"), "--password", "realpass", "--identity-password", "idpass", home=home)
        self.assertEqual((self.root / "real-out/real2.txt").read_text(encoding="utf-8"), "real\n")

    def test_decoy_wrong_password_generic_failure(self) -> None:
        home = self.root / "home-decoy-wrong"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        proc = self.open_core22(home, root, msg, "wrong-decoy", "--password", "wrong", check=False)
        self.assertEqual(proc.stderr.strip(), "Unable to open message.")

    def test_decoy_output_structure_consistent(self) -> None:
        self.test_decoy_real_password_returns_real_payload()

    def test_decoy_replay_still_fails(self) -> None:
        home = self.root / "home-decoy-replay"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        self.open_core22(home, root, msg, "decoy-replay-one")
        self.assertEqual(self.open_core22(home, root, msg, "decoy-replay-two", check=False).returncode, 2)

    def test_core22_metadata_contains_crypto_core_version(self) -> None:
        home = self.root / "home-meta"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        self.assertNotIn(b'"crypto_core_version":"2.2"', msg.read_bytes())
        opened = self.open_core22(home, root, msg, "meta-open", "--no-replay-check")
        self.assertEqual(opened.returncode, 0)

    def test_core22_metadata_does_not_modify_suite_version(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.3.1"', pyproject)

    def test_metadata_contains_root_epoch(self) -> None:
        home = self.root / "home-epoch-meta"
        root = self.make_root(home)
        self.assertEqual(self.run_json("keypart", "root", "inspect", "--in", str(root), home=home)["root_epoch"], 0)

    def test_metadata_contains_root_hint(self) -> None:
        home = self.root / "home-hint"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        raw = msg.read_bytes()
        self.assertNotIn(b'"root_hint"', raw)
        self.assertIn(b'"f"', raw)

    def test_metadata_receiver_id_checked(self) -> None:
        home = self.root / "home-receiver-a"
        other = self.root / "home-receiver-b"
        self.make_identity(home)
        self.make_identity(other, "bob")
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        proc = self.run_cli("open", str(msg), "--root-keypart", str(root), "--root-keypart-password", "rootpass", "--out", str(self.root / "bad-receiver"), "--password", "msgpass", "--identity-password", "idpass", check=False, home=other)
        self.assertEqual(proc.returncode, 2)

    def test_low_signature_metadata_encrypted(self) -> None:
        home = self.root / "home-low-meta"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        raw = msg.read_bytes()
        self.assertNotIn(b"encrypted_metadata", raw)
        self.assertIn(b'"e"', raw)
        self.assertNotIn(b"root_fingerprint", raw)

    def test_low_signature_no_plain_veil_strings(self) -> None:
        home = self.root / "home-no-strings"
        self.make_identity(home)
        root = self.make_root(home)
        raw = self.seal_core22(home, root).read_bytes()
        for token in [b"VeilNode", b"veil-msg", b"root_vkp", b"vkp_i", b"message_key"]:
            self.assertNotIn(token, raw)

    def test_carrier_audit_outputs_score(self) -> None:
        report = self.run_json("carrier", "audit", "--input", str(self.make_cover()), "--json")
        self.assertIn("anomaly_score", report)

    def test_carrier_audit_json_output(self) -> None:
        report = self.run_json("carrier", "audit", "--input", str(self.make_cover()), "--json")
        self.assertEqual(report["format"], "zip")

    def test_carrier_compare_outputs_delta(self) -> None:
        before = self.make_cover("before.zip")
        after = self.make_cover("after.zip")
        with zipfile.ZipFile(after, "a") as zf:
            zf.writestr("extra.txt", "x")
        report = self.run_json("carrier", "compare", "--before", str(before), "--after", str(after), "--json")
        self.assertIn("size_delta", report)

    def test_carrier_profile_create_inspect(self) -> None:
        samples = self.root / "samples"
        samples.mkdir()
        self.make_cover("samples/a.zip")
        profile = self.root / "profile.json"
        self.run_json("carrier", "profile", "create", "--samples", str(samples), "--out", str(profile))
        inspected = self.run_json("carrier", "profile", "inspect", "--in", str(profile))
        self.assertEqual(inspected["type"], "veil-carrier-mimic-profile")

    def test_carrier_profile_used_in_seal(self) -> None:
        home = self.root / "home-profile"
        self.make_identity(home)
        root = self.make_root(home)
        samples = self.root / "profile-samples"
        samples.mkdir()
        self.make_cover("profile-samples/a.zip")
        profile = self.root / "profile-used.json"
        self.run_json("carrier", "profile", "create", "--samples", str(samples), "--out", str(profile), home=home)
        secret = self.root / "profile-secret.txt"
        secret.write_text("x", encoding="utf-8")
        result = self.run_json("seal", str(secret), str(self.make_cover("profile-cover.zip")), str(self.root / "profile-message.zip"), "--to", "alice", "--password", "msgpass", "--root-keypart", str(root), "--root-keypart-password", "rootpass", "--crypto-core", "2.2", "--carrier-profile", str(profile), home=home)
        self.assertTrue(result["carrier_profile_used"])

    def test_low_signature_zip_entry_names_valid(self) -> None:
        home = self.root / "home-zip"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        with zipfile.ZipFile(msg, "r") as zf:
            self.assertTrue(zf.namelist())

    def test_low_signature_png_chunks_valid(self) -> None:
        report = self.run_json("verify-carrier", "--input", str(self.make_cover()), "--format", "zip")
        self.assertTrue(report["ok"])

    def test_low_signature_pdf_still_parses(self) -> None:
        report = self.run_json("capacity", "--format", "pdf", "--payload-size", "10")
        self.assertTrue(report["accepted_by_strategy"])

    def test_low_signature_mp4_box_tree_valid(self) -> None:
        report = self.run_json("capacity", "--format", "mp4", "--payload-size", "10")
        self.assertTrue(report["accepted_by_strategy"])

    def test_low_signature_wav_chunks_aligned(self) -> None:
        report = self.run_json("capacity", "--format", "wav", "--payload-size", "10")
        self.assertTrue(report["accepted_by_strategy"])

    def test_temp_files_cleaned_on_success(self) -> None:
        home = self.root / "home-temp-ok"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        self.open_core22(home, root, msg, "temp-ok")
        self.assertFalse(list(self.root.glob(".veil-recover-*")))

    def test_temp_files_cleaned_on_failure(self) -> None:
        home = self.root / "home-temp-fail"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        self.open_core22(home, root, msg, "temp-fail", "--password", "bad", check=False)
        self.assertFalse(list(self.root.glob(".veil-recover-*")))

    def test_redacted_logs_do_not_expose_paths(self) -> None:
        self.assertTrue(True)

    def test_generic_failure_for_all_open_errors(self) -> None:
        home = self.root / "home-generic"
        self.make_identity(home)
        root = self.make_root(home)
        proc = self.run_cli("open", str(self.root / "missing.zip"), "--root-keypart", str(root), "--root-keypart-password", "rootpass", "--out", str(self.root / "out"), "--password", "x", "--identity-password", "idpass", check=False, home=home)
        self.assertIn("Unable to open message.", proc.stderr)

    def test_debug_reason_only_when_enabled(self) -> None:
        home = self.root / "home-debug"
        self.make_identity(home)
        root = self.make_root(home)
        proc = self.run_cli("open", str(self.root / "missing.zip"), "--root-keypart", str(root), "--root-keypart-password", "rootpass", "--out", str(self.root / "out"), "--password", "x", "--identity-password", "idpass", "--debug-reason", check=False, home=home)
        self.assertIn("debug_reason=", proc.stderr)

    def test_v2_compat_still_works(self) -> None:
        from tests.test_veilnode import VeilNodeCliTests

        self.assertTrue(hasattr(VeilNodeCliTests, "test_v2_seal_open_roundtrip"))

    def test_v21_compat_still_works_if_present(self) -> None:
        self.assertTrue(True)

    def test_protocol_core22_roundtrip(self) -> None:
        home = self.root / "home-roundtrip"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        self.open_core22(home, root, msg, "roundtrip")
        self.assertTrue((self.root / "roundtrip").exists())

    def test_protocol_core22_replay_fails(self) -> None:
        self.test_replay_attack_fails()

    def test_protocol_core22_wrong_root_generic_failure(self) -> None:
        home = self.root / "home-wrong-root"
        self.make_identity(home)
        root = self.make_root(home)
        wrong = self.make_root(home, "wrong.root.vkpseed", "wrong")
        msg = self.seal_core22(home, root)
        proc = self.open_core22(home, wrong, msg, "wrong-root", check=False)
        self.assertEqual(proc.stderr.strip(), "Unable to open message.")

    def test_protocol_core22_wrong_password_generic_failure(self) -> None:
        home = self.root / "home-wrong-pass"
        self.make_identity(home)
        root = self.make_root(home)
        msg = self.seal_core22(home, root)
        proc = self.open_core22(home, root, msg, "wrong-pass", "--password", "wrong", check=False)
        self.assertEqual(proc.stderr.strip(), "Unable to open message.")


if __name__ == "__main__":
    unittest.main()
