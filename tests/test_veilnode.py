from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
import wave
import zipfile
from pathlib import Path

from veil_core.container import embed_payload, extract_payload, generate_carrier
from veil_core.factory import create_node
from veil_core.api import VeilAPI
from veil_core.crypto import b64e
from veil_core.keypart import open_root_vkp_seed


ROOT = Path(__file__).resolve().parents[1]


class VeilNodeCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.env = dict(os.environ)
        self.env["VEIL_FAST_KDF"] = "1"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_cli(self, *args: str, check: bool = True, home: Path | None = None) -> subprocess.CompletedProcess:
        cmd = ["python3", "-m", "veil_core", "--home", str(home or self.root / "home"), *args]
        return subprocess.run(cmd, cwd=ROOT, env=self.env, text=True, capture_output=True, check=check)

    def run_json(self, *args: str, home: Path | None = None) -> dict:
        proc = self.run_cli(*args, home=home)
        return json.loads(proc.stdout)

    def make_identity(self, home: Path, name: str, password: str) -> Path:
        self.run_cli("identity", "create", "--name", name, "--password", password, "--overwrite", home=home)
        pub = self.root / f"{name}.vid"
        self.run_cli("identity", "export", "--out", str(pub), home=home)
        return pub

    def make_v2_message(self, *, suffix: str = "") -> dict[str, Path | str]:
        home = self.root / f"v2-home{suffix}"
        pub = self.make_identity(home, f"alice{suffix}", "idpass")
        self.run_cli("contact", "import", str(pub), "--alias", "alice", home=home)
        root_seed = self.root / f"alice_bob{suffix}.root.vkpseed"
        self.run_cli("keypart", "root", "create", "--out", str(root_seed), "--password", "rootpass", home=home)
        secret = self.root / f"secret{suffix}.txt"
        secret.write_text("v2 secret payload\n", encoding="utf-8")
        cover = self.root / f"cover{suffix}.zip"
        with zipfile.ZipFile(cover, "w") as zf:
            zf.writestr("readme.txt", "ordinary cover file\n")
        message = self.root / f"message{suffix}.zip"
        result = self.run_json(
            "seal",
            str(secret),
            str(cover),
            str(message),
            "--to",
            "alice",
            "--password",
            "msgpass",
            "--root-keypart",
            str(root_seed),
            "--root-keypart-password",
            "rootpass",
            "--no-external-keypart",
            home=home,
        )
        return {"home": home, "root": root_seed, "secret": secret, "cover": cover, "message": message, "result": result}

    def test_root_vkp_create_inspect(self) -> None:
        home = self.root / "root-home"
        root_seed = self.root / "root.vkpseed"
        created = self.run_json("keypart", "root", "create", "--out", str(root_seed), "--password", "rootpass", home=home)
        inspected = self.run_json("keypart", "root", "inspect", "--in", str(root_seed), home=home)
        self.assertEqual(created["kind"], "veil-root-vkpseed")
        self.assertEqual(inspected["version"], 1)
        self.assertEqual(inspected["protocol_version"], 2)
        self.assertEqual(created["fingerprint"], inspected["fingerprint"])
        self.assertNotIn("seed", inspected)
        export = self.root / "root.txt"
        exported = self.run_json(
            "keypart",
            "root",
            "export-qr",
            "--in",
            str(root_seed),
            "--out",
            str(export),
            "--password",
            "rootpass",
            home=home,
        )
        imported_seed = self.root / "imported.root.vkpseed"
        imported = self.run_json(
            "keypart",
            "root",
            "import",
            "--in",
            str(export),
            "--out",
            str(imported_seed),
            "--password",
            "rootpass",
            home=home,
        )
        self.assertEqual(exported["fingerprint"], imported["fingerprint"])
        rotated_seed = self.root / "rotated.root.vkpseed"
        rotated = self.run_json(
            "keypart",
            "root",
            "rotate",
            "--in",
            str(root_seed),
            "--out",
            str(rotated_seed),
            "--password",
            "rootpass",
            home=home,
        )
        self.assertNotEqual(rotated["fingerprint"], inspected["fingerprint"])

    def test_v2_seal_open_roundtrip(self) -> None:
        ctx = self.make_v2_message(suffix="-roundtrip")
        out = self.root / "v2-out"
        self.run_cli(
            "open",
            str(ctx["message"]),
            "--root-keypart",
            str(ctx["root"]),
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(out),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            home=ctx["home"],  # type: ignore[arg-type]
        )
        self.assertEqual((out / "secret-roundtrip.txt").read_text(encoding="utf-8"), "v2 secret payload\n")

    def test_v2_no_external_vkp_created(self) -> None:
        ctx = self.make_v2_message(suffix="-novkp")
        message = Path(ctx["message"])  # type: ignore[arg-type]
        self.assertFalse(message.with_suffix(".vkp").exists())
        self.assertTrue(message.with_suffix(".vauth").exists())
        self.assertFalse(ctx["result"]["external_keypart"])  # type: ignore[index]
        seed = open_root_vkp_seed(ctx["root"], "rootpass")  # type: ignore[arg-type]
        self.assertNotIn(b64e(seed).encode("ascii"), message.read_bytes())

    def test_v2_wrong_root_vkp_fails(self) -> None:
        ctx = self.make_v2_message(suffix="-wrongroot")
        wrong_root = self.root / "wrong.root.vkpseed"
        self.run_cli("keypart", "root", "create", "--out", str(wrong_root), "--password", "rootpass", home=ctx["home"])  # type: ignore[arg-type]
        proc = self.run_cli(
            "open",
            str(ctx["message"]),
            "--root-keypart",
            str(wrong_root),
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(self.root / "wrong-root-out"),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            check=False,
            home=ctx["home"],  # type: ignore[arg-type]
        )
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("root", proc.stderr.lower())
        self.assertNotIn("password", proc.stderr.lower())

    def test_v2_wrong_password_fails(self) -> None:
        ctx = self.make_v2_message(suffix="-wrongpass")
        proc = self.run_cli(
            "open",
            str(ctx["message"]),
            "--root-keypart",
            str(ctx["root"]),
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(self.root / "wrong-pass-out"),
            "--password",
            "badpass",
            "--identity-password",
            "idpass",
            check=False,
            home=ctx["home"],  # type: ignore[arg-type]
        )
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("password", proc.stderr.lower())

    def test_v2_replay_auth_fails(self) -> None:
        ctx = self.make_v2_message(suffix="-replay")
        self.run_cli(
            "open",
            str(ctx["message"]),
            "--root-keypart",
            str(ctx["root"]),
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(self.root / "replay-out1"),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            home=ctx["home"],  # type: ignore[arg-type]
        )
        replay = self.run_cli(
            "open",
            str(ctx["message"]),
            "--root-keypart",
            str(ctx["root"]),
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(self.root / "replay-out2"),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            check=False,
            home=ctx["home"],  # type: ignore[arg-type]
        )
        self.assertEqual(replay.returncode, 2)
        self.assertNotIn("auth", replay.stderr.lower())

    def test_v2_same_file_twice_unique_msg_id(self) -> None:
        ctx1 = self.make_v2_message(suffix="-unique1")
        home = Path(ctx1["home"])  # type: ignore[arg-type]
        root_seed = Path(ctx1["root"])  # type: ignore[arg-type]
        secret = Path(ctx1["secret"])  # type: ignore[arg-type]
        cover = Path(ctx1["cover"])  # type: ignore[arg-type]
        message2 = self.root / "message-unique2.zip"
        result2 = self.run_json(
            "seal",
            str(secret),
            str(cover),
            str(message2),
            "--to",
            "alice",
            "--password",
            "msgpass",
            "--root-keypart",
            str(root_seed),
            "--root-keypart-password",
            "rootpass",
            "--no-external-keypart",
            home=home,
        )
        self.assertNotEqual(ctx1["result"]["msg_id"], result2["msg_id"])  # type: ignore[index]
        self.assertNotEqual(Path(ctx1["message"]).read_bytes(), message2.read_bytes())  # type: ignore[arg-type]

    def test_v1_compat_still_works(self) -> None:
        home = self.root / "v1-compat-home"
        pub = self.make_identity(home, "alice", "idpass")
        self.run_cli("contact", "import", str(pub), "--alias", "alice", home=home)
        secret = self.root / "v1-secret.txt"
        secret.write_text("v1 still works\n", encoding="utf-8")
        cover = self.root / "v1-cover.zip"
        with zipfile.ZipFile(cover, "w") as zf:
            zf.writestr("readme.txt", "cover\n")
        message = self.root / "v1-message.zip"
        self.run_cli("seal", str(secret), str(cover), str(message), "--to", "alice", "--password", "msgpass", home=home)
        out = self.root / "v1-opened"
        self.run_cli(
            "open",
            str(message),
            "--keypart",
            str(message.with_suffix(".vkp")),
            "--out",
            str(out),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            home=home,
        )
        self.assertEqual((out / "v1-secret.txt").read_text(encoding="utf-8"), "v1 still works\n")

    def test_v1_open_with_root_keypart_hint(self) -> None:
        home = self.root / "v1-hint-home"
        pub = self.make_identity(home, "alice", "idpass")
        self.run_cli("contact", "import", str(pub), "--alias", "alice", home=home)
        root_seed = self.root / "v1-hint.root.vkpseed"
        self.run_cli("keypart", "root", "create", "--out", str(root_seed), "--password", "rootpass", home=home)
        secret = self.root / "v1-hint-secret.txt"
        secret.write_text("hint\n", encoding="utf-8")
        cover = self.root / "v1-hint-cover.zip"
        with zipfile.ZipFile(cover, "w") as zf:
            zf.writestr("readme.txt", "cover\n")
        message = self.root / "v1-hint-message.zip"
        self.run_cli("seal", str(secret), str(cover), str(message), "--to", "alice", "--password", "msgpass", home=home)
        proc = self.run_cli(
            "open",
            str(message),
            "--root-keypart",
            str(root_seed),
            "--root-keypart-password",
            "rootpass",
            "--out",
            str(self.root / "v1-hint-out"),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            check=False,
            home=home,
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("This is a v1 external-keypart message. Use --keypart instead.", proc.stderr)

    def test_v2_open_with_external_keypart_hint(self) -> None:
        ctx = self.make_v2_message(suffix="-hint")
        proc = self.run_cli(
            "open",
            str(ctx["message"]),
            "--keypart",
            str(self.root / "unused.vkp"),
            "--out",
            str(self.root / "v2-hint-out"),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            check=False,
            home=ctx["home"],  # type: ignore[arg-type]
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("This is a v2 root-keypart message. Use --root-keypart instead.", proc.stderr)

    def test_png_roundtrip_and_auth_replay_block(self) -> None:
        home = self.root / "alice-home"
        pub = self.make_identity(home, "alice", "idpass")
        self.run_cli("identity", "import", "--in", str(pub), "--alias", "alice", home=home)
        secret = self.root / "secret.txt"
        secret.write_text("real secret payload\n", encoding="utf-8")
        msg = self.root / "message.png"
        keypart = self.root / "message.keypart"
        auth = self.root / "message.auth"
        self.run_cli(
            "send",
            "--input",
            str(secret),
            "--recipient",
            "alice",
            "--password",
            "msgpass",
            "--format",
            "png",
            "--output",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            home=home,
        )
        verified = self.run_json(
            "verify-only",
            "--input",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            home=home,
        )
        self.assertTrue(verified["verified"])
        self.assertFalse(verified["auth_state_consumed"])
        out = self.root / "out"
        self.run_cli(
            "receive",
            "--input",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            "--output",
            str(out),
            home=home,
        )
        self.assertEqual((out / "secret.txt").read_text(encoding="utf-8"), "real secret payload\n")
        replay = self.run_cli(
            "receive",
            "--input",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            "--output",
            str(self.root / "out2"),
            check=False,
            home=home,
        )
        self.assertEqual(replay.returncode, 2)
        self.assertNotIn("password", replay.stderr.lower())
        self.assertNotIn("auth", replay.stderr.lower())

    def test_engineering_commands_and_protocol_metadata(self) -> None:
        home = self.root / "eng-home"
        pub = self.make_identity(home, "eng", "idpass")
        self.run_cli("contact", "add", "--in", str(pub), "--alias", "eng", home=home)
        contacts = self.run_json("contact", "list", home=home)
        self.assertEqual(len(contacts["contacts"]), 1)
        dry_contact = self.run_json("contact", "remove", "--alias", "eng", "--dry-run", home=home)
        self.assertFalse(dry_contact["removed"])
        profile_path = self.root / "balanced.profile.json"
        profile = self.run_json("profile", "create", "--out", str(profile_path), "--name", "eng", "--level", "dev", home=home)
        self.assertEqual(profile["summary"]["security_level"], "dev")
        shown = self.run_json("profile", "show", "--file", str(profile_path), home=home)
        self.assertEqual(shown["node_name"], "eng")
        doctor = self.run_json("--profile", str(profile_path), "doctor", home=home)
        self.assertTrue(doctor["ok"])
        audit = self.run_json("--profile", str(profile_path), "audit", home=home)
        self.assertTrue(audit["identity"]["present"])
        vector = self.run_json("test-vector", home=home)
        self.assertTrue(vector["ok"])
        capacity = self.run_json("capacity", "--format", "png", "--payload-size", "1000", home=home)
        self.assertTrue(capacity["accepted_by_strategy"])

        secret = self.root / "eng-secret.txt"
        secret.write_text("engineering command path\n", encoding="utf-8")
        msg = self.root / "eng-message.png"
        keypart = self.root / "eng-message.keypart"
        auth = self.root / "eng-message.auth"
        self.run_cli(
            "send",
            "--input",
            str(secret),
            "--recipient",
            "eng",
            "--password",
            "msgpass",
            "--format",
            "png",
            "--output",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            home=home,
        )
        inspected = self.run_json("keypart", "inspect", "--keypart", str(keypart), home=home)
        self.assertEqual(inspected["kind"], "veil-keypart")
        self.assertEqual(inspected["protocol"]["version"], 1)
        carrier = self.run_json("verify-carrier", "--input", str(msg), "--format", "png", home=home)
        self.assertTrue(carrier["ok"])
        repaired = self.run_json("repair", "keypart", "--keypart", str(keypart), home=home)
        self.assertIn("compatible", repaired)
        migrated_path = self.root / "eng-message.migrated.keypart"
        migrated = self.run_json("migrate", "keypart", "--keypart", str(keypart), "--out", str(migrated_path), home=home)
        self.assertEqual(migrated["migration"]["to"]["version"], 1)
        scan = self.run_json("repair", "scan", "--dir", str(self.root), home=home)
        self.assertIn("staging_outputs", scan)
        package = self.run_json("package", "--out", str(self.root / "veilnode.pyz"), home=home)
        self.assertTrue(Path(package["package"]).exists())
        packaged_help = subprocess.run(
            ["python3", package["package"], "--help"],
            cwd=ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("doctor", packaged_help.stdout)
        dry_delete = self.run_json("secure-delete", "--path", str(secret), "--dry-run", home=home)
        self.assertFalse(dry_delete["deleted"])
        refused = self.run_cli("secure-delete", "--path", str(secret), check=False, home=home)
        self.assertNotEqual(refused.returncode, 0)

    def test_veilnode_seal_open_and_nodepkg(self) -> None:
        home = self.root / "seal-home"
        pub = self.make_identity(home, "alice", "idpass")
        self.run_cli("contact", "import", str(pub), "--alias", "alice", home=home)
        vpkg = self.root / "alice.vpkg"
        exported = self.run_json("nodepkg", "export", "--out", str(vpkg), home=home)
        self.assertEqual(exported["contacts"], 1)
        inspected = self.run_json("nodepkg", "inspect", "--in", str(vpkg), home=home)
        self.assertEqual(inspected["kind"], "veil-node-package")

        imported_home = self.root / "imported-home"
        imported = self.run_json("nodepkg", "import", "--in", str(vpkg), "--overwrite", home=imported_home)
        self.assertEqual(imported["contacts"], 1)

        secret = self.root / "positional-secret.txt"
        secret.write_text("positional flow\n", encoding="utf-8")
        cover = self.root / "cover.zip"
        generate_carrier("zip")
        cover.write_bytes(generate_carrier("zip"))
        message = self.root / "sealed.zip"
        self.run_cli(
            "seal",
            str(secret),
            str(cover),
            str(message),
            "--to",
            "alice",
            "--password",
            "msgpass",
            home=home,
        )
        self.assertTrue(message.exists())
        self.assertTrue(message.with_suffix(".vkp").exists())
        self.assertTrue(message.with_suffix(".vauth").exists())
        out = self.root / "opened"
        self.run_cli(
            "open",
            str(message),
            "--keypart",
            str(message.with_suffix(".vkp")),
            "--out",
            str(out),
            "--password",
            "msgpass",
            "--identity-password",
            "idpass",
            home=home,
        )
        self.assertEqual((out / "positional-secret.txt").read_text(encoding="utf-8"), "positional flow\n")

    def test_unified_api_facade(self) -> None:
        home = self.root / "api-home"
        api = VeilAPI(home=home)
        api.create_identity("api", "idpass", overwrite=True)
        pub = home / "identity.public.json"
        api.identity.import_public(pub, "api")
        secret = self.root / "api.txt"
        secret.write_text("api facade\n", encoding="utf-8")
        result = api.send(
            input_path=secret,
            output_path=self.root / "api-message.zip",
            keypart_path=self.root / "api-message.keypart",
            auth_state_path=self.root / "api-message.auth",
            recipients=[api.identity.resolve_recipient("api")],
            password="msgpass",
            container_format="zip",
        )
        self.assertEqual(result["format"], "zip")
        verified = api.receive(
            input_path=self.root / "api-message.zip",
            keypart_path=self.root / "api-message.keypart",
            auth_state_path=self.root / "api-message.auth",
            output_dir=self.root / "api-out-unused",
            identity_password="idpass",
            password="msgpass",
            verify_only=True,
        )
        self.assertTrue(verified["verified"])

    def test_decoy_password_recovers_decoy_layer(self) -> None:
        home = self.root / "node-home"
        pub = self.make_identity(home, "node", "idpass")
        self.run_cli("identity", "import", "--in", str(pub), "--alias", "node", home=home)
        real = self.root / "real.txt"
        decoy = self.root / "decoy.txt"
        real.write_text("real layer\n", encoding="utf-8")
        decoy.write_text("decoy layer\n", encoding="utf-8")
        msg = self.root / "message.wav"
        keypart = self.root / "message.keypart"
        auth = self.root / "message.auth"
        self.run_cli(
            "send",
            "--input",
            str(real),
            "--recipient",
            "node",
            "--password",
            "realpass",
            "--decoy-input",
            str(decoy),
            "--decoy-password",
            "coverpass",
            "--format",
            "wav",
            "--output",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            home=home,
        )
        decoy_out = self.root / "decoy-out"
        self.run_cli(
            "receive",
            "--input",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            "--password",
            "coverpass",
            "--identity-password",
            "idpass",
            "--output",
            str(decoy_out),
            home=home,
        )
        self.assertEqual((decoy_out / "decoy.txt").read_text(encoding="utf-8"), "decoy layer\n")
        real_out = self.root / "real-out"
        self.run_cli(
            "receive",
            "--input",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            "--password",
            "realpass",
            "--identity-password",
            "idpass",
            "--output",
            str(real_out),
            home=home,
        )
        self.assertEqual((real_out / "real.txt").read_text(encoding="utf-8"), "real layer\n")

    def test_multi_recipient_can_open_with_second_identity(self) -> None:
        alice_home = self.root / "alice-home"
        bob_home = self.root / "bob-home"
        alice_pub = self.make_identity(alice_home, "alice", "alice-id")
        bob_pub = self.make_identity(bob_home, "bob", "bob-id")
        self.run_cli("identity", "import", "--in", str(alice_pub), "--alias", "alice", home=alice_home)
        self.run_cli("identity", "import", "--in", str(bob_pub), "--alias", "bob", home=alice_home)
        data_dir = self.root / "folder"
        data_dir.mkdir()
        (data_dir / "a.txt").write_text("A\n", encoding="utf-8")
        (data_dir / "b.txt").write_text("B\n", encoding="utf-8")
        msg = self.root / "message.zip"
        keypart = self.root / "message.keypart"
        auth = self.root / "message.auth"
        self.run_cli(
            "send",
            "--input",
            str(data_dir),
            "--recipient",
            "alice",
            "--recipient",
            "bob",
            "--password",
            "shared-pass",
            "--format",
            "zip",
            "--output",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            home=alice_home,
        )
        out = self.root / "bob-out"
        self.run_cli(
            "receive",
            "--input",
            str(msg),
            "--keypart",
            str(keypart),
            "--auth-state",
            str(auth),
            "--password",
            "shared-pass",
            "--identity-password",
            "bob-id",
            "--output",
            str(out),
            home=bob_home,
        )
        self.assertEqual((out / "folder" / "a.txt").read_text(encoding="utf-8"), "A\n")
        self.assertEqual((out / "folder" / "b.txt").read_text(encoding="utf-8"), "B\n")


class ContainerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_all_supported_carriers_extract_payload_and_remain_openable(self) -> None:
        payload = os.urandom(90000)
        for fmt in ["png", "bmp", "wav", "mp4", "zip", "pdf", "7z", "vmsg"]:
            with self.subTest(fmt=fmt):
                carrier = generate_carrier(fmt)
                embedded = embed_payload(carrier, payload, fmt)
                path = self.root / f"carrier.{fmt}"
                path.write_bytes(embedded.data)
                self.assertEqual(extract_payload(path, embedded.offset, embedded.length), payload)
                self._assert_openable(path, fmt)

    def test_factory_generates_executable_node_with_profile_and_identity(self) -> None:
        node = create_node(
            name="shade",
            out_dir=self.root / "nodes",
            chunk_size=1024,
            padding="random",
            bucket_size=4096,
            containers=["png", "zip"],
            param_style="mixed",
            init_identity_password="idpass",
            fast_kdf=True,
        )
        script = Path(node["node"])
        self.assertTrue(os.access(script, os.X_OK))
        profile = json.loads(Path(node["profile"]).read_text(encoding="utf-8"))
        self.assertEqual(profile["chunk_size"], 1024)
        proc = subprocess.run([str(script), "identity", "list"], text=True, capture_output=True, check=True)
        self.assertIn("private", proc.stdout)
        alias_proc = subprocess.run(
            [str(script), node["aliases"]["identity"], "list"],
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertIn("private", alias_proc.stdout)
        pub = self.root / "shade.pub.json"
        subprocess.run([str(script), "identity", "export", "--out", str(pub)], text=True, capture_output=True, check=True)
        subprocess.run(
            [str(script), "identity", "import", "--in", str(pub), "--alias", "self"],
            text=True,
            capture_output=True,
            check=True,
        )
        secret = self.root / "node-secret.txt"
        secret.write_text("alias options work\n", encoding="utf-8")
        opts = node["option_aliases"]
        subprocess.run(
            [
                str(script),
                node["aliases"]["send"],
                opts["input"],
                str(secret),
                opts["recipient"],
                "self",
                opts["password"],
                "msgpass",
                opts["format"],
                "png",
                opts["output"],
                str(self.root / "node-message.png"),
                opts["keypart"],
                str(self.root / "node-message.keypart"),
                opts["auth_state"],
                str(self.root / "node-message.auth"),
            ],
            text=True,
            capture_output=True,
            check=True,
        )

    def _assert_openable(self, path: Path, fmt: str) -> None:
        if fmt in {"png", "bmp"}:
            raw = path.read_bytes()
            if fmt == "png":
                self.assertTrue(raw.startswith(b"\x89PNG\r\n\x1a\n"))
                self.assertIn(b"IEND", raw[-64:])
            else:
                self.assertTrue(raw.startswith(b"BM"))
                self.assertGreater(int.from_bytes(raw[2:6], "little"), 54)
            return
        if fmt == "wav":
            with wave.open(str(path), "rb") as wav_file:
                self.assertGreater(wav_file.getnframes(), 0)
            return
        if fmt == "zip":
            with zipfile.ZipFile(path, "r") as zf:
                self.assertTrue(zf.namelist())
            return
        if fmt == "mp4" and shutil.which("ffprobe"):
            subprocess.run(["ffprobe", "-v", "error", str(path)], check=True)
            return
        if fmt == "7z" and shutil.which("7z"):
            subprocess.run(["7z", "t", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return
        if fmt == "pdf":
            raw = path.read_bytes()
            self.assertTrue(raw.startswith(b"%PDF-"))
            self.assertIn(b"%%EOF", raw[-128:])
            return
        if fmt == "vmsg":
            self.assertGreater(path.stat().st_size, 128)


if __name__ == "__main__":
    unittest.main()
