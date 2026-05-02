from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from veil_core.container import embed_payload, generate_carrier, verify_container
from veil_core.errors import VeilError
from veil_core.strategy.dataset import collect_dataset
from veil_core.strategy.features import carrier_features, payload_features
from veil_core.strategy.generator import generate_policies_from_features
from veil_core.strategy.model import rank_candidates, train_heuristic_model
from veil_core.strategy.policy import EnvelopePolicy
from veil_core.strategy.registry import list_strategies, strategies_for_format
from veil_core.strategy.scorer import scan_fixed_signatures, score_paths
from veil_core.strategy.selector import select_policy


ROOT = Path(__file__).resolve().parents[1]


class StrategyTests(unittest.TestCase):
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

    def make_payload(self, name: str = "secret.txt", text: str = "secret\n") -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def make_zip(self, name: str = "cover.zip") -> Path:
        path = self.root / name
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("readme.txt", "ordinary cover file\n")
        return path

    def write_carrier(self, fmt: str, name: str | None = None) -> Path:
        path = self.root / (name or f"cover.{fmt}")
        path.write_bytes(generate_carrier(fmt))
        return path

    def make_identity_and_root(self) -> tuple[Path, Path]:
        home = self.root / "alice-home"
        self.run_cli("identity", "create", "--name", "alice", "--password", "idpass", "--overwrite", home=home)
        pub = self.root / "alice.vid"
        self.run_cli("identity", "export", "--out", str(pub), home=home)
        self.run_cli("contact", "import", str(pub), "--alias", "alice", home=home)
        root = self.root / "root.vkpseed"
        self.run_cli("keypart", "root", "create", "--out", str(root), "--password", "rootpass", "--label", "alice-bob", home=home)
        return home, root

    def seal_adaptive(self, *, policy_in: Path | None = None, model: Path | None = None) -> tuple[Path, Path, Path, dict]:
        home, root_seed = self.make_identity_and_root()
        payload = self.make_payload()
        cover = self.make_zip()
        out = self.root / ("message-policy.zip" if policy_in else "message.zip")
        policy_out = self.root / "selected.policy.json"
        args = [
            "seal",
            str(payload),
            str(cover),
            str(out),
            "--to",
            "alice",
            "--password",
            "msgpass",
            "--root-keypart",
            str(root_seed),
            "--root-keypart-password",
            "rootpass",
            "--crypto-core",
            "2.2",
            "--low-signature",
            "--policy-out",
            str(policy_out),
        ]
        if policy_in:
            args += ["--policy-in", str(policy_in)]
        else:
            args += ["--adaptive-policy", "--policy-candidates", "10"]
        if model:
            args += ["--policy-model", str(model)]
        result = self.run_json(*args, home=home)
        return home, root_seed, out, result

    def test_strategy_features_extract_zip(self) -> None:
        features = carrier_features(self.make_zip(), payload_size=7)
        self.assertEqual(features.format, "zip")
        self.assertEqual(features.structure_stats["entry_count"], 1)

    def test_strategy_features_extract_png(self) -> None:
        features = carrier_features(self.write_carrier("png"), payload_size=7)
        self.assertEqual(features.format, "png")
        self.assertGreater(features.structure_stats["chunk_count"], 0)

    def test_strategy_features_extract_mp4(self) -> None:
        features = carrier_features(self.write_carrier("mp4"), payload_size=7)
        self.assertEqual(features.format, "mp4")
        self.assertIn("box_count", features.structure_stats)

    def test_strategy_features_extract_pdf(self) -> None:
        features = carrier_features(self.write_carrier("pdf"), payload_size=7)
        self.assertEqual(features.format, "pdf")
        self.assertGreaterEqual(features.structure_stats["eof_count"], 1)

    def test_strategy_features_extract_wav(self) -> None:
        features = carrier_features(self.write_carrier("wav"), payload_size=7)
        self.assertEqual(features.format, "wav")
        self.assertGreater(features.structure_stats["riff_chunk_count"], 0)

    def test_envelope_policy_contains_no_secrets(self) -> None:
        data = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member").to_json()
        raw = json.dumps(data).lower()
        self.assertNotIn("message_key", raw)
        with self.assertRaises(VeilError):
            EnvelopePolicy.from_json({**data, "message_key": "bad"})

    def test_policy_registry_has_valid_strategies(self) -> None:
        self.assertTrue(strategies_for_format("zip"))
        self.assertIn("zip_stored_member", {s.name for s in strategies_for_format("zip")})

    def test_policy_registry_strategy_constraints(self) -> None:
        for item in list_strategies("zip")["strategies"]:
            self.assertGreater(item["max_payload_ratio"], 0)
            self.assertTrue(item["low_signature_compatible"])

    def test_policy_in_rejects_crypto_changes(self) -> None:
        policy = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member").to_json()
        with self.assertRaises(VeilError):
            EnvelopePolicy.from_json({**policy, "crypto_core_version": "1.0"})

    def test_candidate_generator_respects_capacity(self) -> None:
        carrier = carrier_features(self.make_zip(), payload_size=7).to_json()
        payload = payload_features(self.make_payload()).to_json()
        policies = generate_policies_from_features(carrier, payload, count=5)
        self.assertTrue(all(p.constraints["capacity_estimate"] >= payload["payload_size"] + 1024 for p in policies))

    def test_candidate_generator_respects_payload_ratio(self) -> None:
        carrier = carrier_features(self.make_zip(), payload_size=7).to_json()
        payload = payload_features(self.make_payload()).to_json()
        for policy in generate_policies_from_features(carrier, payload, count=5):
            self.assertLessEqual(carrier["payload_ratio"], policy.constraints["max_payload_ratio"])

    def test_candidate_generator_no_crypto_changes(self) -> None:
        carrier = carrier_features(self.make_zip(), payload_size=7).to_json()
        payload = payload_features(self.make_payload()).to_json()
        self.assertTrue(all(p.crypto_core_version == "2.2" for p in generate_policies_from_features(carrier, payload, count=5)))

    def test_candidate_generator_outputs_unique_policies(self) -> None:
        carrier = carrier_features(self.make_zip(), payload_size=7).to_json()
        payload = payload_features(self.make_payload()).to_json()
        policies = generate_policies_from_features(carrier, payload, count=10)
        keys = {(p.embed_strategy, p.chunk_profile, p.padding_profile, p.metadata_layout, p.locator_strategy) for p in policies}
        self.assertEqual(len(keys), len(policies))

    def test_strategy_score_outputs_json(self) -> None:
        before = self.make_zip()
        after = self.root / "after.zip"
        after.write_bytes(embed_payload(before.read_bytes(), b"payload", "zip").data)
        policy = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member")
        score = score_paths(before, after, policy=policy)
        self.assertIn("overall_score", score)

    def test_strategy_score_penalizes_invalid_parser(self) -> None:
        before = self.make_zip()
        after = self.root / "bad.zip"
        after.write_bytes(b"not a zip")
        policy = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member")
        self.assertEqual(score_paths(before, after, policy=policy)["recommendation"], "high")

    def test_strategy_score_penalizes_plain_signatures(self) -> None:
        before = self.make_zip()
        after = self.root / "signed.zip"
        after.write_bytes(embed_payload(before.read_bytes(), b"VeilNode", "zip").data)
        policy = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member")
        self.assertGreater(score_paths(before, after, policy=policy)["fixed_signature_penalty"], 0)

    def test_strategy_score_lower_is_better(self) -> None:
        before = self.make_zip()
        low = self.root / "low.zip"
        high = self.root / "high.zip"
        low.write_bytes(embed_payload(before.read_bytes(), b"x", "zip").data)
        high.write_bytes(embed_payload(before.read_bytes(), b"VeilNode" + b"x" * 4096, "zip").data)
        policy = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member")
        self.assertLess(score_paths(before, low, policy=policy)["overall_score"], score_paths(before, high, policy=policy)["overall_score"])

    def test_strategy_selector_returns_valid_policy(self) -> None:
        result = select_policy(self.make_zip(), self.make_payload(), count=8)
        self.assertEqual(result["selected_policy"]["crypto_core_version"], "2.2")

    def test_strategy_selector_dry_run_outputs_valid_carrier(self) -> None:
        result = select_policy(self.make_zip(), self.make_payload(), count=8)
        self.assertTrue(result["selected_score"]["parser_valid"])

    def test_strategy_selector_cleans_temp_files(self) -> None:
        result = select_policy(self.make_zip(), self.make_payload(), count=4)
        self.assertTrue(result["temp_cleaned"])

    def test_strategy_selector_does_not_bypass_verifier(self) -> None:
        with mock.patch("veil_core.strategy.selector.verify_container", return_value={"ok": False}):
            with self.assertRaises(VeilError):
                select_policy(self.make_zip(), self.make_payload(), count=4)

    def test_adaptive_policy_seal_roundtrip(self) -> None:
        home, root_seed, message, _ = self.seal_adaptive()
        out = self.root / "opened"
        self.run_cli("open", str(message), "--root-keypart", str(root_seed), "--root-keypart-password", "rootpass", "--out", str(out), "--password", "msgpass", "--identity-password", "idpass", "--no-replay-check", home=home)
        self.assertEqual((out / "secret.txt").read_text(encoding="utf-8"), "secret\n")

    def test_policy_out_contains_no_secrets(self) -> None:
        _, _, _, result = self.seal_adaptive()
        raw = Path(result["policy_out"]["policy"]).read_text(encoding="utf-8").lower()
        for marker in ["root_vkp", "vkp_i", "message_key", "password"]:
            self.assertNotIn(marker, raw)

    def test_policy_in_reproduces_valid_roundtrip(self) -> None:
        home, root_seed, message, result = self.seal_adaptive()
        policy_path = Path(result["policy_out"]["policy"])
        home2, root_seed2, message2, _ = self.seal_adaptive(policy_in=policy_path)
        out = self.root / "opened-policy"
        self.run_cli("open", str(message2), "--root-keypart", str(root_seed2), "--root-keypart-password", "rootpass", "--out", str(out), "--password", "msgpass", "--identity-password", "idpass", "--no-replay-check", home=home2)
        self.assertEqual((out / "secret.txt").read_text(encoding="utf-8"), "secret\n")
        self.assertTrue(verify_container(message, "zip")["ok"])

    def test_policy_model_used_for_candidate_ranking(self) -> None:
        model = self.root / "model.json"
        dataset = self.root / "dataset.jsonl"
        row = {
            "carrier_features": carrier_features(self.make_zip(), payload_size=7).to_json(),
            "payload_features": payload_features(self.make_payload()).to_json(),
            "candidate_policy": EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member").to_json(),
            "strategy_score": {"overall_score": 0.01},
            "audit_score": {},
            "compare_score": {},
            "parser_valid": True,
            "selected": True,
        }
        dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
        train_heuristic_model(dataset, model)
        policies = [
            EnvelopePolicy(carrier_format="zip", embed_strategy="zip_comment"),
            EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member"),
        ]
        self.assertEqual(rank_candidates(policies, model, row["carrier_features"])[0].embed_strategy, "zip_stored_member")

    def test_adaptive_policy_still_generic_failure_on_wrong_password(self) -> None:
        home, root_seed, message, _ = self.seal_adaptive()
        proc = self.run_cli("open", str(message), "--root-keypart", str(root_seed), "--root-keypart-password", "rootpass", "--out", str(self.root / "bad"), "--password", "wrong", "--identity-password", "idpass", check=False, home=home)
        self.assertEqual(proc.stderr.strip(), "Unable to open message.")

    def test_adaptive_policy_still_generic_failure_on_wrong_root(self) -> None:
        home, _, message, _ = self.seal_adaptive()
        wrong_root = self.root / "wrong.root.vkpseed"
        self.run_cli("keypart", "root", "create", "--out", str(wrong_root), "--password", "rootpass", home=home)
        proc = self.run_cli("open", str(message), "--root-keypart", str(wrong_root), "--root-keypart-password", "rootpass", "--out", str(self.root / "bad-root"), "--password", "msgpass", "--identity-password", "idpass", check=False, home=home)
        self.assertEqual(proc.stderr.strip(), "Unable to open message.")

    def test_strategy_collect_writes_jsonl(self) -> None:
        samples = self.root / "samples"
        payloads = self.root / "payloads"
        samples.mkdir()
        payloads.mkdir()
        self.make_zip(samples / "cover.zip")
        (payloads / "payload.txt").write_text("secret\n", encoding="utf-8")
        out = self.root / "dataset.jsonl"
        result = collect_dataset(samples, payloads, out, candidates_per_sample=3)
        self.assertGreater(result["rows"], 0)

    def test_strategy_collect_contains_no_secrets(self) -> None:
        samples = self.root / "samples2"
        payloads = self.root / "payloads2"
        samples.mkdir()
        payloads.mkdir()
        self.make_zip(samples / "cover.zip")
        (payloads / "payload.txt").write_text("secret\n", encoding="utf-8")
        out = self.root / "dataset2.jsonl"
        collect_dataset(samples, payloads, out, candidates_per_sample=2)
        raw = out.read_text(encoding="utf-8").lower()
        for marker in ["root_vkp", "vkp_i", "message_key", "password"]:
            self.assertNotIn(marker, raw)

    def test_strategy_train_outputs_model_or_fallback(self) -> None:
        dataset = self.root / "train.jsonl"
        policy = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member").to_json()
        dataset.write_text(json.dumps({"carrier_features": {"format": "zip", "payload_ratio": 0.01}, "candidate_policy": policy, "strategy_score": {"overall_score": 0.2}}) + "\n", encoding="utf-8")
        model = self.root / "model.json"
        result = train_heuristic_model(dataset, model)
        self.assertEqual(result["model_type"], "heuristic_ranker")

    def test_strategy_model_inspect(self) -> None:
        dataset = self.root / "inspect-train.jsonl"
        policy = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member").to_json()
        dataset.write_text(json.dumps({"carrier_features": {"format": "zip"}, "candidate_policy": policy, "strategy_score": {"overall_score": 0.2}}) + "\n", encoding="utf-8")
        model = self.root / "inspect-model.json"
        result = train_heuristic_model(dataset, model)
        self.assertIn("zip", result["supported_formats"])

    def test_policy_model_ranks_candidates(self) -> None:
        dataset = self.root / "rank.jsonl"
        good = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member").to_json()
        bad = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_comment").to_json()
        dataset.write_text(
            json.dumps({"carrier_features": {"format": "zip"}, "candidate_policy": good, "strategy_score": {"overall_score": 0.1}}) + "\n"
            + json.dumps({"carrier_features": {"format": "zip"}, "candidate_policy": bad, "strategy_score": {"overall_score": 0.9}}) + "\n",
            encoding="utf-8",
        )
        model = self.root / "rank-model.json"
        train_heuristic_model(dataset, model)
        ranked = rank_candidates([EnvelopePolicy.from_json(bad), EnvelopePolicy.from_json(good)], model, {"format": "zip"})
        self.assertEqual(ranked[0].embed_strategy, "zip_stored_member")

    def test_model_cannot_change_crypto_core(self) -> None:
        dataset = self.root / "model-core.jsonl"
        policy = EnvelopePolicy(carrier_format="zip", embed_strategy="zip_stored_member").to_json()
        dataset.write_text(json.dumps({"carrier_features": {"format": "zip"}, "candidate_policy": policy, "strategy_score": {"overall_score": 0.2}}) + "\n", encoding="utf-8")
        model = self.root / "model-core.json"
        train_heuristic_model(dataset, model)
        data = json.loads(model.read_text(encoding="utf-8"))
        self.assertEqual(data["crypto_core_version_supported"], ["2.2"])

    def test_fixed_signature_scanner_detects_plain_veil_strings(self) -> None:
        path = self.root / "sig.bin"
        path.write_bytes(b"VeilNode root_vkp message_key")
        self.assertTrue(scan_fixed_signatures(path)["found_plain_signatures"])

    def test_low_signature_output_has_no_plain_veil_strings(self) -> None:
        _, _, message, _ = self.seal_adaptive()
        self.assertFalse(scan_fixed_signatures(message)["found_plain_signatures"])

    def test_v1_v2_core22_still_compatible(self) -> None:
        self.assertEqual(self.run_cli("test-vector").returncode, 0)

    def test_crypto_core_version_not_suite_version(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.3.1"', pyproject)
        self.assertNotIn('version = "2.2"', pyproject)

    def test_adaptive_policy_does_not_modify_suite_version(self) -> None:
        self.seal_adaptive()
        self.test_crypto_core_version_not_suite_version()

    def test_crypto_core_10_is_not_supported(self) -> None:
        proc = self.run_cli("seal", "a", "b", "c", "--to", "alice", "--crypto-core", "1.0", check=False)
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
