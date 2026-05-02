from __future__ import annotations

import json
import os
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class VeilNodeGui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("VeilNode")
        self.geometry("900x620")
        self._build()

    def _build(self) -> None:
        tabs = ttk.Notebook(self)
        tabs.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        self.output = tk.Text(self, height=12)
        self.output.pack(fill=tk.BOTH, expand=False, padx=12, pady=(0, 12))
        tabs.add(self._dashboard(tabs), text="Doctor")
        tabs.add(self._seal(tabs), text="Seal")
        tabs.add(self._open(tabs), text="Open")
        tabs.add(self._root_tools(tabs), text="Roots")
        tabs.add(self._carrier_tools(tabs), text="Carrier")
        tabs.add(self._strategy_tools(tabs), text="Strategy")
        tabs.add(self._contacts(tabs), text="Contacts")
        tabs.add(self._advanced_cli(tabs), text="CLI")

    def _dashboard(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        ttk.Label(frame, text="VeilNode — offline envelope encryption for ordinary carrier files.").pack(anchor=tk.W)
        ttk.Button(frame, text="Doctor", command=lambda: self.run(["doctor"])).pack(anchor=tk.W, pady=8)
        ttk.Button(frame, text="Test vectors", command=lambda: self.run(["test-vector"])).pack(anchor=tk.W)
        return frame

    def _seal(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        inputs: list[str] = []
        mode = tk.StringVar(value="root")
        cover = tk.StringVar(value="No cover selected")
        output_dir = tk.StringVar(value="No output folder selected")
        root_keypart = tk.StringVar(value="No root keypart selected")
        carrier_profile = tk.StringVar(value="No carrier profile selected")
        policy_model = tk.StringVar(value="No policy model selected")
        policy_out = tk.StringVar(value="No policy output selected")
        decoy_input = tk.StringVar(value="No decoy selected")
        recipient = tk.StringVar()
        message_password = tk.StringVar()
        root_password = tk.StringVar()
        decoy_password = tk.StringVar()
        low_signature = tk.BooleanVar(value=True)
        adaptive_policy = tk.BooleanVar(value=True)
        policy_candidates = tk.StringVar(value="20")
        signature_profile = tk.StringVar(value="balanced")
        inputs_label = tk.StringVar(value="No inputs selected")

        def choose_inputs() -> None:
            selected = filedialog.askopenfilenames(title="Choose files to seal")
            inputs.clear()
            inputs.extend(selected)
            inputs_label.set(f"{len(inputs)} input(s) selected" if inputs else "No inputs selected")

        def add_input_folder() -> None:
            selected = filedialog.askdirectory(title="Choose folder to seal")
            if selected:
                inputs.append(selected)
                inputs_label.set(f"{len(inputs)} input(s) selected")

        ttk.Radiobutton(frame, text="Root keypart v2", variable=mode, value="root").pack(anchor=tk.W)
        ttk.Checkbutton(frame, text="Use crypto core 2.2 low-signature", variable=low_signature).pack(anchor=tk.W)
        ttk.Checkbutton(frame, text="Adaptive envelope policy", variable=adaptive_policy).pack(anchor=tk.W)
        ttk.Combobox(frame, textvariable=signature_profile, values=["conservative", "balanced", "aggressive"], state="readonly").pack(fill=tk.X, pady=(0, 8))
        self._entry(frame, "Policy candidates", policy_candidates)
        self._picker_row(frame, "Inputs", inputs_label, choose_inputs)
        ttk.Button(frame, text="Add input folder", command=add_input_folder).pack(anchor=tk.W, pady=(0, 8))
        self._picker_row(frame, "Cover", cover, lambda: self._set_file(cover))
        self._picker_row(frame, "Output folder", output_dir, lambda: self._set_dir(output_dir))
        self._picker_row(frame, "Root keypart", root_keypart, lambda: self._set_file(root_keypart))
        self._picker_row(frame, "Carrier profile", carrier_profile, lambda: self._set_file(carrier_profile))
        self._picker_row(frame, "Policy model", policy_model, lambda: self._set_file(policy_model))
        self._picker_row(frame, "Policy output", policy_out, lambda: self._set_save_file(policy_out))
        self._picker_row(frame, "Decoy input", decoy_input, lambda: self._set_file(decoy_input))
        self._entry(frame, "Recipient alias", recipient)
        self._entry(frame, "Message password", message_password, show="*")
        self._entry(frame, "Root keypart password", root_password, show="*")
        self._entry(frame, "Decoy password", decoy_password, show="*")
        ttk.Button(frame, text="Seal selected", command=lambda: self.run_many(build_seal_commands())).pack(anchor=tk.W)

        def build_seal_commands() -> list[list[str]]:
            if not inputs or cover.get().startswith("No ") or output_dir.get().startswith("No ") or not recipient.get():
                return []
            commands = []
            ext = Path(cover.get()).suffix.lstrip(".") or "vmsg"
            for index, input_path in enumerate(inputs, start=1):
                suffix = f"-{index}" if len(inputs) > 1 else ""
                output = str(Path(output_dir.get()) / f"{Path(input_path).stem}{suffix}.sealed.{ext}")
                args = ["seal", input_path, cover.get(), output, "--to", recipient.get(), "--password", message_password.get()]
                if mode.get() == "root":
                    if root_keypart.get().startswith("No "):
                        return []
                    args += ["--root-keypart", root_keypart.get(), "--root-keypart-password", root_password.get(), "--crypto-core", "2.2"]
                    if low_signature.get():
                        args += ["--low-signature", "--signature-profile", signature_profile.get()]
                    if adaptive_policy.get():
                        args += ["--adaptive-policy", "--policy-candidates", policy_candidates.get() or "20"]
                    if not policy_model.get().startswith("No "):
                        args += ["--policy-model", policy_model.get()]
                    if not policy_out.get().startswith("No "):
                        args += ["--policy-out", policy_out.get()]
                    if not carrier_profile.get().startswith("No "):
                        args += ["--carrier-profile", carrier_profile.get()]
                    if not decoy_input.get().startswith("No "):
                        args += ["--decoy-input", decoy_input.get(), "--decoy-password", decoy_password.get()]
                commands.append(args)
            return commands
        return frame

    def _open(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        messages: list[str] = []
        mode = tk.StringVar(value="root")
        messages_label = tk.StringVar(value="No messages selected")
        output_dir = tk.StringVar(value="No output folder selected")
        keypart = tk.StringVar(value="No external keypart selected")
        root_keypart = tk.StringVar(value="No root keypart selected")
        root_store = tk.StringVar(value="No root store selected")
        root_fingerprint = tk.StringVar()
        message_password = tk.StringVar()
        identity_password = tk.StringVar()
        root_password = tk.StringVar()
        allow_revoked = tk.BooleanVar(value=False)
        no_replay_check = tk.BooleanVar(value=False)

        def choose_messages() -> None:
            selected = filedialog.askopenfilenames(title="Choose messages to open")
            messages.clear()
            messages.extend(selected)
            messages_label.set(f"{len(messages)} message(s) selected" if messages else "No messages selected")

        ttk.Radiobutton(frame, text="Root keypart v2", variable=mode, value="root").pack(anchor=tk.W)
        ttk.Radiobutton(frame, text="External keypart v1", variable=mode, value="external").pack(anchor=tk.W)
        self._picker_row(frame, "Messages", messages_label, choose_messages)
        self._picker_row(frame, "Output folder", output_dir, lambda: self._set_dir(output_dir))
        self._picker_row(frame, "Root keypart", root_keypart, lambda: self._set_file(root_keypart))
        self._picker_row(frame, "Root store", root_store, lambda: self._set_dir(root_store))
        self._picker_row(frame, "External keypart", keypart, lambda: self._set_file(keypart))
        self._entry(frame, "Root fingerprint", root_fingerprint)
        self._entry(frame, "Message password", message_password, show="*")
        self._entry(frame, "Identity password", identity_password, show="*")
        self._entry(frame, "Root keypart password", root_password, show="*")
        ttk.Checkbutton(frame, text="Allow revoked root", variable=allow_revoked).pack(anchor=tk.W)
        ttk.Checkbutton(frame, text="No replay check (debug)", variable=no_replay_check).pack(anchor=tk.W)
        ttk.Button(frame, text="Verify selected", command=lambda: self.run_many(build_open_commands(True))).pack(anchor=tk.W, pady=(0, 8))
        ttk.Button(frame, text="Open selected", command=lambda: self.run_many(build_open_commands(False))).pack(anchor=tk.W)

        def build_open_commands(verify_only: bool) -> list[list[str]]:
            if not messages or output_dir.get().startswith("No "):
                return []
            commands = []
            for index, message in enumerate(messages, start=1):
                suffix = f"-{index}" if len(messages) > 1 else ""
                out = str(Path(output_dir.get()) / f"{Path(message).stem}{suffix}-opened")
                args = ["open", message, "--out", out, "--password", message_password.get(), "--identity-password", identity_password.get()]
                if mode.get() == "root":
                    if root_keypart.get().startswith("No ") and root_store.get().startswith("No "):
                        return []
                    if root_keypart.get().startswith("No "):
                        args += ["--root-store", root_store.get()]
                    else:
                        args += ["--root-keypart", root_keypart.get()]
                    if root_fingerprint.get():
                        args += ["--root-fingerprint", root_fingerprint.get()]
                    args += ["--root-keypart-password", root_password.get()]
                    if allow_revoked.get():
                        args.append("--allow-revoked-root")
                    if no_replay_check.get():
                        args.append("--no-replay-check")
                else:
                    kp = keypart.get() if not keypart.get().startswith("No ") else str(Path(message).with_suffix(".vkp"))
                    args += ["--keypart", kp]
                if verify_only:
                    args.append("--verify-only")
                commands.append(args)
            return commands
        return frame

    def _contacts(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        path = tk.StringVar(value="No identity selected")
        alias = tk.StringVar()
        self._picker_row(frame, "Identity .vid", path, lambda: self._set_file(path))
        self._entry(frame, "Alias", alias)
        ttk.Button(frame, text="Import", command=lambda: self.run(["contact", "import", path.get(), "--alias", alias.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="List", command=lambda: self.run(["contact", "list"])).pack(anchor=tk.W, pady=8)
        return frame

    def _root_tools(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        root_path = tk.StringVar(value="No root selected")
        out_path = tk.StringVar(value="No output selected")
        shares_dir = tk.StringVar(value="No shares folder selected")
        label = tk.StringVar(value="alice-bob")
        password = tk.StringVar()
        fingerprint = tk.StringVar()
        self._picker_row(frame, "Root file", root_path, lambda: self._set_file(root_path))
        self._picker_row(frame, "Output root", out_path, lambda: self._set_save_file(out_path))
        self._picker_row(frame, "Shares folder", shares_dir, lambda: self._set_dir(shares_dir))
        self._entry(frame, "Label", label)
        self._entry(frame, "Root password", password, show="*")
        self._entry(frame, "Fingerprint", fingerprint)
        ttk.Button(frame, text="Create root", command=lambda: self.run(["keypart", "root", "create", "--out", out_path.get(), "--password", password.get(), "--label", label.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Inspect root", command=lambda: self.run(["keypart", "root", "inspect", "--in", root_path.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Rotate root", command=lambda: self.run(["keypart", "root", "rotate", "--in", root_path.get(), "--out", out_path.get(), "--password", password.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Retire root", command=lambda: self.run(["keypart", "root", "retire", "--in", root_path.get(), "--out", out_path.get(), "--password", password.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Revoke root", command=lambda: self.run(["keypart", "root", "revoke", "--in", root_path.get(), "--out", out_path.get(), "--password", password.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Import to store", command=lambda: self.run(["keypart", "root", "import", "--in", root_path.get(), "--password", password.get(), "--label", label.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="List store", command=lambda: self.run(["keypart", "root", "list"])).pack(anchor=tk.W)
        ttk.Button(frame, text="Show root", command=lambda: self.run(["keypart", "root", "show", "--fingerprint", fingerprint.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Split 3 of 5", command=lambda: self.run(["keypart", "root", "split", "--in", root_path.get(), "--password", password.get(), "--shares", "5", "--threshold", "3", "--out-dir", shares_dir.get()])).pack(anchor=tk.W)
        return frame

    def _carrier_tools(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        before = tk.StringVar(value="No before file selected")
        after = tk.StringVar(value="No carrier selected")
        samples = tk.StringVar(value="No samples folder selected")
        profile = tk.StringVar(value="No profile selected")
        self._picker_row(frame, "Before", before, lambda: self._set_file(before))
        self._picker_row(frame, "Carrier", after, lambda: self._set_file(after))
        self._picker_row(frame, "Samples", samples, lambda: self._set_dir(samples))
        self._picker_row(frame, "Profile", profile, lambda: self._set_save_file(profile))
        ttk.Button(frame, text="Audit", command=lambda: self.run(["carrier", "audit", "--input", after.get(), "--json"])).pack(anchor=tk.W)
        ttk.Button(frame, text="Compare", command=lambda: self.run(["carrier", "compare", "--before", before.get(), "--after", after.get(), "--json"])).pack(anchor=tk.W)
        ttk.Button(frame, text="Create profile", command=lambda: self.run(["carrier", "profile", "create", "--samples", samples.get(), "--out", profile.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Inspect profile", command=lambda: self.run(["carrier", "profile", "inspect", "--in", profile.get()])).pack(anchor=tk.W)
        return frame

    def _strategy_tools(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        carrier = tk.StringVar(value="No carrier selected")
        payload = tk.StringVar(value="No payload selected")
        before = tk.StringVar(value="No before selected")
        after = tk.StringVar(value="No after selected")
        policy = tk.StringVar(value="No policy selected")
        model = tk.StringVar(value="No model selected")
        dataset = tk.StringVar(value="No dataset selected")
        candidates = tk.StringVar(value="20")
        self._picker_row(frame, "Carrier", carrier, lambda: self._set_file(carrier))
        self._picker_row(frame, "Payload", payload, lambda: self._set_file(payload))
        self._picker_row(frame, "Before", before, lambda: self._set_file(before))
        self._picker_row(frame, "After", after, lambda: self._set_file(after))
        self._picker_row(frame, "Policy", policy, lambda: self._set_file(policy))
        self._picker_row(frame, "Model", model, lambda: self._set_file(model))
        self._picker_row(frame, "Dataset", dataset, lambda: self._set_file(dataset))
        self._entry(frame, "Candidates", candidates)
        ttk.Button(frame, text="Features", command=lambda: self.run(["strategy", "features", "--carrier", carrier.get(), "--payload", payload.get(), "--json"])).pack(anchor=tk.W)
        ttk.Button(frame, text="Generate policies", command=lambda: self.run(["strategy", "generate", "--carrier", carrier.get(), "--payload", payload.get(), "--count", candidates.get(), "--json"])).pack(anchor=tk.W)
        ttk.Button(frame, text="Select policy", command=lambda: self.run(["strategy", "select", "--carrier", carrier.get(), "--payload", payload.get(), "--count", candidates.get(), "--json"])).pack(anchor=tk.W)
        ttk.Button(frame, text="Score output", command=lambda: self.run(["strategy", "score", "--before", before.get(), "--after", after.get(), "--policy", policy.get(), "--json"])).pack(anchor=tk.W)
        ttk.Button(frame, text="Scan signatures", command=lambda: self.run(["strategy", "scan-signature", "--input", after.get(), "--json"])).pack(anchor=tk.W)
        ttk.Button(frame, text="Inspect policy", command=lambda: self.run(["strategy", "policy", "inspect", "--in", policy.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Inspect model", command=lambda: self.run(["strategy", "model", "inspect", "--in", model.get()])).pack(anchor=tk.W)
        ttk.Button(frame, text="Train model", command=lambda: self.run(["strategy", "train", "--dataset", dataset.get(), "--out", model.get()])).pack(anchor=tk.W)
        return frame

    def _advanced_cli(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        command = tk.StringVar(value="doctor")
        self._entry(frame, "veil-node arguments", command)
        ttk.Button(frame, text="Run", command=lambda: self.run(command.get().split())).pack(anchor=tk.W)
        return frame

    def _picker_row(self, frame: ttk.Frame, label: str, value: tk.StringVar, command) -> None:
        row = ttk.Frame(frame)
        row.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(row, text=label).pack(anchor=tk.W)
        ttk.Label(row, textvariable=value).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row, text="Choose", command=command).pack(side=tk.RIGHT)

    def _entry(self, frame: ttk.Frame, label: str, value: tk.StringVar, show: str | None = None) -> None:
        ttk.Label(frame, text=label).pack(anchor=tk.W)
        ttk.Entry(frame, textvariable=value, show=show).pack(fill=tk.X, pady=(0, 8))

    def _set_file(self, value: tk.StringVar) -> None:
        selected = filedialog.askopenfilename()
        if selected:
            value.set(selected)

    def _set_dir(self, value: tk.StringVar) -> None:
        selected = filedialog.askdirectory(mustexist=False)
        if selected:
            value.set(selected)

    def _set_save_file(self, value: tk.StringVar) -> None:
        selected = filedialog.asksaveasfilename()
        if selected:
            value.set(selected)

    def run(self, args: list[str]) -> None:
        self.run_many([args])

    def run_many(self, commands: list[list[str]]) -> None:
        self.output.delete("1.0", tk.END)
        if not commands:
            self.output.insert(tk.END, "Choose the required files and options first.\n")
            return
        try:
            for args in commands:
                self.output.insert(tk.END, "$ veil-node " + " ".join(args) + "\n")
                env = dict(os.environ)
                existing = env.get("PYTHONPATH")
                env["PYTHONPATH"] = str(PROJECT_ROOT) if not existing else str(PROJECT_ROOT) + os.pathsep + existing
                proc = subprocess.run(
                    [sys.executable, "-m", "veil_core", *args],
                    text=True,
                    capture_output=True,
                    cwd=PROJECT_ROOT,
                    env=env,
                )
                self.output.insert(tk.END, proc.stdout)
                if proc.stderr:
                    self.output.insert(tk.END, proc.stderr)
                self.output.insert(tk.END, f"\nexit={proc.returncode}\n\n")
        except Exception as exc:
            self.output.insert(tk.END, f"failed: {exc}\n")


def main() -> None:
    app = VeilNodeGui()
    app.mainloop()


if __name__ == "__main__":
    main()
