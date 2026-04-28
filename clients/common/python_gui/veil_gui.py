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
        tabs.add(self._contacts(tabs), text="Contacts")

    def _dashboard(self, parent: ttk.Notebook) -> ttk.Frame:
        frame = ttk.Frame(parent, padding=12)
        ttk.Label(frame, text="VeilNode — encrypted files disguised as ordinary data.").pack(anchor=tk.W)
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
        recipient = tk.StringVar()
        message_password = tk.StringVar()
        root_password = tk.StringVar()
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
        ttk.Radiobutton(frame, text="External keypart v1", variable=mode, value="external").pack(anchor=tk.W)
        self._picker_row(frame, "Inputs", inputs_label, choose_inputs)
        ttk.Button(frame, text="Add input folder", command=add_input_folder).pack(anchor=tk.W, pady=(0, 8))
        self._picker_row(frame, "Cover", cover, lambda: self._set_file(cover))
        self._picker_row(frame, "Output folder", output_dir, lambda: self._set_dir(output_dir))
        self._picker_row(frame, "Root keypart", root_keypart, lambda: self._set_file(root_keypart))
        self._entry(frame, "Recipient alias", recipient)
        self._entry(frame, "Message password", message_password, show="*")
        self._entry(frame, "Root keypart password", root_password, show="*")
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
                    args += ["--root-keypart", root_keypart.get(), "--root-keypart-password", root_password.get(), "--no-external-keypart"]
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
        message_password = tk.StringVar()
        identity_password = tk.StringVar()
        root_password = tk.StringVar()

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
        self._picker_row(frame, "External keypart", keypart, lambda: self._set_file(keypart))
        self._entry(frame, "Message password", message_password, show="*")
        self._entry(frame, "Identity password", identity_password, show="*")
        self._entry(frame, "Root keypart password", root_password, show="*")
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
                    if root_keypart.get().startswith("No "):
                        return []
                    args += ["--root-keypart", root_keypart.get(), "--root-keypart-password", root_password.get()]
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
