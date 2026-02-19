#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Simple Windows GUI launcher for Moodle Security Scanner."""

from __future__ import annotations

import subprocess
import sys
import threading
from pathlib import Path
from queue import Empty, Queue
from tkinter import BooleanVar, StringVar, Tk, filedialog, messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText


class ScannerGUI:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.root.title("Moodle Security Scanner GUI")
        self.root.geometry("980x700")

        self.project_root = Path(__file__).resolve().parent
        self.scanner_script = self.project_root / "moodle_scanner.py"
        self.docx_converter_script = self.project_root / "results_to_docx.py"
        self.python_executable = self._resolve_python_executable()
        self.process: subprocess.Popen[str] | None = None
        self.output_queue: Queue[str] = Queue()

        self.target_var = StringVar()
        self.output_var = StringVar(value="results.json")
        self.proxy_var = StringVar()
        self.cookies_var = StringVar()
        self.timeout_var = StringVar(value="30")
        self.delay_var = StringVar(value="0")
        self.threads_var = StringVar(value="5")
        self.user_agent_var = StringVar(
            value=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )
        )

        self.verbose_var = BooleanVar(value=False)
        self.no_verify_ssl_var = BooleanVar(value=False)
        self.report_format_var = StringVar(value="both")

        self.module_vars = {
            "version": BooleanVar(value=True),
            "auth": BooleanVar(value=True),
            "xss": BooleanVar(value=True),
            "rce": BooleanVar(value=True),
            "sqli": BooleanVar(value=True),
            "lfi": BooleanVar(value=True),
            "api": BooleanVar(value=True),
        }

        self._build_ui()
        self._poll_output_queue()

    def _resolve_python_executable(self) -> str:
        venv_windows = self.project_root / ".venv" / "Scripts" / "python.exe"
        if venv_windows.exists():
            return str(venv_windows)

        venv_unix = self.project_root / ".venv" / "bin" / "python"
        if venv_unix.exists():
            return str(venv_unix)

        return sys.executable

    def _build_ui(self) -> None:
        root_frame = ttk.Frame(self.root, padding=10)
        root_frame.pack(fill="both", expand=True)

        form = ttk.LabelFrame(root_frame, text="Scan Options", padding=10)
        form.pack(fill="x")

        ttk.Label(form, text="Target URL").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(form, textvariable=self.target_var, width=80).grid(
            row=0, column=1, columnspan=3, sticky="ew", pady=4
        )

        ttk.Label(form, text="Output file").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(form, textvariable=self.output_var, width=60).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(form, text="Browse...", command=self._browse_output).grid(
            row=1, column=2, sticky="w", padx=4
        )

        format_frame = ttk.Frame(form)
        format_frame.grid(row=1, column=3, sticky="w", pady=4)
        ttk.Label(format_frame, text="Format:").pack(side="left", padx=(0, 8))
        ttk.Radiobutton(format_frame, text="JSON", variable=self.report_format_var, value="json").pack(
            side="left"
        )
        ttk.Radiobutton(format_frame, text="Word", variable=self.report_format_var, value="word").pack(
            side="left", padx=(8, 0)
        )
        ttk.Radiobutton(format_frame, text="Both", variable=self.report_format_var, value="both").pack(
            side="left", padx=(8, 0)
        )

        ttk.Label(form, text="Proxy").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(form, textvariable=self.proxy_var, width=30).grid(row=2, column=1, sticky="ew", pady=4)

        ttk.Label(form, text="Cookies").grid(row=2, column=2, sticky="w", padx=(12, 8), pady=4)
        ttk.Entry(form, textvariable=self.cookies_var, width=40).grid(row=2, column=3, sticky="ew", pady=4)

        ttk.Label(form, text="Timeout").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(form, textvariable=self.timeout_var, width=10).grid(row=3, column=1, sticky="w", pady=4)

        ttk.Label(form, text="Delay").grid(row=3, column=2, sticky="w", padx=(12, 8), pady=4)
        ttk.Entry(form, textvariable=self.delay_var, width=10).grid(row=3, column=3, sticky="w", pady=4)

        ttk.Label(form, text="Threads").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(form, textvariable=self.threads_var, width=10).grid(row=4, column=1, sticky="w", pady=4)

        ttk.Label(form, text="User-Agent").grid(row=5, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(form, textvariable=self.user_agent_var, width=80).grid(
            row=5, column=1, columnspan=3, sticky="ew", pady=4
        )

        modules_frame = ttk.LabelFrame(root_frame, text="Modules", padding=10)
        modules_frame.pack(fill="x", pady=(10, 0))

        for index, module_name in enumerate(self.module_vars):
            ttk.Checkbutton(
                modules_frame,
                text=module_name,
                variable=self.module_vars[module_name],
            ).grid(row=0, column=index, padx=8, sticky="w")

        flags_frame = ttk.Frame(root_frame)
        flags_frame.pack(fill="x", pady=(10, 0))
        ttk.Checkbutton(flags_frame, text="Verbose", variable=self.verbose_var).pack(side="left", padx=(0, 12))
        ttk.Checkbutton(
            flags_frame,
            text="Disable SSL verification",
            variable=self.no_verify_ssl_var,
        ).pack(side="left")

        buttons = ttk.Frame(root_frame)
        buttons.pack(fill="x", pady=(10, 0))
        self.start_button = ttk.Button(buttons, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text="Stop Scan", command=self.stop_scan, state="disabled")
        self.stop_button.pack(side="left", padx=8)
        ttk.Button(buttons, text="Clear Output", command=self.clear_output).pack(side="left", padx=8)

        self.status_var = StringVar(value="Ready")
        ttk.Label(root_frame, textvariable=self.status_var).pack(anchor="w", pady=(8, 0))

        self.output_text = ScrolledText(root_frame, wrap="word", height=22)
        self.output_text.pack(fill="both", expand=True, pady=(8, 0))

        form.columnconfigure(1, weight=1)
        form.columnconfigure(3, weight=1)

    def _browse_output(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save results as",
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("Word files", "*.docx"),
                ("HTML files", "*.html"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
            initialdir=str(self.project_root),
        )
        if path:
            self.output_var.set(path)

    def _selected_modules(self) -> list[str]:
        return [name for name, var in self.module_vars.items() if var.get()]

    def _get_output_paths(self) -> tuple[Path, Path]:
        output_value = self.output_var.get().strip() or "results"
        output_path = Path(output_value)

        if not output_path.is_absolute():
            output_path = self.project_root / output_path

        if output_path.suffix.lower() in {".json", ".docx", ".txt", ".html", ".log"}:
            base_path = output_path.with_suffix("")
        else:
            base_path = output_path

        json_path = base_path.with_suffix(".json")
        docx_path = base_path.with_suffix(".docx")
        return json_path, docx_path

    def _build_command(self) -> tuple[list[str], str, Path, Path]:
        modules = self._selected_modules()
        if not modules:
            raise ValueError("Select at least one module.")

        target = self.target_var.get().strip()
        if not target:
            raise ValueError("Target URL is required.")

        report_format = self.report_format_var.get()
        json_path, docx_path = self._get_output_paths()

        cmd = [
            self.python_executable,
            str(self.scanner_script),
            "-t",
            target,
            "-m",
            ",".join(modules),
            "--timeout",
            self.timeout_var.get().strip() or "30",
            "--delay",
            self.delay_var.get().strip() or "0",
            "--threads",
            self.threads_var.get().strip() or "5",
            "--user-agent",
            self.user_agent_var.get().strip(),
            "-o",
            str(json_path),
        ]

        proxy = self.proxy_var.get().strip()
        if proxy:
            cmd.extend(["--proxy", proxy])

        cookies = self.cookies_var.get().strip()
        if cookies:
            cmd.extend(["--cookies", cookies])

        if self.verbose_var.get():
            cmd.append("--verbose")

        if self.no_verify_ssl_var.get():
            cmd.append("--no-verify-ssl")

        return cmd, report_format, json_path, docx_path

    def start_scan(self) -> None:
        if self.process is not None:
            messagebox.showinfo("Scanner running", "A scan is already running.")
            return

        try:
            cmd, report_format, json_path, docx_path = self._build_command()
        except ValueError as exc:
            messagebox.showerror("Invalid options", str(exc))
            return

        self.output_text.insert("end", "$ " + " ".join(cmd) + "\n")
        self.output_text.see("end")

        self.status_var.set("Running...")
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        thread = threading.Thread(
            target=self._run_process,
            args=(cmd, report_format, json_path, docx_path),
            daemon=True,
        )
        thread.start()

    def _run_process(self, cmd: list[str], report_format: str, json_path: Path, docx_path: Path) -> None:
        try:
            self.process = subprocess.Popen(
                cmd,
                cwd=str(self.project_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            assert self.process.stdout is not None
            for line in self.process.stdout:
                self.output_queue.put(line)

            exit_code = self.process.wait()

            if exit_code == 0 and report_format in {"word", "both"}:
                convert_cmd = [
                    self.python_executable,
                    str(self.docx_converter_script),
                    "-i",
                    str(json_path),
                    "-o",
                    str(docx_path),
                ]
                convert_result = subprocess.run(
                    convert_cmd,
                    cwd=str(self.project_root),
                    capture_output=True,
                    text=True,
                )
                if convert_result.stdout:
                    self.output_queue.put(convert_result.stdout)
                if convert_result.stderr:
                    self.output_queue.put(convert_result.stderr)

                if convert_result.returncode != 0:
                    self.output_queue.put("DOCX conversion failed.\n")
                elif report_format == "word":
                    try:
                        json_path.unlink(missing_ok=True)
                    except OSError:
                        pass

            self.output_queue.put(f"\nProcess finished with exit code {exit_code}\n")
        except Exception as exc:
            self.output_queue.put(f"\nFailed to run scanner: {exc}\n")
        finally:
            self.process = None
            self.output_queue.put("__PROCESS_DONE__")

    def stop_scan(self) -> None:
        if self.process is None:
            return

        self.process.terminate()
        self.output_queue.put("\nStopping scan...\n")

    def clear_output(self) -> None:
        self.output_text.delete("1.0", "end")

    def _poll_output_queue(self) -> None:
        try:
            while True:
                message = self.output_queue.get_nowait()
                if message == "__PROCESS_DONE__":
                    self.status_var.set("Ready")
                    self.start_button.config(state="normal")
                    self.stop_button.config(state="disabled")
                else:
                    self.output_text.insert("end", message)
                    self.output_text.see("end")
        except Empty:
            pass
        finally:
            self.root.after(100, self._poll_output_queue)


def main() -> None:
    root = Tk()
    ScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
