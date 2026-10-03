"""Tkinter front end. Collection, SQLite access and discovery stay off the UI thread."""
import json
import queue
import threading
import tkinter as tk
from collections import deque
from dataclasses import replace
from tkinter import filedialog, messagebox, ttk

from .config import Budget, Config


class App:
    def __init__(self, root):
        self.root = root
        self.scanner = None
        self.active = False
        self.messages = queue.Queue(maxsize=16)
        self.config = Config()
        self.paths = []
        self.history = deque(maxlen=100)
        self.closing = False
        self.request_cancel = threading.Event()
        self.request_pause = threading.Event()
        self.anonymize = []
        self.anon_key = None
        self.sign_key = None
        self.sign_password = ""
        self.excludes = []
        self.includes = []
        self.root.title("DriveWitness • forensic baseline")
        self.root.geometry("1000x850")
        self.root.minsize(840, 730)
        self.root.configure(bg="#111822")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#111822")
        style.configure("TLabel", background="#111822", foreground="#dbe4ed")
        style.configure("TButton", padding=7)
        style.configure("TRadiobutton", background="#111822", foreground="#dbe4ed")
        style.configure("Treeview", rowheight=30)
        body = ttk.Frame(root, padding=20)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="DRIVEWITNESS", font=("Segoe UI", 24, "bold")).pack(anchor="w")
        ttk.Label(body, text="Tamper-evident inventory • read-only collection • live resource control").pack(anchor="w", pady=(0, 14))
        self.hardware = ttk.Label(body, text="CPU: detecting…    GPU: detecting…    USN: checking…")
        self.hardware.pack(anchor="w")
        toolbar = ttk.Frame(body)
        toolbar.pack(fill="x", pady=8)
        ttk.Label(toolbar, text="DRIVES / DIRECTORIES", font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(toolbar, text="Add folder", command=self.add_folder).pack(side="right")
        ttk.Button(toolbar, text="Settings / Advanced", command=self.settings).pack(side="right", padx=8)
        self.tree = ttk.Treeview(body, columns=("selected", "path", "fs", "storage", "free"), show="headings", height=5, selectmode="none")
        for name, label, width in [("selected", "Scan", 55), ("path", "Drive / directory", 390), ("fs", "Filesystem", 90), ("storage", "Storage", 85), ("free", "Free / total GiB", 130)]:
            self.tree.heading(name, text=label)
            self.tree.column(name, width=width, stretch=name == "path")
        self.tree.pack(fill="x")
        self.tree.bind("<ButtonRelease-1>", self.toggle_drive)
        modes = ttk.Frame(body)
        modes.pack(fill="x", pady=10)
        ttk.Label(modes, text="SCAN MODE", font=("Segoe UI", 11, "bold")).pack(side="left", padx=(0, 15))
        self.mode = tk.StringVar(value="verify")
        for value in ("quick", "verify", "forensic"):
            ttk.Radiobutton(modes, text=value.title(), variable=self.mode, value=value).pack(side="left", padx=8)
        self.gpu = tk.StringVar(value="auto")
        ttk.Label(modes, text="GPU").pack(side="left", padx=(30, 6))
        ttk.Combobox(modes, textvariable=self.gpu, values=("auto", "off", "force"), state="readonly", width=8).pack(side="left")
        self.level = tk.IntVar(value=60)
        ttk.Label(body, text="PERFORMANCE", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        controls = ttk.Frame(body)
        controls.pack(fill="x")
        for text, delta in [("−10", -10), ("−1", -1)]:
            ttk.Button(controls, text=text, width=5, command=lambda n=delta: self.step(n)).pack(side="left")
        self.slider = tk.Scale(controls, from_=0, to=100, orient="horizontal", variable=self.level,
                               command=self.performance_changed, showvalue=True, bg="#111822", fg="#dbe4ed",
                               highlightthickness=0, troughcolor="#263647", activebackground="#56c5b5")
        self.slider.pack(side="left", fill="x", expand=True, padx=8)
        for text, delta in [("+1", 1), ("+10", 10)]:
            ttk.Button(controls, text=text, width=5, command=lambda n=delta: self.step(n)).pack(side="left")
        self.behavior = ttk.Label(body)
        self.behavior.pack(anchor="w", pady=(3, 10))
        database = ttk.Frame(body)
        database.pack(fill="x", pady=4)
        ttk.Label(database, text="Evidence DB").pack(side="left")
        self.database = tk.StringVar(value="drive_witness.db")
        ttk.Entry(database, textvariable=self.database).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(database, text="Browse", command=self.choose_db).pack(side="left")
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=8)
        self.start_button = ttk.Button(buttons, text="START SCAN", command=self.start)
        self.start_button.pack(side="left")
        self.pause_button = ttk.Button(buttons, text="PAUSE", command=self.pause, state="disabled")
        self.pause_button.pack(side="left", padx=8)
        self.cancel_button = ttk.Button(buttons, text="CANCEL", command=self.cancel, state="disabled")
        self.cancel_button.pack(side="left")
        ttk.Button(buttons, text="Inspect errors / unstable", command=self.errors).pack(side="right")
        self.status = ttk.Label(body, text="Ready. Select a drive or add a directory.", font=("Segoe UI", 11, "bold"))
        self.status.pack(anchor="w", pady=8)
        self.metrics = ttk.Label(body, text="Files: 0    Processed: 0    Changed: 0    Added: 0    Deleted: 0", justify="left")
        self.metrics.pack(anchor="w")
        self.current = ttk.Label(body, text="", wraplength=900)
        self.current.pack(anchor="w", pady=6)
        self.chart = tk.Canvas(body, height=110, bg="#182433", highlightthickness=0)
        self.chart.pack(fill="x", pady=5)
        ttk.Label(body, text="Live: teal MB/s • blue files/s • amber CPU % • gray queue pressure (each scaled separately)").pack(anchor="w")
        ttk.Label(body, text="Quick uses eligible USN checkpoints; Verify reads all files; Forensic recalculates both hashes.\n"
                              "Completion reports coverage gaps. Endpoint integrity and live filesystem consistency cannot be guaranteed.",
                  wraplength=930).pack(anchor="w", pady=10)
        self.performance_changed()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(50, self.discover)
        self.root.after(100, self.poll)

    def emit(self, kind, value):
        if kind == "progress":
            try:
                self.messages.put_nowait((kind, value))
            except queue.Full:
                pass
        else:
            self.messages.put((kind, value))

    def background(self, operation, kind):
        def work():
            try:
                self.emit(kind, operation())
            except Exception as exc:
                self.emit("failure", {"message": str(exc), "kind": kind})
        threading.Thread(target=work, name="dw-" + kind, daemon=True).start()

    def discover(self):
        def work():
            # Render first, then load settings and probe hardware asynchronously.
            from .windows import capabilities
            try:
                config = Config.load()
            except (OSError, ValueError, TypeError) as exc:
                self.emit("settings_error", str(exc))
                config = Config()
            self.emit("settings", config)
            self.emit("discovery", capabilities())
        self.background(work, "discovery_done")

    def add_folder(self):
        if self.active:
            return
        path = filedialog.askdirectory()
        if path:
            self.paths.append({"path": path, "selected": True})
            self.tree.insert("", "end", values=("✓", path, "directory", "auto", ""))

    def toggle_drive(self, event):
        if self.active:
            return
        item = self.tree.identify_row(event.y)
        if item:
            index = self.tree.index(item)
            self.paths[index]["selected"] = not self.paths[index].get("selected", False)
            self.tree.set(item, "selected", "✓" if self.paths[index]["selected"] else "")

    def choose_db(self):
        if self.active:
            return
        path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("Evidence database", "*.db")])
        if path:
            self.database.set(path)

    def step(self, delta):
        self.level.set(max(0, min(100, self.level.get() + delta)))
        self.performance_changed()

    def performance_changed(self, *_):
        self.config.performance = self.level.get()
        if self.scanner and self.active:
            self.scanner.budget.set(self.level.get())
            budget = self.scanner.budget.get()
        else:
            budget = Budget(self.config).get()
        self.behavior.configure(text=f"{budget['label']} {budget['level']}   •   File workers: {budget['workers']}   •   Large-file threads: {budget['large_threads']}"
                                    f"   •   Queue limit: {budget['queue_depth']}   •   Disk: {budget['storage']}\n"
                                    "Resource budget hint; in-flight work drains safely when lowered. GPU collection backend: unavailable.")

    def start(self):
        if self.active:
            return
        paths = [d["path"] for d in self.paths if d.get("selected")]
        if not paths:
            messagebox.showinfo("DriveWitness", "Select a drive or add a directory.")
            return
        config = replace(self.config, mode=self.mode.get(), performance=self.level.get(), gpu=self.gpu.get())
        db, anon, key, sign, excludes, includes = self.database.get(), list(self.anonymize), self.anon_key, self.sign_key, list(self.excludes), list(self.includes)
        sign_password = self.sign_password.encode() if self.sign_password else None
        self.active = True
        self.request_cancel.clear()
        self.request_pause.clear()
        self.start_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.pause_button.configure(state="normal", text="PAUSE")
        self.status.configure(text="Starting…")
        def work():
            from pathlib import Path
            from .scanner import Scanner
            scanner = Scanner(db, config, lambda data: self.emit("progress", data))
            scanner.cancel = self.request_cancel
            scanner.paused = self.request_pause
            self.scanner = scanner
            return scanner.run(paths, anonymize=anon, anonymization_key=Path(key).read_bytes() if key else None,
                               excludes=excludes, includes=includes, signing_key=sign, signing_password=sign_password)
        self.background(work, "completed")

    def pause(self):
        if self.active:
            if self.request_pause.is_set():
                self.request_pause.clear()
                self.pause_button.configure(text="PAUSE")
            else:
                self.request_pause.set()
                self.pause_button.configure(text="RESUME")

    def cancel(self):
        if self.active:
            self.request_cancel.set()
            self.request_pause.clear()
            self.status.configure(text="Cancelling; flushing completed evidence…")

    def settings(self):
        if self.active:
            return
        window = tk.Toplevel(self.root)
        window.title("DriveWitness Settings / Performance")
        frame = ttk.Frame(window, padding=16)
        frame.pack(fill="both", expand=True)
        network = tk.BooleanVar(value=self.config.network_time)
        usn = tk.BooleanVar(value=self.config.usn_enabled)
        ttk.Checkbutton(frame, text="Observe HTTP network time (ordinary clock observation)", variable=network).pack(anchor="w")
        ttk.Checkbutton(frame, text="Enable NTFS USN optimization in Quick mode", variable=usn).pack(anchor="w")
        entries = {}
        for field, label, value in [("workers", "File worker override (blank = adaptive)", self.config.workers or ""),
                                     ("blake3_threads", "Large-file BLAKE3 threads (blank = adaptive)", self.config.blake3_threads or ""),
                                     ("large_file_threshold", "Large-file threshold in MiB", self.config.large_file_threshold // 1024**2),
                                     ("exclude", "Exclude glob (canonical / paths)", self.excludes[0] if self.excludes else ""),
                                     ("include", "Include glob (files only)", self.includes[0] if self.includes else "")]:
            ttk.Label(frame, text=label).pack(anchor="w", pady=(8, 2))
            entries[field] = tk.StringVar(value=str(value))
            ttk.Entry(frame, textvariable=entries[field], width=60).pack(fill="x")
        def key_choice():
            self.anon_key = filedialog.askopenfilename(title="Select anonymization key (32+ bytes)") or self.anon_key
            self.anonymize = [d["path"] for d in self.paths if d.get("selected")]
            key_label.configure(text=f"Anonymized roots: {len(self.anonymize)} • key: {self.anon_key or 'none'}")
        ttk.Button(frame, text="Anonymize currently selected roots with a key file", command=key_choice).pack(anchor="w", pady=8)
        key_label = ttk.Label(frame, text=f"Anonymized roots: {len(self.anonymize)} • key: {self.anon_key or 'none'}")
        key_label.pack(anchor="w")
        def clear_key():
            self.anonymize, self.anon_key = [], None
            key_label.configure(text="Anonymization disabled")
        ttk.Button(frame, text="Disable anonymization", command=clear_key).pack(anchor="w")
        def signing_choice():
            self.sign_key = filedialog.askopenfilename(title="Select Ed25519 PEM key") or None
            signing_label.configure(text=f"Signing key: {self.sign_key or 'none'}")
        ttk.Button(frame, text="Select manifest signing key", command=signing_choice).pack(anchor="w", pady=8)
        signing_label = ttk.Label(frame, text=f"Signing key: {self.sign_key or 'none'}")
        signing_label.pack(anchor="w")
        ttk.Label(frame, text="Encrypted PEM password (session only)").pack(anchor="w", pady=(8, 2))
        signing_password = tk.StringVar(value=self.sign_password)
        ttk.Entry(frame, textvariable=signing_password, show="•").pack(fill="x")
        def save():
            try:
                config = replace(self.config, network_time=network.get(), usn_enabled=usn.get(),
                                 workers=int(entries["workers"].get()) if entries["workers"].get() else None,
                                 blake3_threads=int(entries["blake3_threads"].get()) if entries["blake3_threads"].get() else None,
                                 large_file_threshold=int(entries["large_file_threshold"].get()) * 1024**2).validate()
                self.config = config
                self.sign_password = signing_password.get()
                self.excludes = [entries["exclude"].get()] if entries["exclude"].get() else []
                self.includes = [entries["include"].get()] if entries["include"].get() else []
                self.background(lambda: config.save(), "saved")
                self.performance_changed()
                window.destroy()
            except ValueError as exc:
                messagebox.showerror("Settings", str(exc))
        ttk.Button(frame, text="Save settings", command=save).pack(anchor="w", pady=10)
        def run_benchmark():
            path = filedialog.askdirectory(title="Read-only benchmark sample directory")
            if path:
                from .benchmark import benchmark
                self.background(lambda: benchmark(path), "benchmark")
        ttk.Button(frame, text="Performance > Benchmark", command=run_benchmark).pack(anchor="w")

    def errors(self):
        db = self.database.get()
        def work():
            from .evidence import connect
            with connect(db, True) as conn:
                return [dict(row) for row in conn.execute("SELECT category,path,error_code,message FROM dw_events ORDER BY id DESC LIMIT 500")]
        self.background(work, "errors")

    def show_text(self, title, text):
        window = tk.Toplevel(self.root)
        window.title(title)
        box = tk.Text(window, wrap="word", width=100, height=30)
        box.pack(fill="both", expand=True)
        box.insert("1.0", text)
        box.configure(state="disabled")

    def poll(self):
        for _ in range(16):
            try:
                kind, data = self.messages.get_nowait()
            except queue.Empty:
                break
            if kind == "settings":
                self.config = data
                self.level.set(data.performance)
                self.mode.set(data.mode)
                self.gpu.set(data.gpu)
                self.performance_changed()
            elif kind == "discovery":
                gpu = ", ".join(g.get("Name", "unknown") for g in data["gpu"]) or "none detected"
                self.hardware.configure(text=f"CPU: {data['cpu_physical']} physical / {data['cpu_logical']} logical • RAM: {data['ram_bytes']/1024**3:.1f} GiB\n"
                                             f"GPU: {gpu} • hashing backend unavailable • USN: per-volume capability shown during scan")
                for drive in data["volumes"]:
                    if drive.get("error"):
                        continue
                    self.paths.append({**drive, "selected": False})
                    self.tree.insert("", "end", values=("", drive["path"], drive["filesystem"], drive["storage"], f"{drive['free']/1024**3:.1f} / {drive['total']/1024**3:.1f}"))
            elif kind == "progress":
                self.status.configure(text=data["status"] + (" • PAUSED" if self.scanner and self.scanner.paused.is_set() else ""))
                self.metrics.configure(text=f"Files: {data['discovered']:,}    Processed: {data['processed']:,}    Changed: {data['modified']:,}    Added: {data['added']:,}    Deleted: {data['deleted']:,}\n"
                                            f"Renamed: {data['renamed']:,}    Unstable: {data['unstable']:,}    Errors: {data['errors']:,}    Skipped: {data['skipped']:,}\n"
                                            f"Read: {data['bytes_read']/1024**3:.3f} GiB    {data['mb_per_sec']:.1f} MB/s    {data['files_per_sec']:.1f} files/s    Elapsed: {data['elapsed']:.1f}s\n"
                                            f"Hash workers: {data['budget']['workers']}    SHA-256 files: {data['sha256_files']:,}    DB queue: {data['db_queue']}    Hash queue: {data['hash_queue']}    CPU: {data['cpu_percent']:.0f}%    Drive utilization: unavailable")
                self.current.configure(text=data["current_path"][-150:])
                self.history.append(data)
                self.draw_chart()
                self.performance_changed()
            elif kind == "completed":
                self.active = False
                self.start_button.configure(state="normal")
                self.pause_button.configure(state="disabled")
                self.cancel_button.configure(state="disabled")
                summary = data["summary"]
                self.status.configure(text=f"{data['status']} • scan {data['scan_id']} • {summary['processed']:,} processed • {summary['errors']} errors • {summary['unstable']} unstable")
            elif kind == "failure":
                if data["kind"] == "completed":
                    self.active = False
                    self.start_button.configure(state="normal")
                    self.pause_button.configure(state="disabled")
                    self.cancel_button.configure(state="disabled")
                self.status.configure(text="Failed: " + data["message"])
                messagebox.showerror("DriveWitness", data["message"])
            elif kind in ("errors", "benchmark"):
                self.show_text("DriveWitness " + kind, json.dumps(data, indent=2, ensure_ascii=False))
            elif kind == "settings_error":
                self.status.configure(text="Settings could not be loaded: " + data)
        if self.closing and not self.active:
            self.root.destroy()
            return
        self.root.after(100, self.poll)

    def draw_chart(self):
        self.chart.delete("all")
        width = max(100, self.chart.winfo_width())
        for field, color in [("mb_per_sec", "#56c5b5"), ("files_per_sec", "#69a8ff"), ("cpu_percent", "#ffbc69"), ("hash_queue", "#97a4b1")]:
            values = [row.get(field) or 0 for row in self.history]
            scale = max(1, max(values, default=1))
            points = []
            for i, value in enumerate(values):
                points.extend((i / 99 * width, 100 - value / scale * 90))
            if len(points) >= 4:
                self.chart.create_line(*points, fill=color, width=2)

    def close(self):
        self.closing = True
        if self.active:
            self.cancel()
        else:
            self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()
