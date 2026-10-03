"""Reproducible local comparison. Writes only bounded data in a temporary folder."""
import contextlib
import importlib.util
import io
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import types
import platform
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dw.benchmark import benchmark
from dw.config import Config
from dw.scanner import Scanner
from dw.windows import volume_info


def original_module():
    source = subprocess.run(["git", "show", "aaaf944:drivewitness.py"], capture_output=True, text=True, check=True).stdout
    # The baseline scan functions do not use these drive/time imports. Supply stubs
    # instead of installing obsolete runtime dependencies just to time that function.
    saved = {name: sys.modules.get(name) for name in ("requests", "win32api", "win32file", "pywintypes")}
    for name in saved:
        sys.modules[name] = types.ModuleType(name)
    module = types.ModuleType("original_drivewitness")
    try:
        exec(compile(source, "original_drivewitness.py", "exec"), module.__dict__)
    finally:
        for name, value in saved.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value
    return module


def run(output):
    original = original_module()
    report = {"methodology": "Warm-cache medians of three runs, original SHA-1 versus new dual-hash (different guarantees); new serial versus new adaptive (same guarantees). No raw-drive saturation claim."}
    import psutil
    report["hardware"] = {"python": platform.python_version(), "platform": platform.platform(),
                          "logical_cpus": os.cpu_count(), "physical_cpus": psutil.cpu_count(logical=False),
                          "ram_bytes": psutil.virtual_memory().total, "storage": volume_info(tempfile.gettempdir())["storage"]}
    with tempfile.TemporaryDirectory(prefix="drivewitness-performance-") as folder:
        root = Path(folder)
        data = root / "data"
        data.mkdir()
        for i in range(2000):
            (data / f"small-{i:04}.bin").write_bytes(bytes([i % 256]) * 4096)
        for i in range(4):
            (data / f"medium-{i}.bin").write_bytes(bytes([i]) * (16 * 1024 * 1024))
        report["dataset"] = {"small_files": 2000, "small_bytes_each": 4096, "medium_files": 4,
                             "medium_bytes_each": 16 * 1024 * 1024, "total_bytes": 2000 * 4096 + 64 * 1024 * 1024}
        legacy_times = []
        for i in range(3):
            print(f"Timing original run {i + 1}…", flush=True)
            t = time.perf_counter()
            conn = original.init_db(root / f"legacy-{i}.db")
            with contextlib.redirect_stdout(io.StringIO()):
                original.index_drive(str(data), conn, scan_time="2026-10-02T00:00:00+00:00")
            conn.close()
            legacy_times.append(time.perf_counter() - t)
        report["original_sha1_seconds"] = legacy_times
        for label, workers in [("modern_serial", 1), ("modern_adaptive", None)]:
            times, details = [], []
            for i in range(3):
                print(f"Timing {label} run {i + 1}…", flush=True)
                scanner = Scanner(root / f"{label}-{i}.db", Config(usn_enabled=False, workers=workers, performance=60))
                t = time.perf_counter()
                result = scanner.run([str(data)])
                times.append(time.perf_counter() - t)
                details.append(result["summary"])
            report[label + "_seconds"] = times
            report[label + "_summary"] = details[-1]
        report["median_seconds"] = {name: statistics.median(report[name + "_seconds"])
                                     for name in ("original_sha1", "modern_serial", "modern_adaptive")}
        report["bounded_benchmark"] = benchmark(str(data), cache=False)
        summary = report["modern_adaptive_summary"]
        components = ("read", "blake3", "sha256", "metadata", "enumeration", "compression", "db_insert", "db_commit", "merkle")
        total = sum(summary[name] for name in components)
        report["subsystem_service_percent"] = {name: 100 * summary[name] / max(total, 1e-9) for name in components}
        report["dominant_measured_subsystem"] = max(components, key=lambda name: summary[name])
        report["service_percent_note"] = "Aggregate instrumented subsystem service time; concurrent worker service times overlap and are not wall-clock fractions. Scheduler/Python overhead is not separately measured."
    Path(output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"median_seconds": report["median_seconds"], "dominant": report["dominant_measured_subsystem"],
                      "subsystems": report["subsystem_service_percent"]}, indent=2))


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "PERFORMANCE_REPORT.json")
