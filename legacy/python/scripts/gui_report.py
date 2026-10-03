"""Measure actual Tk event-loop startup and responsiveness without a visible window."""
import json
import sys
import tempfile
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dw.gui import App


def run():
    with tempfile.TemporaryDirectory(prefix="drivewitness-gui-") as folder:
        data = Path(folder) / "data"
        data.mkdir()
        for i in range(1000):
            (data / str(i)).write_bytes(b"x" * 65536)
        t = time.perf_counter()
        root = tk.Tk()
        root.withdraw()
        app = App(root)
        root.update()
        interactive = time.perf_counter() - t
        app.paths.append({"path": str(data), "selected": True})
        app.database.set(str(Path(folder) / "scan.db"))
        app.level.set(100)
        app.config.usn_enabled = False
        app.start()
        stamps = []
        def heartbeat():
            stamps.append(time.perf_counter())
            root.after(20, heartbeat)
        heartbeat()
        while app.active:
            root.update()
            time.sleep(0.005)
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        report = {"tk_and_window_construction_seconds": interactive,
                  "heartbeat_count": len(stamps), "max_heartbeat_gap_seconds": max(gaps, default=0),
                  "status": app.status.cget("text"), "performance": 100,
                  "caveat": "Window withdrawn for testing; timings exclude Python process launch and Tk import. Background discovery also ran."}
        root.destroy()
    Path("GUI_TEST_REPORT.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    run()
