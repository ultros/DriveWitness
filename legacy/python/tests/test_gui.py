import threading
import time

import pytest


def test_gui_throttle_and_responsiveness(tmp_path, monkeypatch):
    import tkinter as tk
    from dw.gui import App
    monkeypatch.setattr(App, "discover", lambda self: None)
    root = tk.Tk()
    root.withdraw()
    try:
        app = App(root)
        app.level.set(60)
        app.step(10)
        assert app.level.get() == 70
        app.step(-1)
        assert app.level.get() == 69
        data = tmp_path / "data"
        data.mkdir()
        for i in range(500):
            (data / str(i)).write_bytes(b"a" * 65536)
        app.paths = [{"path": str(data), "selected": True}]
        app.database.set(str(tmp_path / "evidence.db"))
        app.level.set(100)
        app.config.usn_enabled = False
        app.start()
        deadline = time.monotonic() + 15
        heartbeat = []
        def tick():
            heartbeat.append(time.monotonic())
            root.after(20, tick)
        tick()
        while app.active and time.monotonic() < deadline:
            root.update()
            time.sleep(0.005)
        assert not app.active
        assert app.status.cget("text").startswith("COMPLETED")
        assert len(heartbeat) >= 5
        assert max(b - a for a, b in zip(heartbeat, heartbeat[1:])) < 0.25
    finally:
        root.destroy()
