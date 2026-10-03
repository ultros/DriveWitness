"""Versioned settings and live, bounded resource budgets."""
import json
import os
import threading
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Config:
    version: int = 1
    performance: int = 60
    mode: str = "verify"
    gpu: str = "auto"
    workers: int | None = None
    blake3_threads: int | None = None
    large_file_threshold: int = 64 * 1024 * 1024
    chunk_bytes: int = 1024 * 1024
    db_batch_rows: int = 2000
    db_commit_seconds: float = 2.0
    unstable_retries: int = 1
    ui_progress_interval: float = 0.25
    usn_enabled: bool = True
    network_time: bool = False
    storage: str = "unknown"
    benchmark_cache: dict | None = None

    def validate(self):
        if self.version != 1:
            raise ValueError("Unsupported configuration version")
        if not 0 <= self.performance <= 100:
            raise ValueError("Performance must be between 0 and 100")
        if self.mode not in ("quick", "verify", "forensic"):
            raise ValueError("Invalid scan mode")
        if self.gpu not in ("auto", "off", "force"):
            raise ValueError("Invalid GPU mode")
        for value in (self.workers, self.blake3_threads):
            if value is not None and not 1 <= value <= 32:
                raise ValueError("Worker/thread overrides must be between 1 and 32")
        if not 65536 <= self.chunk_bytes <= 16 * 1024 * 1024:
            raise ValueError("Chunk size must be 64 KiB to 16 MiB")
        if self.large_file_threshold < self.chunk_bytes:
            raise ValueError("Large file threshold must be at least one chunk")
        if not 1 <= self.db_batch_rows <= 10000 or not 0.1 <= self.db_commit_seconds <= 10:
            raise ValueError("Invalid database batching configuration")
        if not 0 <= self.unstable_retries <= 5:
            raise ValueError("Retries must be between zero and five")
        return self

    @classmethod
    def load(cls, path=None):
        path = Path(path) if path else settings_path()
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data).validate()

    def save(self, path=None):
        self.validate()
        path = Path(path) if path else settings_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        os.replace(temp, path)


def settings_path():
    return Path(os.getenv("LOCALAPPDATA", str(Path.home()))) / "DriveWitness" / "config.json"


class Budget:
    def __init__(self, config):
        self.config = config.validate()
        self._lock = threading.Lock()
        self._level = config.performance
        self.cpu = max(1, os.cpu_count() or 1)
        self.limit = min(32, self.cpu)
        self.storage = config.storage

    def set(self, level):
        with self._lock:
            self._level = max(0, min(100, int(level)))

    def get(self):
        with self._lock:
            level = self._level
        label = ("Quiet" if level <= 20 else "Low" if level <= 45 else
                 "Balanced" if level <= 70 else "Fast" if level <= 90 else "Maximum")
        storage_cap = {"hdd": 2, "remote": 2, "unknown": 4, "ssd": 8, "nvme": 16}.get(self.storage, 4)
        workers = min(self.limit, storage_cap, 1 + level * max(0, storage_cap - 1) // 100)
        workers = min(self.limit, self.config.workers or workers)
        threads = min(self.limit, self.config.blake3_threads or max(1, 1 + level * (min(8, self.cpu) - 1) // 100))
        return {"level": level, "label": label, "workers": workers, "large_threads": threads,
                "queue_depth": max(4, workers * 4), "storage": self.storage,
                "quiet_delay": max(0, (25 - level) / 1000)}
