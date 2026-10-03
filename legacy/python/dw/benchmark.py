"""Bounded, read-only data sampling and reproducible diagnostic benchmarks."""
import hashlib
import os
import sqlite3
import tempfile
import time
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from blake3 import blake3

from .config import Config
from .windows import capabilities, long_path


def representative_files(root, limit=16, max_entries=10000):
    stack = [os.scandir(long_path(root))]
    seen = 0
    small, bigger = [], []
    try:
        while stack and seen < max_entries:
            entry = next(stack[-1], None)
            if entry is None:
                stack.pop().close()
                continue
            seen += 1
            try:
                stat = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or getattr(stat, "st_file_attributes", 0) & 0x400:
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(os.scandir(entry.path))
                elif entry.is_file(follow_symlinks=False) and stat.st_size:
                    if stat.st_size < 1024 * 1024 and len(small) < limit // 2:
                        small.append(entry.path)
                    elif stat.st_size >= 1024 * 1024:
                        bigger.append((stat.st_size, entry.path))
                        bigger.sort(reverse=True)
                        del bigger[limit // 2:]
            except OSError:
                continue
    finally:
        for iterator in stack:
            iterator.close()
    yield from (path for _, path in bigger)
    yield from small


def benchmark(root, cache=True):
    samples, errors = [], []
    remaining = 64 * 1024 * 1024
    start = time.perf_counter()
    paths = list(representative_files(root))  # At most 16 candidates, never a full inventory.
    enumeration_seconds = time.perf_counter() - start
    read_seconds = 0
    for path in paths:
        try:
            t = time.perf_counter()
            with open(path, "rb") as stream:
                data = stream.read(min(remaining, 16 * 1024 * 1024))
            read_seconds += time.perf_counter() - t
            samples.append((path, len(data), data))
            remaining -= len(data)
            if remaining <= 0:
                break
        except OSError as exc:
            errors.append(str(exc))
    enumeration_read_seconds = time.perf_counter() - start
    total = sum(n for _, n, _ in samples)
    if total == 0:
        raise ValueError("Benchmark requires accessible nonempty files (at most 10,000 entries examined)")

    def timed_hash(name, factory):
        t = time.perf_counter()
        for _, _, data in samples:
            factory(data)
        elapsed = time.perf_counter() - t
        return {"name": name, "seconds": elapsed, "mb_per_sec": total / 1024**2 / max(elapsed, 1e-9)}

    tests = [timed_hash("blake3_single", lambda data: blake3(data).digest()),
             timed_hash("blake3_multi", lambda data: blake3(data, max_threads=min(4, os.cpu_count() or 1)).digest()),
             timed_hash("sha256", lambda data: hashlib.sha256(data).digest()),
             timed_hash("dual", lambda data: (blake3(data).digest(), hashlib.sha256(data).digest()))]
    worker_tests = []
    for workers in (1, 2, 4, 8):
        if workers > (os.cpu_count() or 1):
            continue
        def read_hash(sample):
            path, size, _ = sample
            b3, sha = blake3(), hashlib.sha256()
            read = 0
            with open(path, "rb", buffering=0) as stream:
                while read < size:
                    chunk = stream.read(min(1024 * 1024, size - read))
                    if not chunk:
                        break
                    b3.update(chunk)
                    sha.update(chunk)
                    read += len(chunk)
            return read
        t = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            count = sum(pool.map(read_hash, samples))
        elapsed = time.perf_counter() - t
        worker_tests.append({"workers": workers, "seconds": elapsed, "mb_per_sec": count / 1024**2 / max(elapsed, 1e-9)})
    with tempfile.TemporaryDirectory(prefix="drivewitness-benchmark-") as folder:
        db = sqlite3.connect(str(Path(folder) / "benchmark.db"))
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("CREATE TABLE rows(id INTEGER PRIMARY KEY,path BLOB,digest BLOB)")
        t = time.perf_counter()
        rows = [(i, zlib.compress(f"sample/{i}".encode()), b"x" * 32) for i in range(5000)]
        compression_seconds = time.perf_counter() - t
        t = time.perf_counter()
        db.executemany("INSERT INTO rows VALUES (?,?,?)", rows)
        insert_seconds = time.perf_counter() - t
        t = time.perf_counter()
        db.commit()
        commit_seconds = time.perf_counter() - t
        db.close()
    read_speed = total / 1024**2 / max(read_seconds, 1e-9)
    best = max(worker_tests, key=lambda row: row["mb_per_sec"])
    dual_speed = next(row["mb_per_sec"] for row in tests if row["name"] == "dual")
    report = {"sample_bytes": total, "sample_files": len(samples), "errors": errors,
              "enumeration_plus_read_seconds": enumeration_read_seconds, "enumeration_seconds": enumeration_seconds,
              "sequential_read_seconds": read_seconds, "read_mb_per_sec": read_speed,
              "hash_tests": tests, "worker_tests": worker_tests, "sqlite_insert_seconds": insert_seconds,
              "sqlite_commit_seconds": commit_seconds, "sqlite_rows_per_sec": 5000 / max(insert_seconds + commit_seconds, 1e-9),
              "compression_seconds": compression_seconds,
              "recommendation": {"workers": best["workers"], "blake3_threads": 1,
                                 "large_file_threshold": 64 * 1024 * 1024, "gpu_eligible": False},
              "limiting_resource": "storage/enumeration" if read_speed < dual_speed else "dual hashing CPU",
              "caveats": "Bounded sample, warm OS cache possible; hardware saturation not established. SQLite test is synthetic."}
    if cache:
        config = Config.load()
        config.benchmark_cache = {"root": str(Path(root).resolve()), "report": report}
        config.save()
    return report
