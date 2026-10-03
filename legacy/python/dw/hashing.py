"""Stable read-only hashing and an optional, validated accelerator seam."""
import hashlib
import os
import random
import threading
import time
from typing import Protocol

from blake3 import blake3

from .windows import change_token, file_usn, identity, long_path


class Cancelled(Exception):
    pass


class Unstable(Exception):
    pass


class HashBackend(Protocol):
    name: str
    version: str

    def digest(self, data: bytes) -> bytes: ...


class Accelerator:
    """No GPU backend ships today. Every installed backend must be validated.

    The interface validates standard vectors and deterministic randomized data.
    Runtime digests are CPU cross-checked; a bad backend is disabled for the session.
    Streaming file collection currently always uses the official CPU backend.
    """
    def __init__(self, backend=None):
        self.backend = backend
        self.eligible = False
        self.error = None
        if backend is not None:
            try:
                rng = random.Random(0)
                for data in [b"", b"abc"] + [rng.randbytes(n) for n in (1, 64, 1024, 1025, 65536)]:
                    if backend.digest(data) != blake3(data).digest():
                        raise ValueError("GPU_ERROR: backend digest validation failed")
                self.eligible = True
            except Exception as exc:
                self.error = str(exc)

    def digest(self, data):
        expected = blake3(data).digest()
        if self.eligible:
            try:
                actual = self.backend.digest(data)
                if actual != expected:
                    raise ValueError("GPU_ERROR: runtime CPU cross-check failed")
                return actual
            except Exception as exc:
                self.error, self.eligible = str(exc), False
        return expected


def fingerprint(stat, file_identity):
    # Python/Windows stat and fstat disagree on st_ctime semantics on some releases.
    # Birth time is consistent there; POSIX ctime remains a useful mutation signal.
    return file_identity, stat.st_size, stat.st_mtime_ns, getattr(stat, "st_birthtime_ns", stat.st_ctime_ns)


def wait_control(cancel, paused):
    while paused.is_set():
        if cancel.wait(0.05):
            raise Cancelled()
    if cancel.is_set():
        raise Cancelled()


def hash_file(path, previous=None, full=False, threads=1, config=None, cancel=None, paused=None, on_bytes=None, budget=None):
    cancel = cancel or threading.Event()
    paused = paused or threading.Event()
    timings = {"read": 0.0, "blake3": 0.0, "sha256": 0.0, "metadata": 0.0}
    bytes_read = 0
    for attempt in range(config.unstable_retries + 1):
        try:
            wait_control(cancel, paused)
            t = time.perf_counter()
            with open(long_path(path), "rb", buffering=0) as stream:
                before = os.fstat(stream.fileno())
                before_id = identity(fd=stream.fileno(), stat=before)
                before_change = change_token(stream.fileno(), before)
                object_usn = None
                if os.name == "nt" and before.st_nlink > 1:
                    try:
                        object_usn = file_usn(path)
                    except (OSError, ValueError):
                        pass
                timings["metadata"] += time.perf_counter() - t
                primary = blake3(max_threads=threads)
                # Baselines and new files compute both digests in a single read.
                dual = full or not previous or previous["blake3"] is None or previous["sha256"] is None
                sha = hashlib.sha256() if dual else None

                def read_into_hashers(b3, sha256):
                    nonlocal bytes_read
                    while True:
                        wait_control(cancel, paused)
                        # Live Quiet pacing also applies inside long-running files, so
                        # lowering the slider does not wait for a huge file to finish.
                        delay = budget.get()["quiet_delay"] if budget is not None else 0
                        if delay and cancel.wait(delay):
                            raise Cancelled()
                        t = time.perf_counter()
                        chunk = stream.read(config.chunk_bytes)
                        timings["read"] += time.perf_counter() - t
                        if not chunk:
                            break
                        bytes_read += len(chunk)
                        if on_bytes is not None:
                            on_bytes(len(chunk))
                        if b3 is not None:
                            t = time.perf_counter()
                            b3.update(chunk)
                            timings["blake3"] += time.perf_counter() - t
                        if sha256 is not None:
                            t = time.perf_counter()
                            sha256.update(chunk)
                            timings["sha256"] += time.perf_counter() - t

                read_into_hashers(primary, sha)
                digest = primary.digest()
                changed = previous is not None and previous["blake3"] != digest
                if not dual and changed:
                    stream.seek(0)
                    sha = hashlib.sha256()
                    read_into_hashers(None, sha)
                t = time.perf_counter()
                after = os.fstat(stream.fileno())
                after_id = identity(fd=stream.fileno(), stat=after)
                after_change = change_token(stream.fileno(), after)
                if object_usn is not None and file_usn(path) != object_usn:
                    raise Unstable("Hard-linked object changed during hashing")
                # Detect path replacement as well as mutation of the open object.
                path_stat = os.stat(long_path(path), follow_symlinks=False)
                path_id = identity(path=path, stat=path_stat)
                timings["metadata"] += time.perf_counter() - t
                if (before_change != after_change or fingerprint(before, before_id) != fingerprint(after, after_id) or
                        fingerprint(after, after_id) != fingerprint(path_stat, path_id)):
                    raise Unstable("File identity/size/timestamps changed during hashing")
                return {"stat": before, "identity": before_id, "blake3": digest,
                        "sha256": sha.digest() if sha is not None else previous["sha256"],
                        "sha256_origin_scan": None if sha is not None else previous["sha256_origin_scan"],
                        "sha256_provenance": "RECALCULATED" if sha is not None else "CARRIED_FORWARD",
                        "method": "FULL_DUAL_HASH" if dual else "BLAKE3_CHANGED_SHA256" if changed else "FULL_BLAKE3",
                        "status": "ADDED" if previous is None else "MODIFIED" if changed else "UNCHANGED",
                        "bytes_read": bytes_read, "timings": timings, "object_usn": object_usn}
        except Unstable:
            if attempt == config.unstable_retries:
                raise
    raise Unstable("Unstable file")
