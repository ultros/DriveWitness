"""Streaming enumerator -> bounded futures -> coordinated SQLite writer.

The calling thread owns all SQLite writes. The GUI runs it in a background thread.
"""
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import queue
import sqlite3
import threading
import time
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path

from . import SCHEMA_VERSION, __version__
from .config import Budget, Config
from .evidence import (canonical_json, canonical_path, compress, connect, export_manifest,
                       init_db, machine_id, roots, sign_manifest, utc)
from .hashing import Cancelled, Unstable, fingerprint, hash_file, wait_control
from . import windows

LOGGER = logging.getLogger("drivewitness")


@contextmanager
def database_lock(db):
    path = str(Path(db).resolve()) + ".lock"
    with open(path, "a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ValueError("Another collector is using this evidence database") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def categorize(exc):
    if isinstance(exc, PermissionError):
        return "ACCESS_DENIED"
    if isinstance(exc, FileNotFoundError):
        return "FILE_DISAPPEARED"
    if isinstance(exc, Unstable):
        return "UNSTABLE"
    if isinstance(exc, OSError):
        return "READ_ERROR"
    return "HASH_ERROR"


def normalized_root(path):
    # Windows C: means the root, not that drive's per-process current directory.
    if os.name == "nt" and len(path) == 2 and path[1] == ":":
        path += "\\"
    return os.path.realpath(os.path.abspath(path))


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"discovered": 0, "processed": 0, "added": 0, "modified": 0, "deleted": 0,
                     "renamed": 0, "unstable": 0, "errors": 0, "skipped": 0, "directories": 0,
                     "bytes_read": 0, "sha256_files": 0, "current_path": "", "status": "STARTING",
                     "read": 0.0, "blake3": 0.0, "sha256": 0.0, "metadata": 0.0,
                     "enumeration": 0.0, "compression": 0.0, "db_insert": 0.0,
                     "db_commit": 0.0, "merkle": 0.0, "network_time": 0.0}
        self.start = time.monotonic()
        self.samples = deque(maxlen=20)

    def add(self, **values):
        with self.lock:
            for name, value in values.items():
                self.data[name] += value

    def set(self, **values):
        with self.lock:
            self.data.update(values)

    def snapshot(self):
        with self.lock:
            data = dict(self.data)
        now = time.monotonic()
        self.samples.append((now, data["bytes_read"], data["processed"]))
        first = self.samples[0]
        dt = max(0.001, now - first[0])
        data.update(elapsed=now - self.start, mb_per_sec=(data["bytes_read"] - first[1]) / dt / 1024**2,
                    files_per_sec=(data["processed"] - first[2]) / dt)
        return data


class Scanner:
    def __init__(self, db, config=None, on_progress=None):
        self.db = str(Path(db).resolve())
        self.config = (config or Config()).validate()
        self.budget = Budget(self.config)
        self.cancel = threading.Event()
        self.paused = threading.Event()
        self.stats = Stats()
        self.on_progress = on_progress
        self.work = queue.Queue(maxsize=128)
        self._queue_condition = threading.Condition()
        self.scan_id = None
        self.parent = None
        self._last_progress = 0.0
        self._coverage_incomplete = False
        self._rows = []

    def progress(self, active=0):
        if time.monotonic() - self._last_progress >= self.config.ui_progress_interval:
            self._last_progress = time.monotonic()
            data = self.stats.snapshot()
            import psutil
            data.update(budget=self.budget.get(), hash_queue=self.work.qsize(),
                        db_queue=len(self._rows), active_workers=active, gpu_backend="cpu_blake3", cpu_percent=psutil.cpu_percent(),
                        disk_percent=None, eta=None)
            if self.on_progress:
                try:
                    self.on_progress(data)
                except Exception:
                    LOGGER.exception("Progress consumer failed", extra={"scan_id": self.scan_id})

    def put(self, item):
        while not self.cancel.is_set():
            wait_control(self.cancel, self.paused)
            with self._queue_condition:
                if self.work.qsize() >= self.budget.get()["queue_depth"]:
                    self._queue_condition.wait(0.05)
                    continue
                self.work.put_nowait(item)
                return
        raise Cancelled()

    @contextmanager
    def hashing_pool(self):
        pool = ThreadPoolExecutor(max_workers=self.budget.limit, thread_name_prefix="dw-hash")
        try:
            yield pool
        except BaseException:
            # Signal before executor shutdown waits for active readers.
            self.cancel.set()
            raise
        finally:
            pool.shutdown(wait=True, cancel_futures=True)

    def enumerate(self, roots_selected, excludes, includes, ignored, done):
        try:
            for selected in roots_selected:
                # Depth-first scandir iterators use O(depth) memory, not O(file count).
                stack = []
                try:
                    self.stats.add(directories=1)
                    stack.append((selected, os.scandir(windows.long_path(selected))))
                    while stack:
                        wait_control(self.cancel, self.paused)
                        parent, iterator = stack[-1]
                        t = time.perf_counter()
                        entry = next(iterator, None)
                        self.stats.add(enumeration=time.perf_counter() - t)
                        if entry is None:
                            iterator.close()
                            stack.pop()
                            continue
                        path = os.path.join(parent, entry.name)
                        canonical = canonical_path(path)
                        if canonical in ignored or any(fnmatch.fnmatchcase(canonical, p) for p in excludes):
                            self.stats.add(skipped=1)
                            continue
                        try:
                            t = time.perf_counter()
                            stat = entry.stat(follow_symlinks=False)
                            self.stats.add(metadata=time.perf_counter() - t)
                            reparse = bool(getattr(stat, "st_file_attributes", 0) & 0x400) or entry.is_symlink()
                            if reparse:
                                self.put(("event", {"path": path, "category": "REPARSE_POINT",
                                                    "message": "Not followed; target content is outside this collection policy"}))
                                self.stats.add(skipped=1)
                            elif entry.is_dir(follow_symlinks=False):
                                self.stats.add(directories=1)
                                stack.append((path, os.scandir(windows.long_path(path))))
                            elif entry.is_file(follow_symlinks=False):
                                if includes and not any(fnmatch.fnmatchcase(canonical, p) for p in includes):
                                    self.stats.add(skipped=1)
                                    continue
                                self.stats.add(discovered=1)
                                self.put(("file", path, stat))
                            else:
                                self.stats.add(skipped=1)
                        except OSError as exc:
                            self.put(("event", {"path": path, "category": categorize(exc),
                                                "message": str(exc), "error_code": getattr(exc, "winerror", exc.errno),
                                                "incomplete": True}))
                except OSError as exc:
                    self.put(("event", {"path": selected, "category": categorize(exc), "message": str(exc), "incomplete": True}))
                finally:
                    for _, iterator in stack:
                        iterator.close()
        except Cancelled:
            pass
        except Exception as exc:
            # A producer failure must not masquerade as a complete inventory.
            self._producer_failure = exc
            self.cancel.set()
        finally:
            done.set()

    def run(self, paths, *, anonymize=(), anonymization_key=None, excludes=(), includes=(),
            signing_key=None, signing_password=None, timestamp_provider=None):
        self.paths = sorted(set(normalized_root(p) for p in paths))
        if not self.paths or any(not os.path.isdir(windows.long_path(p)) for p in self.paths):
            raise ValueError("Select existing drive roots or directories")
        for i, path in enumerate(self.paths):
            if any(os.path.commonpath([path, other]) == other for other in self.paths[:i]
                   if os.path.splitdrive(path)[0].lower() == os.path.splitdrive(other)[0].lower()):
                raise ValueError("Selected scan roots overlap")
        self.anon_roots = [normalized_root(p) for p in anonymize]
        if self.anon_roots and (anonymization_key is None or len(anonymization_key) < 32):
            raise ValueError("Anonymization requires an explicit key file containing at least 32 bytes")
        self.anon_key = anonymization_key
        # Force cannot quietly imply hardware hashing which does not exist.
        if self.config.gpu == "force":
            raise ValueError("No validated GPU hashing backend is installed; choose Auto or Off")
        scope = canonical_json({"roots": [self.stored_path(p) for p in self.paths], "exclude": sorted(excludes), "include": sorted(includes),
                                "anonymize": sorted(self.stored_path(p) for p in self.anon_roots),
                                "key_id": hashlib.sha256(anonymization_key).hexdigest() if self.anon_roots else None}).decode()
        self._producer_failure = None
        with database_lock(self.db):
            conn = init_db(self.db, self.config.mode == "forensic")
            try:
                parent = conn.execute("SELECT * FROM dw_scans WHERE status='COMPLETED' AND scope=? ORDER BY id DESC LIMIT 1", (scope,)).fetchone()
                self.parent = parent["id"] if parent else None
                cursor = conn.execute("INSERT INTO dw_scans(schema_version,status,parent_scan_id,started,machine_id,mode,scope,config) VALUES (?,?,?,?,?,?,?,?)",
                                      (SCHEMA_VERSION, "RUNNING", self.parent, utc(), machine_id(), self.config.mode, scope, json.dumps(asdict(self.config))))
                self.scan_id = cursor.lastrowid
                conn.commit()
                self.stats.set(status="RUNNING")
                volume_records = self.prepare_volumes(conn)
                if self.config.network_time:
                    self.observe_network_time(conn)
                self.collect(conn, excludes, includes)
                if self._producer_failure:
                    raise self._producer_failure
                if self.cancel.is_set():
                    status = "CANCELLED"
                else:
                    self.finalize_deletions(conn)
                    status = "COMPLETED"
                summary = self.stats.snapshot()
                summary["status"] = status
                if status == "COMPLETED":
                    self.stats.set(status="FINALIZING")
                    self.progress()
                    conn.commit()
                    t = time.perf_counter()
                    def root_progress():
                        wait_control(self.cancel, self.paused)
                        self.progress()
                    calculated = roots(conn, self.scan_id, root_progress)
                    self.stats.add(merkle=time.perf_counter() - t)
                    for source_path, record in zip(self.paths, volume_records):
                        try:
                            end = windows.journal(source_path)
                            record["journal_end"] = end
                            if record["journal_start"]:
                                ok, reason = windows.continuity(record["journal_start"], end)
                                if not ok:
                                    record["continuity"] = "END_INVALID: " + reason
                        except (OSError, ValueError) as exc:
                            record["end_error"] = str(exc)
                        conn.execute("UPDATE dw_volumes SET journal_end=?,continuity=? WHERE scan_id=? AND path=?",
                                     (json.dumps(record.get("journal_end")), record["continuity"], self.scan_id, record["path"]))
                    summary = self.stats.snapshot()
                    summary["status"] = status
                    completion = utc()
                    manifest = {"version": __version__, "schema_version": SCHEMA_VERSION, "scan_id": self.scan_id,
                                "machine_id": machine_id(), "started": conn.execute("SELECT started FROM dw_scans WHERE id=?", (self.scan_id,)).fetchone()[0],
                                "completed": completion, "hash_algorithms": ["BLAKE3", "SHA-256"],
                                "system_time": conn.execute("SELECT started FROM dw_scans WHERE id=?", (self.scan_id,)).fetchone()[0],
                                "network_time_observation": conn.execute("SELECT network_time_observation FROM dw_scans WHERE id=?", (self.scan_id,)).fetchone()[0],
                                "file_count": conn.execute("SELECT COUNT(*) FROM dw_files WHERE scan_id=? AND status!='DELETED'", (self.scan_id,)).fetchone()[0],
                                "directory_count": summary["directories"], "bytes_processed": summary["bytes_read"],
                                "verification_mode": self.config.mode, "volumes": volume_records,
                                "scope": json.loads(scope), "summary": summary,
                                "performance": asdict(self.config), "final_budget": self.budget.get(),
                                "backend": "official blake3 Rust CPU + hashlib SHA-256", "gpu_backend": None,
                                "previous_scan_root": parent["scan_root"] if parent else None,
                                "coverage_complete": not self._coverage_incomplete and summary["errors"] == 0 and summary["unstable"] == 0 and summary["skipped"] == 0,
                                "stream_policy": "Default data stream only; reparse targets excluded",
                                "trusted_timestamp": "not configured" if not timestamp_provider else "separate validated proof",
                                **calculated}
                    if signing_key:
                        public, signature = sign_manifest(manifest, signing_key, signing_password)
                        conn.execute("INSERT INTO dw_signatures VALUES (?,?,?,?)", (self.scan_id, "Ed25519", public, signature))
                    if timestamp_provider:
                        try:
                            proof = timestamp_provider.timestamp(hashlib.sha256(canonical_json(manifest)).digest())
                        except Exception as exc:
                            self.event(conn, "TIMESTAMP_ERROR", None, str(exc))
                            conn.commit()
                            raise
                        conn.execute("UPDATE dw_scans SET trusted_timestamp_proof=? WHERE id=?", (proof, self.scan_id))
                    wait_control(self.cancel, self.paused)
                    conn.execute("UPDATE dw_scans SET content_root=?,metadata_root=?,scan_root=?,manifest=?,completed=? WHERE id=?",
                                 (*calculated.values(), canonical_json(manifest).decode(), completion, self.scan_id))
                conn.execute("UPDATE dw_scans SET status=?,summary=?,completed=COALESCE(completed,?) WHERE id=?",
                             (status, json.dumps(summary), utc(), self.scan_id))
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                if status == "COMPLETED":
                    try:
                        export_manifest(self.db, self.db + ".manifest.json", self.scan_id)
                    except OSError as exc:
                        # Evidence finalization succeeded; export can be retried independently.
                        self.event(conn, "MANIFEST_EXPORT_ERROR", None, str(exc))
                        conn.commit()
                        summary["manifest_export_error"] = str(exc)
                self.stats.set(status=status)
                self._last_progress = 0
                self.progress()
                return {"scan_id": self.scan_id, "db": self.db, "status": status, "summary": summary}
            except Cancelled:
                self.flush_rows(conn)
                summary = self.stats.snapshot()
                summary["status"] = "CANCELLED"
                conn.execute("UPDATE dw_scans SET status='CANCELLED',completed=?,summary=? WHERE id=?", (utc(), json.dumps(summary), self.scan_id))
                conn.commit()
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.stats.set(status="CANCELLED")
                return {"scan_id": self.scan_id, "db": self.db, "status": "CANCELLED", "summary": summary}
            except BaseException as exc:
                self.cancel.set()
                conn.rollback()
                if self.scan_id is not None:
                    try:
                        conn.execute("UPDATE dw_scans SET status='FAILED',failure=?,completed=? WHERE id=?", (str(exc), utc(), self.scan_id))
                        conn.commit()
                    except sqlite3.Error:
                        # RUNNING is deliberately retained if the storage device cannot record failure.
                        LOGGER.exception("DATABASE_ERROR while recording failure", extra={"scan_id": self.scan_id})
                self.stats.set(status="FAILED")
                raise
            finally:
                conn.close()

    def anonymized(self, path):
        for root in self.anon_roots:
            try:
                if os.path.commonpath([os.path.abspath(path), root]) == root:
                    return True
            except ValueError:
                continue
        return False

    def stored_path(self, path):
        canonical = canonical_path(path)
        if self.anonymized(path):
            return "hmac-sha256:" + hmac.new(self.anon_key, canonical.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
        return canonical

    def event(self, conn, category, path, message, code=None):
        stored = self.stored_path(path) if path else None
        # OS exception messages commonly contain the complete sensitive filename.
        if path and self.anonymized(path):
            message = category + " (path redacted)"
        conn.execute("INSERT INTO dw_events(scan_id,time,category,path,error_code,message) VALUES (?,?,?,?,?,?)",
                     (self.scan_id, utc(), category, stored, str(code) if code is not None else None, message))

    def observe_network_time(self, conn):
        from urllib.request import urlopen, Request
        t = time.perf_counter()
        try:
            request = Request("https://worldtimeapi.org/api/ip", headers={"User-Agent": "DriveWitness/2"})
            with urlopen(request, timeout=3) as response:
                observation = json.loads(response.read(65536))["utc_datetime"]
            conn.execute("UPDATE dw_scans SET network_time_observation=? WHERE id=?", (observation, self.scan_id))
        except Exception as exc:
            self.event(conn, "NETWORK_TIME_ERROR", None, str(exc))
        self.stats.add(network_time=time.perf_counter() - t)
        conn.commit()

    def prepare_volumes(self, conn):
        conn.execute("CREATE TEMP TABLE dw_dirty(volume TEXT,file_id TEXT,PRIMARY KEY(volume,file_id)) WITHOUT ROWID")
        conn.execute("""CREATE TEMP TABLE dw_objects(volume TEXT,file_id TEXT,size INTEGER,modified_ns INTEGER,
                     object_usn INTEGER,blake3 BLOB,sha256 BLOB,origin_scan INTEGER,
                     PRIMARY KEY(volume,file_id)) WITHOUT ROWID""")
        self.quick_volumes = {}
        result = []
        for path in self.paths:
            info = windows.volume_info(path)
            stored = self.stored_path(path)
            record = {"path": stored, "info": info, "journal_start": None, "continuity": "NOT_USED"}
            if self.anonymized(path):
                info = {**info, "label": "redacted"}
                record["info"] = info
            if self.config.storage == "unknown":
                # Mixed drives use the most conservative detected budget.
                rank = {"unknown": 0, "remote": 1, "hdd": 1, "ssd": 2, "nvme": 3}
                if self.budget.storage == "unknown" or rank[info["storage"]] < rank[self.budget.storage]:
                    self.budget.storage = info["storage"]
            if self.config.usn_enabled:
                try:
                    current = windows.journal(path)
                    record["journal_start"] = current
                    previous_row = conn.execute("SELECT journal_start,continuity FROM dw_volumes WHERE scan_id=? AND path=?", (self.parent, stored)).fetchone()
                    previous = json.loads(previous_row[0]) if previous_row and previous_row[0] else None
                    if previous_row and previous_row[1].startswith("END_INVALID"):
                        previous = None
                    ok, reason = windows.continuity(previous, current)
                    record["continuity"] = reason
                    if self.config.mode == "quick" and ok:
                        for change in windows.journal_changes(previous, current):
                            wait_control(self.cancel, self.paused)
                            conn.execute("INSERT OR IGNORE INTO dw_dirty VALUES (?,?)", (stored, change["file_id"]))
                        self.quick_volumes[path] = current
                    elif self.config.mode == "quick":
                        self.event(conn, "USN_ERROR", path, "Full verification fallback: " + reason)
                except (OSError, ValueError) as exc:
                    record["continuity"] = "UNAVAILABLE: " + str(exc)
                    self.event(conn, "USN_ERROR", path, "Full verification fallback: " + str(exc))
                    conn.execute("DELETE FROM dw_dirty WHERE volume=?", (stored,))
            conn.execute("INSERT INTO dw_volumes VALUES (?,?,?,?,?,?)", (self.scan_id, stored, json.dumps(info), json.dumps(record["journal_start"]), None, record["continuity"]))
            result.append(record)
        conn.commit()
        return result

    def previous(self, conn, path, file_identity):
        if not self.parent:
            return None, False
        previous = conn.execute("SELECT * FROM dw_files WHERE scan_id=? AND canonical_path=? AND status NOT IN ('DELETED','ERROR','UNSTABLE','UNVERIFIED')",
                                (self.parent, self.stored_path(path))).fetchone()
        if previous:
            return dict(previous), False
        previous = conn.execute("SELECT * FROM dw_files WHERE scan_id=? AND volume_serial=? AND file_id=? AND blake3 IS NOT NULL AND status NOT IN ('DELETED','UNVERIFIED','ERROR','UNSTABLE') LIMIT 1",
                                (self.parent, *file_identity)).fetchone()
        return (dict(previous), True) if previous else (None, False)

    def quick_result(self, conn, path, stat, file_identity, previous):
        if not previous or previous["blake3"] is None or previous["sha256"] is None:
            return None
        for root, checkpoint in self.quick_volumes.items():
            if os.path.commonpath([path, root]) != root:
                continue
            if conn.execute("SELECT 1 FROM dw_dirty WHERE volume=? AND file_id=?", (self.stored_path(root), file_identity[1])).fetchone():
                return None
            if (previous["volume_serial"], previous["file_id"], previous["size"], previous["modified_ns"]) != (*file_identity, stat.st_size, stat.st_mtime_ns):
                return None
            try:
                # A file changed after journal collection must still be hashed.
                usn = windows.file_usn(path)
                after = os.stat(windows.long_path(path), follow_symlinks=False)
                after_id = windows.identity(path=path, stat=after)
                if usn >= checkpoint["next_usn"] or fingerprint(stat, file_identity) != fingerprint(after, after_id):
                    return None
                return {"stat": stat, "identity": file_identity, "blake3": previous["blake3"], "sha256": previous["sha256"],
                        "sha256_origin_scan": previous["sha256_origin_scan"], "sha256_provenance": "CARRIED_FORWARD",
                        "method": "USN_INCREMENTAL", "status": "UNCHANGED", "bytes_read": 0, "timings": {}}
            except (OSError, ValueError) as exc:
                self.event(conn, "USN_ERROR", path, "Per-file fallback: " + str(exc))
        return None

    def collect(self, conn, excludes, includes):
        ignored = {canonical_path(self.db + suffix) for suffix in ("", "-wal", "-shm", ".lock", ".manifest.json", ".manifest.json.tmp")}
        done = threading.Event()
        producer = threading.Thread(target=self.enumerate, args=(self.paths, excludes, includes, ignored, done), name="dw-enumerator", daemon=True)
        pending, identities = {}, set()
        held = None
        producer.start()
        rows_since_commit, last_commit = 0, time.monotonic()
        def flush():
            nonlocal rows_since_commit, last_commit
            self.flush_rows(conn)
            t = time.perf_counter()
            conn.commit()
            self.stats.add(db_commit=time.perf_counter() - t)
            rows_since_commit, last_commit = 0, time.monotonic()
        try:
            with self.hashing_pool() as pool:
                while pending or held is not None or not done.is_set() or not self.work.empty():
                    budget = self.budget.get()
                    # Drain already finished work even when paused/cancelled.
                    for future in [f for f in pending if f.done()]:
                        path, previous, renamed, file_identity = pending.pop(future)
                        identities.discard(file_identity)
                        try:
                            result = future.result()
                            if renamed:
                                result["status"] = "LINK_OR_RENAME"
                            self.store_result(conn, path, result, previous)
                        except Cancelled:
                            continue
                        except sqlite3.Error:
                            self.cancel.set()
                            raise
                        except Exception as exc:
                            self.store_error(conn, path, exc)
                        rows_since_commit += 1
                    if rows_since_commit >= self.config.db_batch_rows or time.monotonic() - last_commit >= self.config.db_commit_seconds:
                        flush()
                    self.progress(len(pending))
                    if self.cancel.is_set():
                        held = None
                        while not self.work.empty():
                            self.work.get_nowait()
                        if pending:
                            wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                        elif not done.is_set():
                            done.wait(0.05)
                        continue
                    if self.paused.is_set():
                        self.cancel.wait(0.05)
                        continue
                    if len(pending) >= budget["workers"]:
                        wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                        continue
                    if held is None:
                        try:
                            held = self.work.get(timeout=0.05)
                            with self._queue_condition:
                                self._queue_condition.notify()
                        except queue.Empty:
                            continue
                    item = held
                    if item[0] == "event":
                        event = item[1]
                        self.event(conn, event["category"], event["path"], event["message"], event.get("error_code"))
                        if event.get("incomplete"):
                            self._coverage_incomplete = True
                            self.stats.add(errors=1)
                        held = None
                        rows_since_commit += 1
                        continue
                    _, path, stat = item
                    large = stat.st_size >= self.config.large_file_threshold
                    if large and pending:
                        wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                        continue
                    # A large-file task reserves the thread budget exclusively.
                    if any(getattr(f, "dw_large", False) for f in pending):
                        wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                        continue
                    try:
                        # A new ordinary file needs no extra identity handle before the
                        # hashing worker opens it. Its open-handle identity is authoritative.
                        file_identity = (windows.identity(path=path, stat=stat) if self.parent or stat.st_nlink > 1 or self.config.mode == "quick"
                                         else ("pending_path", self.stored_path(path)))
                        if file_identity in identities:
                            wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                            continue
                        previous, renamed = self.previous(conn, path, file_identity)
                        result = None
                        if stat.st_nlink > 1:
                            same_object = conn.execute("SELECT * FROM dw_objects WHERE volume=? AND file_id=?", file_identity).fetchone()
                            if same_object and (same_object["size"], same_object["modified_ns"]) == (stat.st_size, stat.st_mtime_ns):
                                try:
                                    token = windows.file_usn(path)
                                    after = os.stat(windows.long_path(path), follow_symlinks=False)
                                    after_id = windows.identity(path=path, stat=after)
                                    if token == same_object["object_usn"] and fingerprint(stat, file_identity) == fingerprint(after, after_id):
                                        result = {"stat": stat, "identity": file_identity, "blake3": same_object["blake3"], "sha256": same_object["sha256"],
                                            "sha256_origin_scan": same_object["origin_scan"], "sha256_provenance": "SAME_SCAN_OBJECT",
                                            "method": "CARRIED_FORWARD", "status": "LINK_OR_RENAME" if renamed else "ADDED" if previous is None else
                                            "MODIFIED" if previous["blake3"] != same_object["blake3"] else "UNCHANGED", "timings": {}, "bytes_read": 0}
                                except (OSError, ValueError):
                                    pass  # No reliable token: independently read this path.
                        if result is None and self.config.mode == "quick" and not renamed:
                            result = self.quick_result(conn, path, stat, file_identity, previous)
                        if result is not None:
                            self.store_result(conn, path, result, previous)
                            rows_since_commit += 1
                        else:
                            future = pool.submit(hash_file, path, previous, self.config.mode == "forensic",
                                                 budget["large_threads"] if large else 1, self.config, self.cancel, self.paused,
                                                 lambda count: self.stats.add(bytes_read=count), self.budget)
                            future.dw_large = large
                            pending[future] = path, previous, renamed, file_identity
                            identities.add(file_identity)
                        self.stats.set(current_path=self.stored_path(path))
                    except sqlite3.Error:
                        self.cancel.set()
                        raise
                    except Exception as exc:
                        self.store_error(conn, path, exc)
                        rows_since_commit += 1
                    held = None
                    if budget["quiet_delay"]:
                        self.cancel.wait(budget["quiet_delay"])
            producer.join(timeout=2)
            flush()
        except BaseException:
            self.cancel.set()
            producer.join(timeout=2)
            raise

    def store_result(self, conn, path, result, previous):
        stat = result["stat"]
        status = result["status"]
        if previous and (previous["volume_serial"], previous["file_id"]) != result["identity"]:
            status = "MODIFIED"
            self.event(conn, "REPLACED", path, "A different file object now occupies this path")
        t = time.perf_counter()
        timestamps = [getattr(stat, "st_birthtime_ns", stat.st_ctime_ns), stat.st_mtime_ns, stat.st_atime_ns]
        from datetime import datetime, timezone
        compressed_times = [compress(datetime.fromtimestamp(n / 1e9, timezone.utc).isoformat()) for n in timestamps]
        original = compress(self.stored_path(path) if self.anonymized(path) else path)
        self.stats.add(compression=time.perf_counter() - t)
        row = (self.scan_id, self.stored_path(path), original, *result["identity"], stat.st_size,
               *timestamps, getattr(stat, "st_file_attributes", stat.st_mode), result["blake3"], result["sha256"],
               None, result["method"], status,
               result["sha256_origin_scan"] or self.scan_id, result["sha256_provenance"], None, None,
               stat.st_nlink, previous["first_seen_scan"] if previous and (previous["volume_serial"], previous["file_id"]) == result["identity"] else self.scan_id, self.scan_id,
               *compressed_times, compress(utc()))
        self._rows.append(row)
        if result.get("object_usn") is not None:
            conn.execute("INSERT OR REPLACE INTO dw_objects VALUES (?,?,?,?,?,?,?,?)", (*result["identity"], stat.st_size, stat.st_mtime_ns,
                         result["object_usn"], result["blake3"], result["sha256"], result["sha256_origin_scan"] or self.scan_id))
        if len(self._rows) >= self.config.db_batch_rows:
            self.flush_rows(conn)
        self.stats.add(processed=1,
                       sha256_files=int(result["sha256_provenance"] == "RECALCULATED"), **result["timings"])
        if status in ("ADDED", "MODIFIED"):
            self.stats.add(**{status.lower(): 1})
        elif status == "LINK_OR_RENAME" and previous and previous["blake3"] != result["blake3"]:
            self.stats.add(modified=1)

    def store_error(self, conn, path, exc):
        category = categorize(exc)
        message = category + " (path redacted)" if self.anonymized(path) else str(exc)
        conn.execute("INSERT INTO dw_files(scan_id,canonical_path,original_path,method,status,error_code,error_message,last_seen_scan) VALUES (?,?,?,?,?,?,?,?)",
                     (self.scan_id, self.stored_path(path), compress(self.stored_path(path) if self.anonymized(path) else path),
                      "UNSTABLE" if category == "UNSTABLE" else "ERROR", "UNSTABLE" if category == "UNSTABLE" else "ERROR", category, message, self.scan_id))
        self.event(conn, category, path, message, getattr(exc, "winerror", getattr(exc, "errno", None)))
        self.stats.add(processed=1, **{"unstable" if category == "UNSTABLE" else "errors": 1})

    def flush_rows(self, conn):
        if self._rows:
            t = time.perf_counter()
            conn.executemany("INSERT INTO dw_files VALUES (" + ",".join("?" for _ in self._rows[0]) + ")", self._rows)
            self.stats.add(db_insert=time.perf_counter() - t)
            self._rows.clear()

    def finalize_deletions(self, conn):
        if not self.parent:
            return
        # Disk-backed SQL anti-join, no inventory-sized Python sets.
        query = """SELECT old.* FROM dw_files old WHERE old.scan_id=? AND old.status!='DELETED'
                   AND NOT EXISTS(SELECT 1 FROM dw_files new WHERE new.scan_id=? AND new.canonical_path=old.canonical_path)"""
        t = time.monotonic()
        for index, old in enumerate(conn.execute(query, (self.parent, self.scan_id))):
            if index % 512 == 0:
                wait_control(self.cancel, self.paused)
                self.progress()
                if time.monotonic() - t >= self.config.db_commit_seconds:
                    conn.commit()
                    t = time.monotonic()
            renamed = conn.execute("SELECT canonical_path FROM dw_files WHERE scan_id=? AND volume_serial=? AND file_id=? AND status='LINK_OR_RENAME' LIMIT 1",
                                   (self.scan_id, old["volume_serial"], old["file_id"])).fetchone()
            if renamed:
                conn.execute("UPDATE dw_files SET status='RENAMED' WHERE scan_id=? AND canonical_path=?", (self.scan_id, renamed[0]))
                conn.execute("INSERT INTO dw_events(scan_id,time,category,path,message) VALUES (?,?,?,?,?)",
                             (self.scan_id, utc(), "RENAMED", old["canonical_path"], "New path: " + renamed[0]))
                self.stats.add(renamed=1)
                continue
            # An inaccessible subtree cannot establish deletion. Conservatively carry as UNVERIFIED.
            uncertain = self._coverage_incomplete
            status = "UNVERIFIED" if uncertain else "DELETED"
            values = dict(old)
            values.update(scan_id=self.scan_id, status=status, method="UNVERIFIED" if uncertain else "CARRIED_FORWARD",
                          sha256_provenance="CARRIED_FORWARD")
            conn.execute("INSERT INTO dw_files VALUES (" + ",".join("?" for _ in values) + ")", tuple(values.values()))
            if not uncertain:
                self.stats.add(deleted=1)
        changed_links = conn.execute("SELECT COUNT(*) FROM dw_files WHERE scan_id=? AND status='LINK_OR_RENAME'", (self.scan_id,)).fetchone()[0]
        conn.execute("UPDATE dw_files SET status='ADDED' WHERE scan_id=? AND status='LINK_OR_RENAME'", (self.scan_id,))
        self.stats.add(added=changed_links)


def compare_databases(baseline, newer):
    with connect(newer, True) as conn:
        conn.execute("ATTACH DATABASE ? AS baseline", (Path(baseline).resolve().as_uri() + "?mode=ro",))
        old_id = conn.execute("SELECT MAX(id) FROM baseline.dw_scans WHERE status='COMPLETED'").fetchone()[0]
        new_id = conn.execute("SELECT MAX(id) FROM dw_scans WHERE status='COMPLETED'").fetchone()[0]
        if old_id is None or new_id is None:
            raise ValueError("Comparison requires completed scans")
        old_scope = conn.execute("SELECT scope FROM baseline.dw_scans WHERE id=?", (old_id,)).fetchone()[0]
        new_scope = conn.execute("SELECT scope FROM dw_scans WHERE id=?", (new_id,)).fetchone()[0]
        if old_scope != new_scope:
            raise ValueError("Comparison scopes/anonymization keys differ")
        counts = {"added": 0, "deleted": 0, "modified": 0, "unchanged": 0, "renamed": 0, "unverified": 0}
        conn.execute("CREATE TEMP TABLE comparison_pairs(old_path TEXT PRIMARY KEY,new_path TEXT UNIQUE,old_hash BLOB,new_hash BLOB)")
        # Deterministic one-to-one pairing of disappeared/new paths sharing object identity.
        # Window ranks avoid treating all surviving hard-link paths as renames.
        conn.execute("""WITH old_missing AS (
           SELECT a.*,ROW_NUMBER() OVER(PARTITION BY a.volume_serial,a.file_id ORDER BY a.canonical_path) rank
           FROM baseline.dw_files a WHERE a.scan_id=? AND a.status NOT IN ('DELETED','ERROR','UNSTABLE','UNVERIFIED')
           AND NOT EXISTS(SELECT 1 FROM dw_files b WHERE b.scan_id=? AND b.status!='DELETED' AND b.canonical_path=a.canonical_path)),
           new_only AS (
           SELECT b.*,ROW_NUMBER() OVER(PARTITION BY b.volume_serial,b.file_id ORDER BY b.canonical_path) rank
           FROM dw_files b WHERE b.scan_id=? AND b.status NOT IN ('DELETED','ERROR','UNSTABLE','UNVERIFIED')
           AND NOT EXISTS(SELECT 1 FROM baseline.dw_files a WHERE a.scan_id=? AND a.status!='DELETED' AND a.canonical_path=b.canonical_path))
           INSERT INTO comparison_pairs SELECT a.canonical_path,b.canonical_path,a.blake3,b.blake3
           FROM old_missing a JOIN new_only b ON a.volume_serial=b.volume_serial AND a.file_id=b.file_id AND a.rank=b.rank""",
           (old_id, new_id, new_id, old_id))
        counts["renamed"] = conn.execute("SELECT COUNT(*) FROM comparison_pairs").fetchone()[0]
        counts["modified"] = conn.execute("SELECT COUNT(*) FROM comparison_pairs WHERE old_hash!=new_hash").fetchone()[0]
        sql = """SELECT a.blake3 old_hash,b.blake3 new_hash,a.canonical_path old_path,b.canonical_path new_path,
                 a.status old_status,b.status new_status,a.volume_serial old_volume,b.volume_serial new_volume,a.file_id old_id,b.file_id new_id FROM
                 (SELECT * FROM baseline.dw_files WHERE scan_id=? AND status!='DELETED') a
                 LEFT JOIN (SELECT * FROM dw_files WHERE scan_id=? AND status!='DELETED') b ON a.canonical_path=b.canonical_path
                 UNION ALL SELECT NULL,b.blake3,NULL,b.canonical_path,NULL,b.status,NULL,b.volume_serial,NULL,b.file_id FROM dw_files b WHERE b.scan_id=? AND b.status!='DELETED'
                 AND NOT EXISTS(SELECT 1 FROM baseline.dw_files a WHERE a.scan_id=? AND a.status!='DELETED' AND a.canonical_path=b.canonical_path)"""
        for row in conn.execute(sql, (old_id, new_id, new_id, old_id)):
            if row["old_path"] is None and conn.execute("SELECT 1 FROM comparison_pairs WHERE new_path=?", (row["new_path"],)).fetchone():
                continue
            if row["new_path"] is None and conn.execute("SELECT 1 FROM comparison_pairs WHERE old_path=?", (row["old_path"],)).fetchone():
                continue
            label = ("unverified" if row["old_status"] in ("ERROR", "UNSTABLE", "UNVERIFIED") or row["new_status"] in ("ERROR", "UNSTABLE", "UNVERIFIED") else
                     "added" if row["old_path"] is None else "deleted" if row["new_path"] is None else
                     "unchanged" if row["old_hash"] == row["new_hash"] and (row["old_volume"], row["old_id"]) == (row["new_volume"], row["new_id"]) else "modified")
            counts[label] += 1
        return counts
