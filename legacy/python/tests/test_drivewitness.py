import hashlib
import json
import os
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path

import pytest
from blake3 import blake3

from dw import windows
from dw.config import Budget, Config
from dw.evidence import (Merkle, canonical_json, connect, decompress, init_db,
                         roots, verify_database, verify_legacy)
from dw.hashing import Accelerator, Cancelled, Unstable, hash_file
from dw.scanner import Scanner, database_lock


@pytest.fixture
def dataset(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    return data, tmp_path / "evidence.db"


def scan(data, db, **kwargs):
    return Scanner(db, Config(usn_enabled=False, **kwargs)).run([str(data)])


def records(db, scan_id=None):
    with connect(db, True) as conn:
        scan_id = scan_id or conn.execute("SELECT MAX(id) FROM dw_scans").fetchone()[0]
        return [dict(row) for row in conn.execute("SELECT * FROM dw_files WHERE scan_id=? ORDER BY canonical_path", (scan_id,))]


def test_known_vectors():
    assert hashlib.sha256(b"abc").hexdigest() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert blake3(b"").hexdigest() == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    assert blake3(b"abc").hexdigest() == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"


def test_baseline_dual_single_read_and_unchanged(dataset):
    data, db = dataset
    payload = b"some data" * 10000
    (data / "a").write_bytes(payload)
    first = scan(data, db)
    assert first["summary"]["bytes_read"] == len(payload)
    row = records(db)[0]
    assert row["blake3"] == blake3(payload).digest()
    assert row["sha256"] == hashlib.sha256(payload).digest()
    assert row["method"] == "FULL_DUAL_HASH"
    root1 = verify_database(db)["content_root"]
    second = scan(data, db)
    assert second["summary"]["bytes_read"] == len(payload)
    row = records(db)[0]
    assert row["method"] == "FULL_BLAKE3"
    assert row["sha256_provenance"] == "CARRIED_FORWARD"
    assert row["sha256_origin_scan"] == 1
    assert row["status"] == "UNCHANGED"
    assert verify_database(db)["content_root"] == root1


@pytest.mark.parametrize("restore_time", [False, True])
def test_same_size_one_byte_change(dataset, restore_time):
    data, db = dataset
    path = data / "a"
    path.write_bytes(b"abc")
    scan(data, db)
    stat = path.stat()
    path.write_bytes(b"abd")
    if restore_time:
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    result = scan(data, db)
    row = records(db)[0]
    assert row["status"] == "MODIFIED"
    assert row["method"] == "BLAKE3_CHANGED_SHA256"
    assert row["sha256"] == hashlib.sha256(b"abd").digest()
    assert row["sha256_origin_scan"] == 2
    assert result["summary"]["bytes_read"] == 6


def test_added_deleted_and_new_file_single_read(dataset):
    data, db = dataset
    (data / "old").write_bytes(b"old")
    scan(data, db)
    (data / "old").unlink()
    (data / "new").write_bytes(b"new")
    result = scan(data, db)
    assert result["summary"]["added"] == result["summary"]["deleted"] == 1
    assert result["summary"]["bytes_read"] == 3
    assert {r["status"] for r in records(db)} == {"ADDED", "DELETED"}


@pytest.mark.parametrize("directory", [False, True])
def test_rename(dataset, directory):
    data, db = dataset
    if directory:
        folder = data / "old"
        folder.mkdir()
        (folder / "a").write_bytes(b"abc")
        before, after = folder, data / "new"
    else:
        before, after = data / "old", data / "new"
        before.write_bytes(b"abc")
    scan(data, db)
    before.rename(after)
    result = scan(data, db)
    assert result["summary"]["renamed"] == 1
    assert records(db)[0]["status"] == "RENAMED"
    assert records(db)[0]["file_id"] == records(db, 1)[0]["file_id"]


def test_hardlink_explicit_identity(dataset):
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    os.link(data / "a", data / "b")
    scan(data, db)
    a, b = records(db)
    assert a["file_id"] == b["file_id"]
    assert a["hardlink_count"] == b["hardlink_count"] == 2
    assert a["blake3"] == b["blake3"]


def test_zero_byte_unicode_and_long_path(dataset):
    data, db = dataset
    (data / "证据-été-🙂").write_bytes(b"")
    deep = data
    for _ in range(6):
        deep = deep / ("directory" * 5)
        os.mkdir(windows.long_path(str(deep)))
    with open(windows.long_path(str(deep / "file")), "wb") as stream:
        stream.write(b"abc")
    result = scan(data, db)
    assert result["summary"]["processed"] == 2
    assert result["summary"]["errors"] == 0
    assert {r["size"] for r in records(db)} == {0, 3}


def test_junction_not_followed(dataset):
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    if os.name == "nt":
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(data / "loop"), str(data)], capture_output=True)
        if result.returncode:
            pytest.skip("Junction creation unavailable")
    else:
        os.symlink(data, data / "loop", target_is_directory=True)
    result = scan(data, db)
    assert result["summary"]["processed"] == 1
    with connect(db, True) as conn:
        assert conn.execute("SELECT COUNT(*) FROM dw_events WHERE category='REPARSE_POINT'").fetchone()[0] == 1


@pytest.mark.parametrize("exc,category", [(PermissionError(13, "denied"), "ACCESS_DENIED"),
                                        (FileNotFoundError(2, "gone"), "FILE_DISAPPEARED")])
def test_file_errors_do_not_abort(dataset, monkeypatch, exc, category):
    data, db = dataset
    (data / "bad").write_bytes(b"x")
    (data / "good").write_bytes(b"abc")
    original = hash_file
    def fake(path, *args):
        if Path(path).name == "bad":
            raise exc
        return original(path, *args)
    monkeypatch.setattr("dw.scanner.hash_file", fake)
    result = scan(data, db)
    assert result["status"] == "COMPLETED"
    assert result["summary"]["errors"] == 1
    assert any(r["error_code"] == category for r in records(db))


def test_modified_during_hash_retry(dataset, monkeypatch):
    data, db = dataset
    path = data / "a"
    path.write_bytes(b"x" * 131072)
    from dw import hashing
    real = hashing.blake3
    class Mutator:
        def __init__(self, **kwargs):
            self.hasher = real(**kwargs)
        def update(self, chunk):
            self.hasher.update(chunk)
            with open(path, "ab") as stream:
                stream.write(b"x")
        def digest(self):
            return self.hasher.digest()
    # One chunk per attempt avoids creating an endlessly growing stream.
    class OnceMutator(Mutator):
        mutated = False
        def update(self, chunk):
            self.hasher.update(chunk)
            if not self.mutated:
                with open(path, "ab") as stream:
                    stream.write(b"x")
                self.mutated = True
    monkeypatch.setattr(hashing, "blake3", OnceMutator)
    result = scan(data, db, chunk_bytes=65536)
    assert result["summary"]["unstable"] == 1
    row = records(db)[0]
    assert row["status"] == "UNSTABLE"
    assert row["blake3"] is row["sha256"] is None


def test_large_file_read_once_and_worker_cap(dataset):
    data, db = dataset
    with open(data / "large", "wb") as stream:
        stream.truncate(65 * 1024 * 1024)
    result = scan(data, db, performance=100, mode="forensic")
    assert result["summary"]["bytes_read"] == 65 * 1024 * 1024
    assert result["summary"]["unstable"] == 0
    assert Budget(Config(performance=100, workers=32, blake3_threads=32)).get()["workers"] <= 32


def test_cancellation_retains_partial_and_no_manifest(dataset):
    data, db = dataset
    for i in range(100):
        (data / str(i)).write_bytes(b"x" * 10000)
    scanner = Scanner(db, Config(usn_enabled=False, db_batch_rows=1, ui_progress_interval=0.01))
    def progress(info):
        if info["processed"] >= 3:
            scanner.cancel.set()
    scanner.on_progress = progress
    result = scanner.run([str(data)])
    assert result["status"] == "CANCELLED"
    assert len(records(db)) > 0
    assert not Path(str(db) + ".manifest.json").exists()
    assert not verify_database(db)["valid"]


def test_interrupt_and_recovery(dataset):
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    with database_lock(db):
        conn = init_db(db)
        conn.execute("INSERT INTO dw_scans(schema_version,status) VALUES (2,'RUNNING')")
        conn.commit()
        conn.close()
    scan(data, db)
    with connect(db, True) as conn:
        assert conn.execute("SELECT status FROM dw_scans WHERE id=1").fetchone()[0] == "INTERRUPTED"


def test_database_failure_not_completed(dataset, monkeypatch):
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    def fail(*args):
        raise sqlite3.DatabaseError("Injected writer failure")
    monkeypatch.setattr(Scanner, "flush_rows", fail)
    with pytest.raises(sqlite3.DatabaseError):
        scan(data, db)
    with connect(db, True) as conn:
        assert conn.execute("SELECT status FROM dw_scans").fetchone()[0] == "FAILED"


def test_second_writer_rejected(tmp_path):
    db = tmp_path / "x.db"
    with database_lock(db):
        with pytest.raises(ValueError):
            with database_lock(db):
                pass


def test_anonymization_is_keyed_deterministic_and_redacted(dataset):
    data, db = dataset
    (data / "sensitive-name.txt").write_bytes(b"abc")
    key = os.urandom(32)
    first = Scanner(db, Config(usn_enabled=False)).run([str(data)], anonymize=[str(data)], anonymization_key=key)
    second = Scanner(db, Config(usn_enabled=False)).run([str(data)], anonymize=[str(data)], anonymization_key=key)
    assert records(db)[0]["canonical_path"] == records(db, 1)[0]["canonical_path"]
    assert decompress(records(db)[0]["original_path"]).startswith("hmac-sha256:")
    assert records(db)[0]["status"] == "UNCHANGED"
    raw = Path(db).read_bytes() + Path(str(db) + ".manifest.json").read_bytes()
    assert b"sensitive-name" not in raw
    assert str(data).encode() not in raw


def test_merkle_determinism_and_odd_leaf_definition():
    leaves = [canonical_json({"path": str(i), "sha": "ab"}) for i in range(7)]
    root = Merkle()
    for value in leaves:
        root.add(value)
    nodes = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    while len(nodes) > 1:
        nodes = [hashlib.sha256(b"\x01" + nodes[i] + nodes[i + 1]).digest() if i + 1 < len(nodes) else nodes[i]
                 for i in range(0, len(nodes), 2)]
    assert root.root() == nodes[0]
    other = Merkle()
    for value in leaves:
        other.add(value)
    assert other.root() == root.root()
    changed = Merkle()
    for value in leaves[:-1] + [b"changed"]:
        changed.add(value)
    assert changed.root() != root.root()


def test_database_tampering_detected(dataset):
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    scan(data, db)
    assert verify_database(db)["valid"]
    with connect(db) as conn:
        conn.execute("UPDATE dw_files SET blake3=?", (b"x" * 32,))
    assert not verify_database(db)["valid"]


def test_manifest_signature_and_trusted_key(dataset, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    key = Ed25519PrivateKey.generate()
    private_path = tmp_path / "key.pem"
    private_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.BestAvailableEncryption(b"secret")))
    Scanner(db, Config(usn_enabled=False)).run([str(data)], signing_key=private_path, signing_password=b"secret")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert verify_database(db, public)["valid"]
    assert not verify_database(db, os.urandom(32))["valid"]
    assert b"BEGIN ENCRYPTED PRIVATE KEY" not in Path(db).read_bytes()


def test_legacy_sha1_migration_preserves_records(dataset):
    data, db = dataset
    path = data / "a"
    path.write_bytes(b"abc")
    compressed = zlib.compress(str(path).encode())
    with connect(db) as conn:
        conn.execute("CREATE TABLE files(id INTEGER PRIMARY KEY,original_path BLOB,sha1 TEXT)")
        conn.execute("INSERT INTO files VALUES (1,?,?)", (compressed, hashlib.sha1(b"abc").hexdigest()))
        assert verify_legacy(conn)["valid"]
    assert verify_database(db)["legacy"]
    scan(data, db)
    with connect(db, True) as conn:
        assert conn.execute("SELECT original_path FROM files").fetchone()[0] == compressed
        assert conn.execute("SELECT sha1 FROM files").fetchone()[0] == hashlib.sha1(b"abc").hexdigest()


def test_gpu_failed_selftest_and_runtime_fallback():
    class Bad:
        name, version = "bad", "0"
        def digest(self, data):
            return b"0" * 32
    accelerator = Accelerator(Bad())
    assert not accelerator.eligible
    assert accelerator.digest(b"abc") == blake3(b"abc").digest()
    class FailsLater:
        name, version = "late", "0"
        failing = False
        def digest(self, data):
            if self.failing:
                raise RuntimeError("driver reset")
            return blake3(data).digest()
    backend = FailsLater()
    accelerator = Accelerator(backend)
    assert accelerator.eligible
    backend.failing = True
    assert accelerator.digest(b"abc") == blake3(b"abc").digest()
    assert not accelerator.eligible


def journal_value(next_usn=20, jid="1", first=0):
    return {"volume": "C:\\", "serial": "a", "journal_id": jid, "first_usn": first,
            "next_usn": next_usn, "lowest_valid_usn": first, "filesystem": "NTFS"}


@pytest.mark.parametrize("current,valid,reason", [(journal_value(), True, "Continuous"),
      (journal_value(jid="2"), False, "Journal ID changed"), (journal_value(first=15), False, "Journal records rolled off"),
      (journal_value(next_usn=5), False, "Journal moved backwards")])
def test_usn_continuity(current, valid, reason):
    assert windows.continuity(journal_value(next_usn=10), current) == (valid, reason)


@pytest.mark.parametrize("invalid", [False, True])
def test_usn_quick_and_invalid_fallback(dataset, monkeypatch, invalid):
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    value = journal_value(next_usn=10)
    monkeypatch.setattr(windows, "journal", lambda path: dict(value))
    monkeypatch.setattr(windows, "journal_changes", lambda old, new: iter([]))
    monkeypatch.setattr(windows, "file_usn", lambda path: 5)
    Scanner(db, Config(mode="quick")).run([str(data)])
    value["next_usn"] = 20
    if invalid:
        value["journal_id"] = "2"
    result = Scanner(db, Config(mode="quick")).run([str(data)])
    row = records(db)[0]
    assert row["method"] == ("FULL_BLAKE3" if invalid else "USN_INCREMENTAL")
    assert result["summary"]["bytes_read"] == (3 if invalid else 0)


def test_usn_change_after_snapshot_forces_hash(dataset, monkeypatch):
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    value = journal_value(next_usn=10)
    monkeypatch.setattr(windows, "journal", lambda path: dict(value))
    monkeypatch.setattr(windows, "journal_changes", lambda old, new: iter([]))
    monkeypatch.setattr(windows, "file_usn", lambda path: 20)
    Scanner(db, Config(mode="quick")).run([str(data)])
    value["next_usn"] = 20
    Scanner(db, Config(mode="quick")).run([str(data)])
    assert records(db)[0]["method"] == "FULL_BLAKE3"


def test_non_ntfs_falls_back(dataset, monkeypatch):
    data, db = dataset
    (data / "a").write_bytes(b"abc")
    def unavailable(path):
        raise OSError("Not NTFS")
    monkeypatch.setattr(windows, "journal", unavailable)
    Scanner(db, Config(mode="quick")).run([str(data)])
    assert records(db)[0]["method"] == "FULL_DUAL_HASH"


def test_usn_malformed_and_v2_parser():
    name = "a".encode("utf-16le")
    raw = bytearray(64)
    struct.pack_into("<IHHQQqqIIIIHH", raw, 0, 64, 2, 0, 123, 9, 42, 0, 1, 0, 0, 0, len(name), 60)
    raw[60:62] = name
    result = list(windows.parse_records(struct.pack("<q", 50) + raw))
    assert result[0]["file_id"] == f"{123:032x}"
    assert result[0]["usn"] == 42
    with pytest.raises(ValueError):
        list(windows.parse_records(b"short"))
    raw[0:4] = struct.pack("<I", 500)
    with pytest.raises(ValueError):
        list(windows.parse_records(struct.pack("<q", 50) + raw))


def test_bounded_million_item_source_simulation(dataset, monkeypatch):
    data, db = dataset
    path = data / "a"
    path.write_bytes(b"abc")
    scanner = Scanner(db, Config(usn_enabled=False, performance=100, ui_progress_interval=0.01))
    generated = 0
    peak_queue = 0
    def producer(roots, excludes, includes, ignored, done):
        nonlocal generated, peak_queue
        try:
            for i in range(1_000_000):
                scanner.put(("file", str(data / f"file-{i}"), path.stat()))
                generated += 1
                peak_queue = max(peak_queue, scanner.work.qsize())
        except Cancelled:
            pass
        finally:
            done.set()
    def progress(info):
        if info["processed"] >= 100:
            scanner.cancel.set()
    monkeypatch.setattr(scanner, "enumerate", producer)
    scanner.on_progress = progress
    result = scanner.run([str(data)])
    assert result["status"] == "CANCELLED"
    assert peak_queue <= 128
    assert generated < 2000


def test_live_budget_changes_pause_cancel(dataset, monkeypatch):
    data, db = dataset
    for i in range(20):
        (data / str(i)).write_bytes(b"x" * 65536)
    scanner = Scanner(db, Config(usn_enabled=False))
    scanner.paused.set()
    result = []
    worker = threading.Thread(target=lambda: result.append(scanner.run([str(data)])))
    worker.start()
    time.sleep(0.1)
    assert scanner.stats.data["processed"] == 0
    scanner.budget.set(100)
    assert scanner.budget.get()["level"] == 100
    scanner.budget.set(0)
    scanner.cancel.set()
    worker.join(5)
    assert not worker.is_alive()
    assert result[0]["status"] == "CANCELLED"


def test_cli_aliases_and_invalid_performance():
    from dw.cli import aliases, parser
    assert aliases(["--scan", "C:", "D:", "--db", "a.db"]) == ["scan", "C:", "D:", "--db", "a.db"]
    assert aliases(["--list"]) == ["list"]
    with pytest.raises(ValueError):
        Config(performance=101).validate()
