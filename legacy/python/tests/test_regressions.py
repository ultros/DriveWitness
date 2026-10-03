import json
import os
import sqlite3
from pathlib import Path

import pytest

from dw.config import Config
from dw.evidence import connect, init_db, roots, verify_database
from dw.scanner import Scanner


def test_replacement_with_same_content_is_different_object(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    path = data / "a"
    path.write_bytes(b"abc")
    db = tmp_path / "evidence.db"
    Scanner(db, Config(usn_enabled=False)).run([str(data)])
    replacement = data / "temp"
    replacement.write_bytes(b"abc")
    os.replace(replacement, path)
    Scanner(db, Config(usn_enabled=False)).run([str(data)])
    with connect(db, True) as conn:
        row = conn.execute("SELECT * FROM dw_files WHERE scan_id=2").fetchone()
        assert row["status"] == "MODIFIED"
        assert row["first_seen_scan"] == 2


def test_deleted_metadata_is_committed(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    path = data / "a"
    path.write_bytes(b"abc")
    db = tmp_path / "evidence.db"
    Scanner(db, Config(usn_enabled=False)).run([str(data)])
    path.unlink()
    Scanner(db, Config(usn_enabled=False)).run([str(data)])
    assert verify_database(db)["valid"]
    with connect(db) as conn:
        conn.execute("UPDATE dw_files SET modified_ns=99 WHERE scan_id=2")
    assert not verify_database(db)["valid"]


def test_inaccessible_tree_never_claims_deletion(tmp_path, monkeypatch):
    from dw import scanner as module
    data = tmp_path / "data"
    data.mkdir()
    (data / "a").write_bytes(b"abc")
    db = tmp_path / "evidence.db"
    Scanner(db, Config(usn_enabled=False)).run([str(data)])
    original = module.os.scandir
    def inaccessible(path):
        if str(path).endswith("data"):
            raise PermissionError(13, "denied")
        return original(path)
    monkeypatch.setattr(module.os, "scandir", inaccessible)
    result = Scanner(db, Config(usn_enabled=False)).run([str(data)])
    assert result["summary"]["deleted"] == 0
    with connect(db, True) as conn:
        assert conn.execute("SELECT status FROM dw_files WHERE scan_id=2").fetchone()[0] == "UNVERIFIED"


def test_partial_anonymous_live_cli(tmp_path):
    from test_integration import cli
    public = tmp_path / "public"
    private = tmp_path / "private"
    public.mkdir()
    private.mkdir()
    (public / "a").write_bytes(b"abc")
    (private / "secret").write_bytes(b"xyz")
    key = tmp_path / "key.bin"
    key.write_bytes(os.urandom(32))
    db = tmp_path / "evidence.db"
    result = cli("scan", public, private, "--db", db, "--no-usn", "--anonymize", private, "--anonymization-key", key, "--json")
    assert result.returncode == 0, result.stderr
    result = cli("verify", "--db", db, "--live", "--paths", public, private, "--anonymization-key", key, "--json")
    assert result.returncode == 0, result.stderr
    with connect(db, True) as conn:
        assert conn.execute("SELECT parent_scan_id FROM dw_scans WHERE id=2").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM dw_files WHERE scan_id=2 AND status='UNCHANGED'").fetchone()[0] == 2


def test_merkle_independent_of_database_text_encoding(tmp_path):
    results = []
    for encoding in ("UTF-8", "UTF-16le"):
        path = tmp_path / (encoding + ".db")
        with connect(path) as conn:
            conn.execute(f"PRAGMA encoding='{encoding}'")
            conn.execute("CREATE TABLE legacy_marker(id INTEGER)")
        conn = init_db(path)
        conn.execute("INSERT INTO dw_scans(id,schema_version,status) VALUES (1,2,'RUNNING')")
        for name in ("Ā", "ÿ", "🙂", "a"):
            conn.execute("INSERT INTO dw_files(scan_id,canonical_path,volume_serial,file_id,size,blake3,sha256,status,method) VALUES (?,?,?,?,?,?,?,?,?)",
                         (1, "/" + name, "1", name, 3, b"b" * 32, b"s" * 32, "ADDED", "FULL_DUAL_HASH"))
        results.append(roots(conn, 1))
        conn.close()
    assert results[0] == results[1]


def test_future_schema_rejected_and_handle_closed(tmp_path):
    path = tmp_path / "future.db"
    with connect(path) as conn:
        conn.execute("PRAGMA user_version=99")
    with pytest.raises(ValueError, match="Unsupported schema"):
        init_db(path)
    with connect(path, True) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 99
    path.unlink()


def test_compare_tracks_rename_plus_content_change(tmp_path):
    from dw.scanner import compare_databases
    data = tmp_path / "data"
    data.mkdir()
    (data / "old").write_bytes(b"abc")
    old, new = tmp_path / "old.db", tmp_path / "new.db"
    Scanner(old, Config(usn_enabled=False)).run([str(data)])
    (data / "old").rename(data / "new")
    (data / "new").write_bytes(b"abd")
    Scanner(new, Config(usn_enabled=False)).run([str(data)])
    result = compare_databases(old, new)
    assert result["renamed"] == 1
    assert result["modified"] == 1
    assert result["added"] == result["deleted"] == 0


def test_corrupted_compressed_field_fails_verification_cleanly(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "a").write_bytes(b"abc")
    db = tmp_path / "evidence.db"
    Scanner(db, Config(usn_enabled=False)).run([str(data)])
    with connect(db) as conn:
        conn.execute("UPDATE dw_files SET original_path=?", (b"invalid",))
    result = verify_database(db)
    assert not result["valid"]
    assert "Malformed" in result["reason"]
