import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from dw.evidence import connect
from dw.scanner import Scanner
from dw.config import Config


def cli(*args):
    return subprocess.run([sys.executable, "drivewitness.py", *map(str, args)], capture_output=True, text=True, timeout=20)


def test_cli_scan_verify_live_export_compare(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "a").write_bytes(b"abc")
    baseline, newer = tmp_path / "baseline.db", tmp_path / "newer.db"
    result = cli("--scan", data, "--db", baseline, "--no-usn", "--json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "COMPLETED"
    assert cli("verify", "--db", baseline, "--json").returncode == 0
    assert cli("verify", "--db", baseline, "--live", "--json").returncode == 0
    (data / "a").write_bytes(b"abd")
    assert cli("scan", data, "--db", newer, "--no-usn", "--json").returncode == 0
    result = cli("compare", baseline, newer, "--json")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["modified"] == 1
    manifest = tmp_path / "manifest.json"
    errors = tmp_path / "errors.jsonl"
    assert cli("export", "--db", newer, "--manifest", manifest, "--errors", errors).returncode == 0
    assert json.loads(manifest.read_text())["manifest"]["scan_id"] == 1


def test_real_process_crash_preserves_committed_results_and_recovers(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    for i in range(100):
        (data / str(i)).write_bytes(b"x" * 4096)
    db = tmp_path / "evidence.db"
    code = '''
import os,sys
from dw.scanner import Scanner
from dw.config import Config
s=Scanner(sys.argv[1],Config(usn_enabled=False,db_batch_rows=1,ui_progress_interval=0.001))
def progress(info):
    if info['processed']>=10:
        os._exit(7)
s.on_progress=progress
s.run([sys.argv[2]])
'''
    result = subprocess.run([sys.executable, "-c", code, str(db), str(data)], timeout=20)
    assert result.returncode == 7
    with connect(db, True) as conn:
        assert conn.execute("SELECT status FROM dw_scans").fetchone()[0] == "RUNNING"
        assert conn.execute("SELECT COUNT(*) FROM dw_files").fetchone()[0] >= 10
    Scanner(db, Config(usn_enabled=False)).run([str(data)])
    with connect(db, True) as conn:
        assert [r[0] for r in conn.execute("SELECT status FROM dw_scans ORDER BY id")] == ["INTERRUPTED", "COMPLETED"]


def test_context_manager_closes_windows_database_handles(tmp_path):
    path = tmp_path / "a.db"
    with connect(path) as conn:
        conn.execute("CREATE TABLE test(id INTEGER)")
    path.unlink()


def test_cancel_during_merkle_does_not_publish_manifest(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "a").write_bytes(b"abc")
    db = tmp_path / "evidence.db"
    scanner = Scanner(db, Config(usn_enabled=False, ui_progress_interval=0.001))
    def progress(info):
        if info["status"] == "FINALIZING":
            scanner.cancel.set()
    scanner.on_progress = progress
    result = scanner.run([str(data)])
    assert result["status"] == "CANCELLED"
    assert not Path(str(db) + ".manifest.json").exists()
