"""Additive evidence schema, canonical Merkle trees and manifest signatures."""
import base64
import hashlib
import json
import os
import sqlite3
import unicodedata
import uuid
import zlib
from datetime import datetime, timezone
from pathlib import Path

from . import SCHEMA_VERSION, __version__


def utc():
    return datetime.now(timezone.utc).isoformat()


def machine_id():
    # Hardware is provenance, not proof that the collector is uncompromised.
    import platform
    parts = [platform.node(), os.getenv("PROCESSOR_IDENTIFIER", ""), os.getenv("SystemRoot", ""), hex(uuid.getnode())]
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                parts.append(winreg.QueryValueEx(key, "MachineGuid")[0])
        except OSError:
            pass
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def canonical_path(path):
    # Preserve Unicode distinctions. Normalizing to NFC would alias distinct files.
    value = os.path.abspath(path)
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return value.replace("\\", "/")


def compress(value):
    return zlib.compress(str(value).encode("utf-8", "surrogatepass"))


def decompress(value):
    if value is None:
        return None
    return zlib.decompress(value).decode("utf-8", "surrogatepass") if isinstance(value, bytes) else value


class EvidenceConnection(sqlite3.Connection):
    def __exit__(self, *args):
        # sqlite3's default context manager ends a transaction but leaves the handle open.
        # On Windows that prevents cleanup/reopening and can retain WAL readers indefinitely.
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def connect(path, readonly=False):
    if readonly:
        conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=30, factory=EvidenceConnection)
    else:
        conn = sqlite3.connect(path, timeout=30, factory=EvidenceConnection)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(path, forensic=False):
    conn = connect(path)
    try:
        return _initialize(conn, forensic)
    except BaseException:
        conn.rollback()
        conn.close()
        raise


def _initialize(conn, forensic):
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    if current not in (0, SCHEMA_VERSION):
        raise ValueError(f"Unsupported schema version: {current}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=" + ("FULL" if forensic else "NORMAL"))
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA temp_store=FILE")
    conn.execute("PRAGMA cache_size=-16384")
    conn.executescript('''
      BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS dw_scans (
        id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL, status TEXT NOT NULL,
        parent_scan_id INTEGER, started TEXT, completed TEXT, machine_id TEXT,
        mode TEXT, scope TEXT, config TEXT, network_time_observation TEXT,
        content_root TEXT, metadata_root TEXT, scan_root TEXT, manifest TEXT, summary TEXT,
        trusted_timestamp_proof BLOB, failure TEXT);
      CREATE TABLE IF NOT EXISTS dw_volumes (
        scan_id INTEGER, path TEXT, info TEXT, journal_start TEXT, journal_end TEXT,
        continuity TEXT, PRIMARY KEY(scan_id,path));
      CREATE TABLE IF NOT EXISTS dw_files (
        scan_id INTEGER NOT NULL, canonical_path TEXT NOT NULL, original_path BLOB,
        volume_serial TEXT, file_id TEXT, size INTEGER, created_ns INTEGER,
        modified_ns INTEGER, accessed_ns INTEGER, attributes INTEGER,
        blake3 BLOB, sha256 BLOB, legacy_sha1 TEXT, method TEXT, status TEXT,
        sha256_origin_scan INTEGER, sha256_provenance TEXT, error_code TEXT, error_message TEXT,
        hardlink_count INTEGER, first_seen_scan INTEGER, last_seen_scan INTEGER,
        created_utc BLOB, modified_utc BLOB, accessed_utc BLOB, scan_time BLOB,
        PRIMARY KEY(scan_id,canonical_path), FOREIGN KEY(scan_id) REFERENCES dw_scans(id));
      CREATE INDEX IF NOT EXISTS dw_identity ON dw_files(scan_id,volume_serial,file_id);
      CREATE INDEX IF NOT EXISTS dw_status ON dw_files(scan_id,status);
      CREATE TABLE IF NOT EXISTS dw_events (
        id INTEGER PRIMARY KEY, scan_id INTEGER, time TEXT, category TEXT,
        path TEXT, error_code TEXT, message TEXT);
      CREATE TABLE IF NOT EXISTS dw_signatures (
        scan_id INTEGER PRIMARY KEY, algorithm TEXT, public_key BLOB, signature BLOB);
    ''')
    conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
    # Caller holds an exclusive OS lock on this database; no live scan is interrupted.
    conn.execute("UPDATE dw_scans SET status='INTERRUPTED', failure='Collector exited before finalization' WHERE status='RUNNING'")
    conn.commit()
    return conn


def canonical_json(data):
    return json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


class Merkle:
    """O(log N) carry stack; domain-separated nodes, odd nodes promoted unchanged."""
    def __init__(self):
        self.stack = []
        self.count = 0

    def add(self, leaf):
        value = hashlib.sha256(b"\x00" + leaf).digest()
        level = 0
        self.count += 1
        while level < len(self.stack) and self.stack[level] is not None:
            value = hashlib.sha256(b"\x01" + self.stack[level] + value).digest()
            self.stack[level] = None
            level += 1
        if level == len(self.stack):
            self.stack.append(value)
        else:
            self.stack[level] = value

    def root(self):
        value = None
        for node in self.stack:
            if node is not None:
                value = node if value is None else hashlib.sha256(b"\x01" + node + value).digest()
        return value or hashlib.sha256(b"\x02DW-MERKLE-V1").digest()


def roots(conn, scan_id, on_progress=None):
    content, metadata = Merkle(), Merkle()
    collation = "BINARY"
    if conn.execute("PRAGMA encoding").fetchone()[0] != "UTF-8":
        def utf8_compare(left, right):
            a, b = left.encode("utf-8", "surrogatepass"), right.encode("utf-8", "surrogatepass")
            return (a > b) - (a < b)
        conn.create_collation("DW_UTF8", utf8_compare)
        collation = "DW_UTF8"
    query = f"SELECT * FROM dw_files WHERE scan_id=? ORDER BY canonical_path COLLATE {collation},volume_serial,file_id"
    for index, row in enumerate(conn.execute(query, (scan_id,))):
        if on_progress and index % 512 == 0:
            on_progress()
        leaf = {"scheme": "DW-MERKLE-V1", "path": row["canonical_path"], "volume": row["volume_serial"],
                "file_id": row["file_id"], "size": row["size"], "status": row["status"],
                "blake3": row["blake3"].hex() if row["blake3"] else None,
                "sha256": row["sha256"].hex() if row["sha256"] else None,
                "error_code": row["error_code"]}
        # Change classifications belong to provenance, not inventory identity.
        if leaf["status"] in ("UNCHANGED", "ADDED", "MODIFIED", "RENAMED"):
            leaf["status"] = "PRESENT"
        if row["status"] != "DELETED":
            content.add(canonical_json(leaf))
        leaf.update({"created_ns": row["created_ns"], "modified_ns": row["modified_ns"],
                     "accessed_ns": row["accessed_ns"], "attributes": row["attributes"],
                     "verification_method": row["method"], "sha256_provenance": row["sha256_provenance"],
                     "sha256_origin_scan": row["sha256_origin_scan"], "hardlink_count": row["hardlink_count"],
                     "original_path": decompress(row["original_path"]),
                     "created_utc": decompress(row["created_utc"]), "modified_utc": decompress(row["modified_utc"]),
                     "accessed_utc": decompress(row["accessed_utc"]), "error_message": row["error_message"]})
        metadata.add(canonical_json(leaf))
    c, m = content.root(), metadata.root()
    return {"content_root": c.hex(), "metadata_root": m.hex(),
            "scan_root": hashlib.sha256(b"DRIVEWITNESS-SCAN-V1" + c + m).hexdigest()}


def sign_manifest(manifest, key_path, password=None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Manifest signing requires an Ed25519 PEM key")
    signature = key.sign(canonical_json(manifest))
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return public, signature


class TimestampProvider:
    """Integration seam: timestamp a canonical manifest SHA-256 digest.

    Implementations must validate the returned proof, trust chain and message imprint.
    No RFC 3161 provider is configured/shipped by default.
    """
    def timestamp(self, digest: bytes) -> bytes:
        raise NotImplementedError


def export_manifest(db, output, scan_id=None):
    with connect(db, True) as conn:
        row = conn.execute("SELECT id,manifest,status FROM dw_scans " +
                           ("WHERE id=?" if scan_id else "ORDER BY id DESC LIMIT 1"),
                           (scan_id,) if scan_id else ()).fetchone()
        if not row or row["status"] != "COMPLETED" or not row["manifest"]:
            raise ValueError("No completed manifest for this scan")
        signature = conn.execute("SELECT * FROM dw_signatures WHERE scan_id=?", (row["id"],)).fetchone()
        envelope = {"manifest": json.loads(row["manifest"]), "signature": None}
        if signature:
            envelope["signature"] = {"algorithm": signature["algorithm"],
                "public_key": base64.b64encode(signature["public_key"]).decode("ascii"),
                "value": base64.b64encode(signature["signature"]).decode("ascii")}
    target = Path(output)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_bytes(canonical_json(envelope) + b"\n")
    os.replace(temporary, target)
    return envelope


def verify_database(db, public_key=None):
    with connect(db, True) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "dw_scans" not in tables:
            return {"valid": False, "legacy": True, "hash_algorithm": "SHA-1", "reason": "Legacy evidence has no Merkle roots"}
        row = conn.execute("SELECT * FROM dw_scans ORDER BY id DESC LIMIT 1").fetchone()
        if not row and "files" in tables:
            return {"valid": False, "legacy": True, "hash_algorithm": "SHA-1", "reason": "Legacy evidence has no Merkle roots"}
        if not row or row["status"] != "COMPLETED":
            return {"valid": False, "reason": "Latest scan is incomplete"}
        try:
            calculated = roots(conn, row["id"])
            valid = all(row[name] == digest for name, digest in calculated.items())
            manifest = json.loads(row["manifest"])
            valid = valid and all(manifest.get(name) == digest for name, digest in calculated.items())
        except (ValueError, TypeError, AttributeError, zlib.error) as exc:
            return {"valid": False, "scan_id": row["id"], "reason": "Malformed inventory or manifest: " + str(exc)}
        signature = conn.execute("SELECT * FROM dw_signatures WHERE scan_id=?", (row["id"],)).fetchone()
        signed = False
        trusted_key = False
        if signature:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            try:
                Ed25519PublicKey.from_public_bytes(signature["public_key"]).verify(signature["signature"], canonical_json(manifest))
                signed = True
            except (InvalidSignature, ValueError):
                valid = False
            if public_key is not None:
                trusted_key = signature["public_key"] == public_key
                valid = valid and trusted_key
        elif public_key is not None:
            valid = False
        return {"valid": valid, "scan_id": row["id"], "signature_valid": signed,
                "trusted_public_key": trusted_key, "scope": "Stored inventory roots; not a live disk verification", **calculated}


def verify_legacy(conn):
    """Read old compressed rows and compare actual SHA-1, without altering evidence."""
    checked, changed, errors = 0, 0, 0
    for row in conn.execute("SELECT original_path,sha1 FROM files"):
        try:
            digest = hashlib.sha1()
            with open(decompress(row["original_path"]), "rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            checked += 1
            changed += digest.hexdigest() != row["sha1"]
        except (OSError, ValueError, zlib.error):
            errors += 1
    return {"legacy": True, "hash_algorithm": "SHA-1", "verification_strength": "legacy",
            "checked": checked, "changed": changed, "errors": errors, "valid": changed == errors == 0}
