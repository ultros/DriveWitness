import os
import sys
import uuid
import argparse
import hashlib
import sqlite3
from datetime import datetime, timezone
import requests
import time

# Windows-specific imports for drive metadata collection
if os.name == 'nt':
    import ctypes
    import string
    import win32api
    import win32file
    import pywintypes

# Compute SHA1 hash of a file's contents
def get_sha1(file_path):
    sha = hashlib.sha1()
    try:
        start_time = time.time()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
                # Warn if hashing takes too long
                if time.time() - start_time > 30:
                    print(f"Warning: hashing {file_path} is taking over 30 seconds")
        return sha.hexdigest()
    except Exception:
        return "ERROR"

# Generate anonymized filename using UUID or SHA1 of original name
def anonymize_filename(original_filename, method="uuid"):
    ext = os.path.splitext(original_filename)[1]
    if method == "uuid":
        fake_base = str(uuid.uuid4())
    elif method == "hash":
        fake_base = hashlib.sha1(original_filename.encode()).hexdigest()
    else:
        raise ValueError("Invalid method")
    return f"{fake_base}{ext}"

# Convert epoch timestamp to ISO format with UTC timezone
def format_time(epoch_time):
    try:
        return datetime.fromtimestamp(epoch_time, tz=timezone.utc).isoformat()
    except Exception:
        return None

# Fetch current UTC time from an external API
def get_network_time():
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get("https://worldtimeapi.org/api/ip", headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json().get("utc_datetime")
    except Exception:
        return None

# Generate a consistent machine-specific identifier using environment info
def get_machine_id():
    return hashlib.sha256((
        os.getenv('COMPUTERNAME', '') +
        os.getenv('PROCESSOR_IDENTIFIER', '') +
        os.getenv('SystemRoot', '')
    ).encode()).hexdigest()

# Create the SQLite database schema
def init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            index_num INTEGER,
            original_path BLOB,
            anonymized_name TEXT,
            sha1 TEXT,
            size INTEGER,
            created_utc BLOB,
            modified_utc BLOB,
            accessed_utc BLOB,
            scan_time BLOB
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            scan_time_local TEXT,
            scan_time_network TEXT,
            machine_id TEXT
        )
    ''')
    conn.commit()
    return conn

# Insert the scan start time and machine ID into the database
def log_scan_time(conn):
    c = conn.cursor()
    local_time = datetime.now(timezone.utc).isoformat()
    network_time = get_network_time()
    c.execute('''
        INSERT INTO scans (scan_time_local, scan_time_network, machine_id)
        VALUES (?, ?, ?)
    ''', (local_time, network_time, get_machine_id()))
    conn.commit()
    return local_time

# Scan files on the given drive path and store their metadata
def index_drive(drive_path, conn, anonymize=False, method="uuid", scan_time=None):
    import zlib

    def compress_string(text):
        return zlib.compress(text.encode('utf-8'))

    c = conn.cursor()
    file_count = 0
    index_num = 0

    for root, dirs, files in os.walk(drive_path):
        print(f"Scanning folder: {root}")
        for filename in files:
            try:
                full_path = os.path.join(root, filename)
                stat = os.stat(full_path)
                hash_val = get_sha1(full_path)
                anon_name = anonymize_filename(filename, method) if anonymize else filename
                index_num += 1
                c.execute('''
                    INSERT INTO files (index_num, original_path, anonymized_name, sha1, size,
                                       created_utc, modified_utc, accessed_utc, scan_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (index_num, compress_string(full_path), anon_name, hash_val, stat.st_size,
                      compress_string(format_time(stat.st_ctime)), compress_string(format_time(stat.st_mtime)),
                      compress_string(format_time(stat.st_atime)), compress_string(scan_time)))
                file_count += 1
                if file_count % 10000 == 0:
                    conn.commit()
                    conn.execute("VACUUM")
            except Exception as e:
                print(f"Error with {full_path}: {e}")

    conn.commit()
    conn.execute("VACUUM")

# Convert a byte count into a human-readable format
def human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

# Print out a list of detected drives with details
def print_drives(drives):
    print("Available Drives:\n")
    for d in drives:
        print(f"[{d['path']}] Label: {d['label']} | FS: {d['fs_type']} | Serial: {d['serial']} | Size: {human_size(d['total'])} | Free: {human_size(d['free'])}")

if __name__ == "__main__":
    # Command-line argument parsing
    parser = argparse.ArgumentParser(description="DriveWitness: Transparent drive indexer")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--scan", nargs="+")
    parser.add_argument("--anonymize")

    # Build unique filename using timestamp and machine info
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    machine_id = get_machine_id()
    temp_name = f"drive_witness_{timestamp}_{machine_id[:8]}"
    db_hash = hashlib.sha1((temp_name + machine_id).encode()).hexdigest()
    parser.add_argument("--db", default=f"{temp_name}_{db_hash}.db")

    args = parser.parse_args()

    # If --list, show available drives and exit
    if args.list:
        drives = []
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drive = f"{letter}:\\"
                try:
                    volume_info = win32api.GetVolumeInformation(drive)
                    _, total_bytes, free_bytes = win32file.GetDiskFreeSpaceEx(drive)
                    drives.append({'path': drive, 'label': volume_info[0],
                                   'fs_type': volume_info[4], 'serial': hex(volume_info[1]),
                                   'total': total_bytes, 'free': free_bytes})
                except pywintypes.error:
                    pass
            bitmask >>= 1
        print_drives(drives)
        sys.exit(0)

    # Require --scan if not listing
    if not args.scan:
        print("Specify drive(s) with --scan")
        sys.exit(1)

    # Initialize DB and begin scan
    conn = init_db(args.db)
    scan_time = log_scan_time(conn)

    for drive in args.scan:
        is_anon = args.anonymize and os.path.abspath(args.anonymize).lower().startswith(os.path.abspath(drive).lower())
        print(f"[→] Scanning {drive} {'(ANONYMIZED)' if is_anon else ''}")
        index_drive(drive, conn, anonymize=is_anon, scan_time=scan_time)

    conn.close()
