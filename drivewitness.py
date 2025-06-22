import os
import sys
import uuid
import argparse
import hashlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import requests
import time

if os.name == 'nt':
    import ctypes
    import string
    import win32api
    import win32file
    import pywintypes

def get_sha1(file_path):
    sha = hashlib.sha1()
    try:
        start_time = time.time()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
                if time.time() - start_time > 30:
                    print(f"Warning: hashing {file_path} is taking over 30 seconds")
        return sha.hexdigest()
    except Exception:
        return "ERROR"

def anonymize_filename(original_filename, method="uuid"):
    ext = os.path.splitext(original_filename)[1]
    if method == "uuid":
        fake_base = str(uuid.uuid4())
    elif method == "hash":
        fake_base = hashlib.sha1(original_filename.encode()).hexdigest()
    else:
        raise ValueError("Invalid method")
    return f"{fake_base}{ext}"

def format_time(epoch_time):
    try:
        return datetime.fromtimestamp(epoch_time, tz=timezone.utc).isoformat()
    except Exception:
        return None

def get_network_time():
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        resp = requests.get("https://worldtimeapi.org/api/ip", headers=headers, timeout=10)
        resp.raise_for_status()
        return resp.json().get("utc_datetime")
    except Exception:
        return None

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY,
            original_path TEXT,
            anonymized_name TEXT,
            sha1 TEXT,
            size INTEGER,
            created_utc TEXT,
            modified_utc TEXT,
            accessed_utc TEXT,
            scan_time TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY,
            scan_time_local TEXT,
            scan_time_network TEXT
        )
    ''')
    conn.commit()
    return conn

def log_scan_time(conn):
    c = conn.cursor()
    local_time = datetime.now(timezone.utc).isoformat()
    network_time = get_network_time()
    c.execute('''
        INSERT INTO scans (scan_time_local, scan_time_network)
        VALUES (?, ?)
    ''', (local_time, network_time))
    conn.commit()
    return local_time

def index_drive(drive_path, conn, anonymize=False, method="uuid", scan_time=None):
    c = conn.cursor()
    file_count = 0
    for root, dirs, files in os.walk(drive_path):
        print(f"Scanning folder: {root}")
        for filename in files:
            try:
                full_path = os.path.join(root, filename)
                stat = os.stat(full_path)
                hash_val = get_sha1(full_path)
                anon_name = anonymize_filename(filename, method) if anonymize else filename
                c.execute('''
                    INSERT INTO files (original_path, anonymized_name, sha1, size,
                                       created_utc, modified_utc, accessed_utc, scan_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (full_path, anon_name, hash_val, stat.st_size,
                      format_time(stat.st_ctime), format_time(stat.st_mtime),
                      format_time(stat.st_atime), scan_time))
                file_count += 1
                if file_count % 1000 == 0:
                    conn.commit()
            except Exception as e:
                print(f"Error with {full_path}: {e}")
    conn.commit()

def human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

def print_drives(drives):
    print("Available Drives:\n")
    for d in drives:
        print(f"[{d['path']}] Label: {d['label']} | FS: {d['fs_type']} | Serial: {d['serial']} | Size: {human_size(d['total'])} | Free: {human_size(d['free'])}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DriveWitness: Transparent drive indexer")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--scan", nargs="+")
    parser.add_argument("--anonymize")
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    parser.add_argument("--db", default=f"drive_witness_{timestamp}.db")
    args = parser.parse_args()

    if args.list:
        drives = []
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                drive = f"{letter}:\\"
                try:
                    volume_info = win32api.GetVolumeInformation(drive)
                    total_bytes, free_bytes = win32file.GetDiskFreeSpaceEx(drive)[:2]
                    drives.append({'path': drive, 'label': volume_info[0],
                                   'fs_type': volume_info[4], 'serial': hex(volume_info[1]),
                                   'total': total_bytes, 'free': free_bytes})
                except pywintypes.error:
                    pass
            bitmask >>= 1
        print_drives(drives)
        sys.exit(0)

    if not args.scan:
        print("Specify drive(s) with --scan")
        sys.exit(1)

    conn = init_db(args.db)
    scan_time = log_scan_time(conn)

    for drive in args.scan:
        is_anon = args.anonymize and os.path.abspath(args.anonymize).lower().startswith(os.path.abspath(drive).lower())
        print(f"[→] Scanning {drive} {'(ANONYMIZED)' if is_anon else ''}")
        index_drive(drive, conn, anonymize=is_anon, scan_time=scan_time)

    conn.close()
    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    c.execute("SELECT original_path, sha1, size, created_utc, modified_utc, accessed_utc FROM files")
    files = c.fetchall()
    c.execute("SELECT COUNT(*), SUM(size) FROM files")
    total_files, total_size = c.fetchone()
    c.execute("SELECT scan_time_local, scan_time_network FROM scans ORDER BY id DESC LIMIT 1")
    scan_time_local, scan_time_network = c.fetchone()
    conn.close()

    html_path = "drivewitness_report.html"
    with open(html_path, "w", encoding="utf-8") as report:
        report.write("<html><head><title>DriveWitness Report</title><style>")
        report.write("body{font-family:sans-serif;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:8px;text-align:left;}th{background:#eee;}")
        report.write("</style></head><body>")
        report.write(f"<h1>DriveWitness Report</h1><p><strong>Local Scan Time:</strong> {scan_time_local}<br>")
        report.write(f"<strong>Network Time:</strong> {scan_time_network}</p><p>")
        report.write(f"<strong>Total Files:</strong> {total_files}<br><strong>Total Size:</strong> {total_size:,} bytes</p><h2>File Index</h2>")
        report.write("<table><tr><th>Path</th><th>SHA1</th><th>Size</th><th>Created</th><th>Modified</th><th>Accessed</th></tr>")
        for row in files:
            report.write("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>")
        report.write("</table></body></html>")

    print(f"[✔] Scan complete. Database: {args.db}")
    print(f"[📄] HTML report: {html_path}")
