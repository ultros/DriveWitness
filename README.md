# DriveWitness

🔪 **DriveWitness** isn’t stealth. It’s surgical exposure. In a world where digital evidence can be conjured into existence faster than logs can record it — injected into your drive by rogue admins, poisoned USBs, or remote scripts — DriveWitness turns your machine into an incorruptible forensic baseline. It scans every file, timestamps it against local and network clocks, and logs the cryptographic fingerprint of your entire file system. **You’ve already printed the autopsy.** Deploy before the frame job, and their story collapses like a lung shot in an interrogation room.

## Features
- Enumerates all available drives on Windows
- Full SHA1 file hashing
- Timestamp tracking (Created, Modified, Accessed)
- Optional filename anonymization
- Dual time logging: local system + internet time authority
- SQLite database for audit-proof storage
- Machine-specific ID recorded with each scan
- Periodic disk writes (every 10000 files) to protect scan integrity

## Requirements
- Python 3.10+
- Windows 10/11
- Admin privileges to access protected files and drives

## Installation
pip install -r requirements.txt

### 1. List Available Drives

```bash
python drivewitness.py --list
```

### 2. Scan Drive(s)

```bash
python drivewitness.py --scan C: D:
```

### 3. Scan with Filename Anonymization (on selected drive only)

```bash
python drivewitness.py --scan C: D: --anonymize D:
```

### 4. Specify Custom Output Filename

```bash
python drivewitness.py --scan E: --db forensic_output_01.db
```

## Output

- **SQLite Database:** `drive_witness_YYYYMMDD_HHMMSS_<machineID>_<hash>.db`

## Accessing Compressed Fields

The database stores the `original_path` and all timestamp columns
(`created_utc`, `modified_utc`, `accessed_utc`, `scan_time`) as zlib
compressed blobs. To retrieve them you must decompress the value and
decode it back to UTF-8 text.

```python
import sqlite3
import zlib

conn = sqlite3.connect('drive_witness_YYYYMMDD_HHMMSS.db')
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

for row in cursor.execute('SELECT original_path, created_utc FROM files LIMIT 5'):
    path = zlib.decompress(row['original_path']).decode('utf-8')
    created = zlib.decompress(row['created_utc']).decode('utf-8')
    print(path, created)
```

Use the same approach for `modified_utc`, `accessed_utc` and any other
compressed fields.

## Legal Notice

This tool does not modify any files. It reads metadata and contents for hash purposes only. Ensure you are complying with all local laws before scanning drives you do not own or control.

---

*For those who live under the boot of suspicion: your machine now testifies truth.*



