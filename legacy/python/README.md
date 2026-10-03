# DriveWitness

DriveWitness collects a tamper-evident filesystem baseline using read-only file access, explicit verification provenance and a crash-tolerant SQLite evidence database. The graphical interface is primary; the CLI supports automation and forensic workflows.

A baseline can document what was observed during collection. It cannot guarantee correctness on an already compromised endpoint, provide a consistent live-disk snapshot, or make SQLite "audit-proof." Preserve manifests and trusted public keys outside the scanned machine.

## Features

- Windows drive discovery, directory/full-volume scanning, volume and file identities.
- Official optimized BLAKE3 plus SHA-256, established together in one content read.
- Verify mode rehashes BLAKE3 and explicitly carries unchanged SHA-256 forward.
- NTFS USN-assisted Quick verification with continuity checks and safe full-scan fallback.
- Adaptive, bounded multithreaded hashing and a live 0–100 performance bar with ±1/±10 buttons.
- Pause, cooperative cancellation, partial evidence retention and crash recovery statuses.
- Responsive Tkinter interface with background discovery, live counters and lightweight performance graphs.
- File-ID-aware rename tracking, explicit hard-link relationships and unstable-file detection.
- Deterministic content/metadata Merkle roots and optional Ed25519-signed scan manifests.
- Keyed filename/path anonymization, local UTC and optional external clock observations.
- WAL SQLite storage, batch inserts and time/row-based commits.
- GPU detection and a validated accelerator integration interface. **No GPU hashing backend ships enabled.**
- Full CLI workflows, bounded read-only benchmarks and legacy compressed SHA-1 database access.

## Requirements and installation

Windows 10/11, Python 3.10+ with Tkinter. Administrator access may be needed for journal access and protected files. DriveWitness records access failures; it does not change ACLs or enable a missing journal. Tests also support portable filesystem paths where the OS permits them.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\drivewitness.exe
```

Alternatively, `python drivewitness.py` opens the GUI using the Python environment in which dependencies are installed. This checkout's `.venv` is prepared and tested.

Select drives or add a folder, choose a database and mode, and start scanning. Using the same database and scope appends a new scan linked to its completed baseline. Adjust performance during a scan; in-flight work drains safely when the budget is lowered. Quiet deliberately limits concurrency and introduces small pacing delays. Performance is a resource budget, not an exact CPU percentage.

Settings / Advanced contains USN/network-time toggles, worker/thread overrides, a configurable large-file threshold, include/exclude globs, anonymization/signing key selection and Performance > Benchmark. Changing a mode or advanced settings applies to the next scan. The performance control remains live. Inspect errors/unstable results from the main window.

## Modes

| Mode | Content verification | SQLite durability |
|---|---|---|
| Quick | Use eligible USN carry-forward; hash dirty/new candidates; full fallback otherwise | WAL + NORMAL |
| Verify (default) | BLAKE3 across every accessible file; SHA-256 for new/different content | WAL + NORMAL |
| Forensic | Establish both hashes across accessible objects | WAL + FULL |

All new baselines calculate both digests. Completed scans create Merkle roots and a manifest in every mode. Signing occurs only when a key is configured. Hard links may reuse a same-scan verified object with a stable per-file USN; this is explicit in provenance. USN currently saves content reads while namespace enumeration still walks the selected tree.

## CLI examples

After editable installation, activate the virtual environment or use its executable directly:

```powershell
.\.venv\Scripts\Activate.ps1
drivewitness list
drivewitness capabilities --json
drivewitness scan C: D: --db evidence.db --mode verify --performance 60
drivewitness scan C:\Evidence --db evidence.db --mode quick
drivewitness scan C:\Evidence --db evidence.db --mode forensic --gpu off
drivewitness scan C:\Evidence --db evidence.db --workers 4 --blake3-threads 4 --no-usn
drivewitness verify --db evidence.db --json
drivewitness verify --db evidence.db --live --json
drivewitness benchmark C:\Evidence --json
drivewitness export --db evidence.db --manifest manifest.json --errors errors.jsonl
drivewitness compare baseline.db newer.db --json
drivewitness migrate --db old_sha1.db
drivewitness verify --db old_sha1.db --live
drivewitness scan C:\Evidence --db interrupted.db --resume
```

Original flags remain aliases:

```powershell
python drivewitness.py --list
python drivewitness.py --scan C: D: --db evidence.db
```

`verify --db` checks stored logical roots and signatures; it does not reread the drive. Add `--live` for a new content verification pass. For a legacy database, `--live` performs read-only SHA-1 comparisons without rewriting historic evidence. `--resume` starts a new pass after preserving interrupted records; it requires an existing database.

Useful scan options: `--full`, `--quiet`, `--json`, `--include PATTERN`, `--exclude PATTERN`, `--no-gpu`, `--network-time`, `--config`, `--storage`, `--log-level`, `--log-file`. Globs match absolute canonical paths using `/`; includes apply to files. Explicit values override saved defaults. `--gpu force` fails clearly because a validated GPU collector is unavailable.

### Anonymization

Create and securely retain an external key of at least 32 random bytes. Do not place it in the scanned tree. Losing the key prevents deterministic anonymous comparison. Original plaintext paths are not recoverable from modern evidence; unlike the old UUID option, this is deliberate privacy.

```powershell
python -c "import os; from pathlib import Path; Path('path-key.bin').write_bytes(os.urandom(32))"
drivewitness scan C: D: --db evidence.db --anonymize D: --anonymization-key path-key.bin
drivewitness verify --db evidence.db --live --paths C: D: --anonymization-key path-key.bin
```

For anonymized subdirectories rather than whole selected roots, also provide the original `--anonymize` subroot to live verification. Scopes and key identifiers must match for comparisons.

### Signing

Use an external Ed25519 PKCS8 PEM private key, preferably encrypted. GUI passwords are session-only; CLI encrypted-key passwords come from a named environment variable:

```powershell
drivewitness scan C:\Evidence --db evidence.db --mode forensic --sign-key signing.pem --key-password-env DW_KEY_PASSWORD
drivewitness verify --db evidence.db --public-key trusted-public-key.bin
```

The verification key is raw Ed25519 public bytes (32 bytes). An embedded public key checks signature consistency; an externally pinned key authenticates the expected signer. Unsigned roots require separate trusted custody. Do not store private keys in evidence databases.

## Evidence output and compatibility

CLI output defaults to `drive_witness_YYYYMMDD_HHMMSS_<machineID>_<random>.db`; the GUI defaults to `drive_witness.db` for repeated verification. Completed scans also export `<db>.manifest.json`. CANCELLED/FAILED/INTERRUPTED records never receive a completed-baseline manifest. Check the latest scan status and the manifest scan ID: an older manifest beside a database does not represent its latest incomplete scan.

Modern schema version 2 uses `dw_scans`, `dw_volumes`, `dw_files`, `dw_events` and `dw_signatures`. Migration adds these tables and preserves old `files`/`scans` and SHA-1 evidence. Modern paths/comparison timestamps are indexed/native; compatibility display fields remain zlib blobs. Digests are binary BLOBs.

```python
import sqlite3
import zlib

with sqlite3.connect('evidence.db') as conn:
    conn.row_factory = sqlite3.Row
    for row in conn.execute('SELECT original_path, created_utc, blake3, method FROM dw_files LIMIT 5'):
        path = zlib.decompress(row['original_path']).decode('utf-8')
        created = zlib.decompress(row['created_utc']).decode('utf-8') if row['created_utc'] else None
        digest = row['blake3'].hex() if row['blake3'] else None
        print(path, created, digest, row['method'])
```

Use the original `files` table and `sha1` text column for old records. See [EVIDENCE_FORMAT.md](EVIDENCE_FORMAT.md) for canonicalization, provenance, checkpoint and signature details.

## Testing and performance

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
python scripts\performance_report.py PERFORMANCE_REPORT.json
python scripts\gui_report.py
```

See [DEVELOPMENT_NOTES.md](DEVELOPMENT_NOTES.md) for the repository audit and architectural changes, and [PERFORMANCE_REPORT.md](PERFORMANCE_REPORT.md) for measured before/after results. The tested mixed-file workload is metadata/identity-bound; SQLite is not its bottleneck. Different storage and file distributions require their own measurements.

## Collection limits

Files are opened read-only; the OS may update access timestamps. This is a live collector without a VSS snapshot. Stability checks detect observed identity/size/timestamp changes and mark repeatedly changing files UNSTABLE, but cannot prove an adversarial endpoint did not hide mutations. Default data streams are scanned; ADS, ACL/security descriptor capture and other advanced NTFS evidence are a future phase. Reparse targets are recorded and excluded to prevent loops or silently leaving the selected tree.

HTTP clock observations are not cryptographic trusted timestamps. An integration seam accepts validated timestamp proofs over a final manifest digest, but no RFC 3161 client is configured. No experimental GPU hashes are used for evidence. Protect external manifests, public keys and collection custody. Scan only drives you are authorized to examine.
