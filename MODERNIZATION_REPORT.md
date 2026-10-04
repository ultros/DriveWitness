# DriveWitness 3.1 modernization report

October 4, 2026 · Windows 11 x64 · DriveWitness by Jesse Lee Shelley

This is the historical 3.1.0 report. The subsequent [3.1.1 bug, performance and completion audit](BUG_PERFORMANCE_AUDIT.md) fixes review/verification defects, adds saved-view/set/installer workflows, and supplies ten-million-row GUI and twenty-million-observation comparison measurements. Consult that audit for current completion status; the original measurements below are retained unchanged.

The application now has a compact dark shell, dedicated collection and evidence review pages, shared SQL query services, non-destructive analyst reviews, current-disk comparison and streamed exports. The existing native C# scanner and CLI remain in place. This report distinguishes measured results from remaining work.

## Architecture and files

- `MainForm.cs`: existing asynchronous scanner orchestration, shared budget and controls, startup discovery, settings and GUI acceptance harness.
- `MainForm.Shell.cs`: navigation, Overview, New Scan, Active Scan, History, Compare, Reports, Performance, Benchmark, Capabilities, Settings, command palette and workspace restoration.
- `DatabaseExplorer.cs`: three-pane evidence view, asynchronous queries, cancellation, bounded virtual table, inspector, timeline, version comparison, analyst review and categorized context actions.
- `Theme.cs`, `WorkspaceState.cs`, `WindowsFileActions.cs`: shared typography/colors/controls, persisted layouts/preferences, and native Properties dialogs.
- `DatabaseQueryService.cs`: read-only SQLite queries for search, scans, history, events, comparisons, integrity checks and streaming exports. GUI and new CLI commands call this layer.
- `ReviewStore.cs`: separate review storage, with annotations and append-only verification events.
- `LiveFileComparison.cs`: stable current-file reads through the existing hasher, SHA-256 carry/recalculation provenance and precise historical/current differences.
- `EvidenceDatabase.cs`: six targeted indexes. `Integrity.cs`: selected-scan verification and export overwrite protection. `Scanner.cs` and `NativeWindows.cs`: release version metadata updated; collection/hash/USN algorithms preserved.
- `Program.cs` in the app accepts `--explore evidence.db`; the CLI adds evidence query/export/history/health/versions/current-file/comparison commands and `--db` aliases while retaining previous commands.
- `Assets/`, `scripts/generate-icons.ps1`: original shield-and-drive SVG, independently rendered PNG sizes 16, 24, 32, 48, 64, 128, 256 and 512, plus multi-resolution Windows ICO. The executable, window/taskbar and main shell use the mark.
- `tests/DriveWitness.Tests/ExplorerTests.cs`: 20 additional cases. `scripts/Profile/`: reproducible million-record query and before/after scanner profiler.
- `LICENSE`, `NOTICE`, `Directory.Build.props`, `scripts/publish.ps1`, README and screenshots: licensing, attribution and distribution metadata.

The GUI framework remains **.NET 10 WinForms**. No new GUI dependency or framework replacement was introduced. Heavy operations run on worker tasks and update controls only after returning to the event thread. Startup draws before hardware probing. Progress and charts update at 4 Hz, retaining at most 100 samples.

## Database changes and evidence semantics

The evidence schema stays at **version 2**. Existing tables and record encoding remain compatible, including Python-era evidence and compressed legacy SHA-1 paths. Explorer connections use SQLite read-only mode, query-only enforcement, a bounded page cache and disk-backed temporary sorting. Opening older databases does not silently create indexes or migrate them.

The collector adds these indexes when it opens a database:

| Index | Key | Purpose |
|---|---|---|
| `dw_history_path` | canonical_path, scan_id | Exact-path observation history / global path order |
| `dw_history_identity` | volume_serial, file_id, scan_id | Renames, other paths and versions |
| `dw_blake3` | blake3, scan_id | Same-content and prefix lookup |
| `dw_sha256` | sha256, scan_id | SHA-256 lookup |
| `dw_size` | scan_id, COALESCE(size,-1), canonical_path | Per-scan size sort |
| `dw_modified` | scan_id, COALESCE(modified_ns,-1), canonical_path | Per-scan modified-time sort |

No existing indexes were removed. Insertion overhead is measured below; filename/extension substring indexes were not created without a useful B-tree access pattern.

Reviews live in `<evidence>.review.db`, using `annotations` and `verification_events`, outside the signed evidence inventory. Notes include scan/path, flag/review state, set, creation/modification time and analyst identity. Review sets are names on annotations rather than separate set-management tables. Saving a live verification appends a new review event; historical observations are never updated by that operation. Keep review sidecars and any active WAL with the evidence they accompany.

SQLite integrity and cryptographic roots are independent checks. A test deliberately tampers with an evidence row: SQLite still reports `ok`, while root verification fails. Comparisons require completed scans with matching scopes. SQL derives content, rename and metadata statuses. Inferred missing rows retain the actual old observation ID and display `COMPARISON_INFERRED`; incomplete coverage produces `UNVERIFIED` instead of inferred deletion.

The deterministic **DW-MERKLE-V1** content/metadata/scan root implementation, canonicalization, signature interoperability and original USN continuity checks are preserved. Quick falls back to full verification when continuity fails. CPU BLAKE3 remains the validated authority. Legacy SHA-1 is explicitly labeled and is never presented as a modern Merkle baseline.

## Query architecture and large database measurements

The table is virtual, with **256 records per window**, keyset Next/Previous navigation and SQL-side sorting/filtering. Search is debounced by 300 ms. SQLite interrupt supports cancellation; obsolete results are discarded. Inspector versions are also bounded/pageable. The scan catalog shows the latest 500 entries. Exports use one read transaction and stream rather than building a complete result list.

Measured fixture: **1,000,000 observations**, **605.0 MiB** database, created in **20.54 s**. The fixture is synthetic and is not a real forensic collection. Each query ran five times; the table shows medians, including connection/projection work.

| Query | Median | Rows returned |
|---|---:|---:|
| first window | 1.93 ms | 256 |
| deep keyset window | 1.87 ms | 256 |
| changed status | 9.60 ms | 256 |
| indexed size sort | 2.18 ms | 256 |
| indexed modified sort | 1.91 ms | 256 |
| indexed odd hash prefix | 0.97 ms | 3 |
| universal substring near end | 1099.78 ms | 1 |

A deliberately long, unmatched substring query was interrupted in **26.37 ms**. Exporting **10,000 changed records** to JSONL took **0.436 s**. The profiler working set was **71.3 MiB**, with a managed heap of **0.70 MiB**. Five page queries increased measured managed allocation by about 1.2 MiB, rather than by the database's record count. These measurements establish bounded pages and the tested million-row case; they do not establish performance for ten million rows or every schema/filter combination.

Universal substring searches scan records and are **database-query-bound**. Use scan/status/size/hash filters when appropriate. Hash prefixes use indexed binary ranges, including odd-length hexadecimal prefixes. Older evidence without the new indexes remains readable but can sort/search more slowly. Full-text filename search is not shipped.

## Startup, GUI responsiveness and scanning

| Measurement | 3.0 packaged GUI | 3.1 packaged GUI |
|---|---:|---:|
| Window shown | 135.3 ms | 208.9 ms |
| Maximum heartbeat gap (20 ms timer) | 47.0 ms | 31.8 ms |

These are single launch observations, not a statistically demonstrated startup speedup. Both windows appear before deep probing. The 3.1 explorer opened the two-scan / 2,000-observation GUI fixture in **43.5 ms**, retained **256 rows**, and correctly showed three modified/added/deleted observations. GUI working set after the scripted review was **134.7 MiB**. The scripted test verifies live budget changes reach the running engine, collection completes without errors, native table copying preserves full digests, and the event loop remains responsive.

The separate scanner comparison used **5,000 files × 4 KiB**, five alternating old/new passes, performance 100, identical explicit configuration, USN disabled, and the same source fixture. Median engine time was **0.673 s before** and **0.806 s after**, approximately **19.7% longer**. Effective rates were **7,430 files/s before** and **6,206 files/s after**. The additional review indexes increase insert/commit work; no scanner throughput optimization is claimed. Aggregate metadata/identity service time dominates this sample; timings overlap across workers and must not be treated as wall-time percentages. Filesystem cache and small-file metadata costs limit interpretation. These are not whole-drive or uncached NVMe throughput results.

The existing resource scheduler separates file concurrency from native large-file hashing, reserves the pool for large files, safely drains work when the slider drops, bounds queues, and applies Quiet pacing. The tested host used up to 16 file workers and an 8-thread native pool cap. The live slider controls future scheduling and serial/parallel large-file use; explicit commit settings and the native pool cap remain configuration settings, with pool changes requiring restart. Disk saturation feedback is not implemented because disk utilization is not reliably collected.

## Hardware and GPU

Measured host: **AMD Ryzen 9 7900X 12-Core Processor**, 12 physical cores / 24 logical processors, **63.1 GiB** CIM-reported RAM. Windows build: `Microsoft Windows NT 10.0.26220.0`. GPU discovery returned **AMD Radeon RX 7900 XT, AMD Radeon(TM) Graphics**. CIM AdapterRAM is limited to 32 bits and is explicitly marked as potentially underreporting VRAM.

**No GPU hashing accelerator is shipped or enabled.** Auto/Off/Force safely retain CPU hashing. Existing accelerator validation and fallback tests pass; there is no acceleration result to claim. Hardware probing runs after render and can time out without preventing collection. Signing remains Ed25519; trusted timestamping is not configured. Disk/GPU utilization and reliable ETA remain unavailable.

## Screenshots

These images use a real hashed acceptance fixture, not simulated production statistics.

- [New Scan](docs/new-scan.png)
- [Active Scan](docs/active-scan.png)
- [Overview](docs/overview.png)
- [Database Explorer](docs/database-explorer.png)
- [Changed records](docs/changes.png)
- [Scan History](docs/scan-history.png)
- [Compare](docs/compare.png)
- [Reports](docs/reports.png)
- [Performance](docs/performance.png)
- [Settings](docs/settings.png)

## Validation and remaining work

- Locked dependency restore, Release solution build: passed, zero warnings/errors.
- **104 automated tests passed** (84 existing + 20 explorer/CLI cases), including crash recovery, legacy compatibility, root/signature interoperability, bounded pagination with ties in both directions, cancellation, non-destructive review/live comparison, rename/deletion comparison, streaming exports and source-overwrite protection.
- Packaged x64 GUI acceptance: passed, including live budget changes and bounded explorer/filter results.
- Million-observation SQL profile and streamed export: passed. Raw reports are under `docs/modernization/` and the profile can be rerun with `dotnet run --project scripts/Profile -c Release -- 1000000 artifacts/explorer-performance.json`.
- Icon generation and the self-contained x64 distribution build passed. The icon assets are original vectors rendered independently at each output size.

Remaining UX/platform work: physical validation at 125%, 150% and 200% scaling and mixed-DPI monitors; only **96 DPI** was exercised here. The window constrains itself to the active monitor and page layouts scroll at reduced heights. Inspector tabs and native scrollbars retain some Windows rendering. Light theme and PDF reports are not shipped. A separate installer/Start Menu deployment is not included; the distribution is portable. Persistent named filter management and separate review-set administration are not provided beyond built-in views, the last filter and annotation set names. Exact historical per-digest backend/time data cannot be recovered when old evidence never recorded it. File history follows recorded identities/paths; a missing historical path is not an exhaustive live volume search for a moved object. Ten-million-row GUI/compare testing, full-text search and additional disk/GPU telemetry remain future work.

The measured index cost is a material tradeoff. This release improves review capability and preserves evidence behavior; it does not claim every requested advanced feature or a faster scanner.

## License

DriveWitness uses AllianceWatch's version 2.0 **Free-Use No-Resale** terms, adapted to this project, with persistent creator credit and both links in the GUI, About/License, CLI help and exported reports. Earlier valid grants remain effective; the previous GPL text is preserved. Third-party components retain their own terms.

Copyright (c) 2026 Jesse Lee Shelley. All Rights Reserved. [LinkedIn](https://linkedin.com/in/jesse-shelley) · [Project](https://github.com/ultros/DriveWitness).
