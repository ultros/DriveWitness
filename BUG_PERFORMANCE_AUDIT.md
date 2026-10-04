# DriveWitness 3.1.1 bug, performance and completion audit

October 4, 2026 · Windows 11 x64 · DriveWitness by Jesse Lee Shelley

This audit resumes the interrupted modernization and checks the design and all 61 sections of the brief. It fixes evidence-review defects, fills missing review/state workflows, and measures the large-database case. The functional modernization is shipped. The brief is **not 100% verified**: physical mixed-DPI transitions, end-to-end installation, whole-volume performance, and the deferred capabilities below remain outside the validated result.

The application remains native .NET 10 WinForms. The existing scanner, Windows identity/USN services, CPU hash engine, deterministic DW-MERKLE-V1 roots and version 2 evidence format are preserved. Historical evidence is opened read-only. AllianceWatch's adapted Free-Use No-Resale license and attribution remain in place.

The subsequent 3.1.2 release adds Novus Mercatura, a DBA of BioThreat Corporation, as publisher and prepares Store EULA/privacy materials. It preserves the evidence engine and this audit's completion limits. See [STORE_DISTRIBUTION.md](STORE_DISTRIBUTION.md) for that release's checks and outstanding Store submission steps.

## Bugs fixed

| Defect | Corrected behavior and validation |
|---|---|
| Hard-link additions could be called renames; ambiguous identity matching could conceal missing paths | SQL pairs exact paths, then unique unmatched identities. Hard-link additions/removals remain additions/deletions; ambiguous moves receive no invented pairing. Native hard-link regressions pass. |
| Previous-version lookup could select a different hard-link alias | The latest prior scan prefers the same path when available. Regression passes. |
| Unreviewed plus a review set could include records outside the set | Membership and review status are independent conditions, including absent sidecars. Search/export regressions pass. |
| Full dual rehash could miss a differing SHA-256 when BLAKE3 matched | Both historical digests are checked. Regression passes. |
| CLI live verification with `--scan-id` could use the latest baseline | Scope retrieval and comparison use the selected completed scan. End-to-end CLI regression passes. |
| Review sidecars within scan scope could be collected as evidence | Collection and live inventory exclude their own review database/WAL/SHM. Regression verifies unchanged roots. |
| Descending export ordering differed from the table at ties | Export scan/path tie breaks follow the grid direction. Regression passes. |
| Junction aliases could expose the source database as an export target | Existing target identities are checked against evidence/support files before replacement. Native junction regression passes. |
| Database switching could leave stale rows/inspector/results | Cancellation and generation/database guards discard obsolete results. GUI checks exercise rapid switching, invalid input and recovery. |
| Context-menu review actions could discard an unsaved note/set | The action preserves the current inspector draft while changing the requested review fields. A GUI regression exercises the save and checks the sidecar. |
| Saved verification events stayed absent from the current Timeline | The selected observation's history refreshes immediately after saving. Events display chronologically; malformed event JSON does not prevent version history. |
| Long root checks/comparisons lacked cancellation; overlapping work could disable Cancel | SQLite interruption/per-record checks cover comparisons and roots. Cancel remains enabled during operations. Cancelled CLI work returns 130. |
| Explicit workers bypassed Quiet; batching ignored the live slider | Worker settings are processor-constrained caps; future commits use the live batch target within the configured maximum. Quiet/Maximum regressions pass. |
| The minimum-size inspector could clip despite a size-only acceptance check | Percent column sizing constrains the viewport; acceptance measures visible intersections. Minimum-size/scaled screenshots were inspected. |
| Configuration discovery could change settings after a scan started; failed-scan close could throw again | Start/settings await discovery, invalid configuration falls back visibly, and close retains partial work without repeating an already presented exception. |

## Completion against every brief section

“Implemented” describes available behavior, not validation on every hardware/environment combination. Layout differences and unavailable evidence fields are explicit.

| Section | Result |
|---|---|
| 1 Branding | Original shield/drive vector, independently rendered 16/24/32/48/64/128/256/512 PNGs, multi-resolution ICO, executable/window/About/shortcut branding. |
| 2 Design | Compact dark graphite/blue native theme; optional light theme deferred. |
| 3 Typography | Segoe UI; monospace for digests/identifiers. |
| 4 Shell | Permanent compact navigation, selected page, version/status footer. |
| 5 Top bar | Page and persistent scan status/Pause; disk/GPU utilization unavailable; errors open filtered evidence. |
| 6 Startup | Render before asynchronous bounded hardware/volume/capability discovery. |
| 7 Overview | Real changes/errors/scans/volume baselines/last saved verification; exact root scopes; health on demand. |
| 8 New Scan | Drive/folder selection, three modes, calculated budget, Start/Advanced; native implementation of the supplied direction. |
| 9 Slider | Live scheduling/worker/queue/pacing/large-file/batch control; native pool cap changes require restart. |
| 10 Active Scan | Real counters/rates/process CPU/queues/memory, one graph, 4 Hz refresh; disk/GPU utilization and reliable ETA deferred. |
| 11 Explorer | Standalone three-pane review and `--explore` entry point. |
| 12 Header | Name, asynchronous observation count/size, search/actions; scan catalog count capped at 500. |
| 13 Tree | Scan/status/provenance/built-in/named views, including latest saved hash mismatch. File filters use Advanced; full health is in Reports. |
| 14 Table | Default columns and native sort/resize/reorder/hide/pin/copy/persistence. Optional MAC/attributes/volume/first/last/hash-origin fields included. Per-file USN, independent record ID and previous-scan column not supplied; scan/path identifies an observation. |
| 15 Table performance | Virtual 256-record keyset windows, SQL filters/sorts, async work/cancellation. |
| 16 Search | Universal path/name/extension/hash/legacy SHA-1/identity/scan and advanced size/date/prefix filters. Arbitrary substrings scan SQLite; indexed sorts/hash lookup avoid that cost. |
| 17 Inspector | Seven tabs, full digests/metadata/provenance. Exact historical per-digest backend/calculation time cannot be recovered where unrecorded; observation time and SHA origin scan are shown. |
| 18 Timeline | Chronological observations, MAC times, path/hash/status changes, first/last scan and saved verification events; latest 100 events for the selected observation. |
| 19 Versions | Bounded pageable scan/date/path/size/hashes/status/method history. |
| 20 Version comparison | Field/old/new differences; baseline survives paging. |
| 21 Context actions | Open/compare/copy/investigate/filesystem/review/export groups; BLAKE3/SHA actions use existing validated verification/dual-hash paths. SHA rehash calculates both in one read. |
| 22 Live disk | Stable live reads, precise difference/missing/unstable/error results, optional new events; no exhaustive live-volume search for moved files. |
| 23 Same hash | BLAKE3/SHA exact/prefix stored-observation searches. |
| 24 Reviews | Sidecar notes/flags/reviewed/set/analyst/timestamps; set open/rename/remove administration; original roots untouched. |
| 25 Scan History | Search/sort/persisted columns/details/compare/export/verify/report/copy/reveal. Confirmed removal hides local metadata and is reversible; evidence is retained. Latest 500 entries. |
| 26 Scan comparison | Completed matching scopes, SQL status summary; Open comparison records uses the shared virtual Explorer/inspector rather than duplicating a table below the summary. |
| 27 Health | Path/size/schema/count/WAL/last completed/manifests/signatures; distinct cancellable SQLite structure and cryptographic checks; unavailable verification is labeled honestly. |
| 28 Export | Streaming CSV/JSON/JSONL/HTML and manifests, snapshot reads, provenance/selection metadata and atomic replacement. |
| 29 Palette | Ctrl+K navigation/open/search/check/benchmark/capability/settings. |
| 30 Shortcuts | Ctrl+O/F/K/C/Shift+C and F5; Enter/Escape retain native table/dialog behavior, with no separate inspector-collapse shortcut. |
| 31 Safety | Action kinds; no live-file deletion. |
| 32 Status | Textual statuses with restrained accents, readable without color. |
| 33 Responsiveness | Heavy queries/hashing/discovery/benchmark/export/checks off the event thread; bounded signals/windows. |
| 34 Query service | Shared read-only DatabaseQueryService plus separate ReviewStore. |
| 35 Architecture | Existing scanner/hash/writer/Windows/USN/integrity/benchmark services, separate Explorer; shell pages are a MainForm partial. No framework rewrite. |
| 36 Indexes | Six measured evidence indexes retained; sidecar-only indexes added. No evidence migration on Explorer open. |
| 37 Large review | Ten-million-row GUI and twenty-million-observation comparison fixture measured; bounded sampled memory; broad queries remain slow/cancellable. |
| 38 Performance | CPU physical/logical/RAM/storage/filesystem/GPU/backend, custom caps, cached benchmark and Apply recommendation. Queue depth follows the budget rather than an independent override. |
| 39 GPU | Async detection, explicit Auto/Off/Force CPU fallback. Optional acceleration deferred. |
| 40 Threading | File readers and shared native large-file pool scheduled separately; existing oversubscription safeguards retained. |
| 41 Live resources | Future scheduling adjusts safely, including worker caps/batches. Automatic disk saturation feedback deferred until reliable telemetry exists. |
| 42 Hashing | Existing simultaneous dual baseline read and explicit carried/changed SHA provenance preserved. |
| 43 Modes | Quick/Verify/Forensic behavior/durability preserved; CPU is the forensic hash authority. |
| 44 USN | Volume/journal/checkpoint continuity and fallback preserved; no journal creation. Existing tests retained; privileged whole-volume workflow not rerun in this audit. |
| 45 Identity | Volume serial/FILE_ID_128; conservative hard-link comparison and same-path history correction. |
| 46 Unstable | Pre/post checks, bounded retries, events/counters preserved. |
| 47 Merkle | DW-MERKLE-V1 canonicalization/roots/interoperability preserved; cancellation added. EVIDENCE_FORMAT.md documents encoding. |
| 48 Manifests | Export/signature checks, honest unsigned/trusted-key scope, full scan details dialogs. No configured external trusted timestamp client. |
| 49 Reports | Scan/change/error/unstable/root/review-set/comparison, HTML/structured formats; optional PDF deferred. |
| 50 Settings | Collection/resource/database/signing/anonymization controls in Advanced and restore defaults. Full ten-category settings editor deferred; dark appearance fixed. |
| 51 State | Bounds/DPI, last/recent DB, columns, named filters, hidden catalog, mode/budget; no persisted confirmation bypasses. |
| 52 DPI | Per-monitor awareness/restoration/constraints; minimum window and simulated 100/125/150/200% control scales pass. **Physical mixed-DPI/Windows-scaling transitions unverified.** |
| 53 Accessibility | Native keyboard/focus, labels/tooltips and text statuses; no formal screen-reader certification. |
| 54 Empty states | Useful no-baseline/database/matches explanations/actions. |
| 55 Errors | Stored event and per-file inspection, filtered navigation, visible malformed-input failures. |
| 56 CLI | Existing commands/aliases preserved; shared review commands expanded with dates/provenance/mismatch/manifest checks. Rotated diagnostic logging remains; separate `--log-level` selector not implemented. |
| 57 Capabilities | Shared host/backend/GPU/volume/USN/signing/timestamp report with unavailable support identified. |
| 58 Parity | Shared collection/query/live comparison/integrity/export services. |
| 59 Acceptance | 120 tests plus packaged GUI and large synthetic profiling pass, subject to the explicit physical/platform limits. |
| 60 Phases | Prior commits retained; audit correctness, GUI/distribution and report evidence are separate commits. |
| 61 Report | Architecture/files/schema/index/threading/hardware/tests/screenshots and before/after/large-data measurements here and in the historical report. |

## Measurements

Host: AMD Ryzen 9 7900X, 12 physical/24 logical processors, approximately 63.1 GiB reported RAM, Windows 11 build 26220. Detected GPUs: Radeon RX 7900 XT and integrated AMD Radeon graphics. CPU BLAKE3/.NET SHA-256 are available; no acceleration is claimed. Hardware probing remains asynchronous; existing Windows RAM/VRAM reporting limits apply.

The query fixture uses random synthetic digests, unique identities, two identical completed scans and production indexes. It is not a cryptographically valid collection. One million rows per scan yields two million total observations; ten million per scan yields twenty million. Five runs per query include connection/projection work; these are local cached measurements.

| Query | 1 million per scan | 10 million per scan | Returned at 10 million |
|---|---:|---:|---:|
| First window | 2.30 ms | 2.11 ms | 256 |
| Deep keyset window | 2.08 ms | 2.12 ms | 256 |
| Changed status | 11.68 ms | 10.38 ms | 256 |
| Indexed size sort | 2.14 ms | 1.90 ms | 256 |
| Indexed modified sort | 2.02 ms | 1.94 ms | 256 |
| Indexed odd hash prefix | 1.02 ms | 1.09 ms | 11 |
| Universal substring near end | 1.044 s | 10.819 s | 1 |
| Comparison first window | 2.614 s | 28.113 s | 256 |
| Full comparison summary | 2.961 s | 27.474 s | 10 million unchanged |

The twenty-million-observation DB is **12,896,391,168 bytes (12.01 GiB)**. Creating the initial ten-million indexed rows took 596.86 s; the final size includes both scans. Exporting 100,000 changed records took 3.278 s. A long SQL search interrupted in 28.56 ms, including a 10 ms cancellation delay. Profiler working set was **66.97 MiB**, managed heap 0.575 MiB. Page allocation over five queries stayed approximately 1.2–1.5 MiB. These are snapshots/allocation observations, not guarantees of peak RAM for every query shape.

A real GUI opened the first **ten-million-observation / 5.94 GiB** DB while the profiler appended the second scan. It became usable in **107.33 ms**, held **256 rows**, cancelled a long query in **7.71 ms**, and had a maximum 20 ms timer gap of **60.71 ms**; working set was **82.80 MiB**. This used an earlier audit build before final layout/count-header additions; the final package is separately validated on a real hashed acceptance fixture. The synthetic roots are not represented as verified. Raw results/screenshots are retained.

| GUI launch / scan heartbeat | 3.0 original package | 3.1 original package | 3.1.1 package |
|---|---:|---:|---:|
| Window shown | 135.3 ms | 208.9 ms | 203.6 ms |
| Maximum scan timer gap | 47.0 ms | 31.8 ms | 177.8 ms |

These are single launches, not statistical startup comparisons. Other audit launches varied about 185–234 ms, with timer gaps about 34–351 ms. No “never freezes” or startup speedup claim follows from one sample. The package completed a real 1,000-file scan with live resource changes, then reviewed 2,000 observations and exactly three changed/added/deleted records. Explorer opened in 33.23 ms; working set after scan/review/layout checks was 138.86 MiB. State persistence, native full-digest copying, preserved review drafts, database-switch recovery and visible-layout checks passed.

Scanner sample: **5,000 files × 4 KiB**, five alternating separate-process 3.1.0/3.1.1 published x64 CLI runs, identical config, performance 100 and USN disabled. Median engine time was **0.8052 s (6,210 files/s)** before and **0.7699 s (6,494 files/s)** after, 4.4% lower within substantial spread (old 0.746–0.949 s; new 0.663–0.822 s). **No material speedup is claimed.** The historical 3.0→3.1 sample showed about 19.7% slower collection with review indexes; that cost is retained.

Measured bottlenecks: large substring scans/scan joins are **database-query-bound**; small-file collection is dominated by **metadata/identity service time**. Parallel service timings overlap, so they are not wall-time percentages. Random-hash indexes impose substantial fixture creation work. No uncached whole-drive, disk-saturation, GPU-transfer or trusted-timestamp claim is made.

## Validation, architecture and distribution

- Locked restore/Release build: zero warnings/errors. **120 tests passed, zero failed/skipped**: 84 existing core cases and 36 Explorer/CLI cases, including 16 added regressions.
- Coverage retains crash/partial recovery, Unicode/legacy compatibility, USN continuity/fallback, GPU validation/fallback, instability, root/signature interoperability, keyset ties, streaming exports, cancellation, reviews and CLI integration.
- Final self-contained Windows 11 x64 GUI acceptance passes live collection/budget, virtual pages/changes, clipboard, saved state, rapid DB switching/invalid input recovery, minimum window and simulated scales.
- Installer/uninstaller PowerShell syntax and packaged `Install.ps1 -WhatIf` pass. **Actual installation/uninstallation was not performed.** Current-user scripts provide Start Menu shortcuts, reject running installed processes/reparse targets, and preserve external settings/evidence. Uninstall refuses databases, unknown or modified files inside the application folder. Portable use remains supported; no MSI/code-signing certificate is included.
- Evidence schema stays version 2; no new evidence indexes in this audit. Sidecar indexes `annotation_sets(review_set)` and `verification_history(scan_id,path,id)` support set/event lookup. Reviews stay outside original roots; collection excludes its own sidecar family.
- Changes span query/integrity/live comparison/operations/options/review/scanner/CLI, GUI Explorer/shell/orchestration/state/theme/entry point/manifest, version metadata, regression tests and profile/GUI/publish/install scripts. No new runtime dependency or GUI framework replacement. Production GUI handlers call services; acceptance fixtures are isolated.

```powershell
.\scripts\build.ps1
.\scripts\publish.ps1 -SkipTests
.\scripts\test-gui.ps1 -Report artifacts\audit-gui-packaged.json
dotnet run --project scripts/Profile -c Release -- 1000000 artifacts\audit-million.json
# Ten million needs substantial temporary disk space and can take many minutes.
dotnet run --project scripts/Profile -c Release -- 10000000 artifacts\audit-ten-million.json
.\scripts\test-gui.ps1 -Database C:\Evidence\large.db -Report artifacts\large-gui.json
```

Raw reports/screenshots: [docs/audit](docs/audit). Reproduce the scanner sample by passing `1000`, output JSON, old CLI and new CLI paths to Profile. Cleanup is restricted to its own checked temporary directory. Historical architecture/index and before/after evidence remain in [MODERNIZATION_REPORT.md](MODERNIZATION_REPORT.md) and [CSHARP_PERFORMANCE_REPORT.md](CSHARP_PERFORMANCE_REPORT.md).

Primary 3.1.1 screens use a real hashed fixture: [New Scan](docs/audit/new-scan.png), [Active Scan](docs/audit/active-scan.png), [Overview](docs/audit/overview.png), [Explorer](docs/audit/database-explorer.png), [Changes](docs/audit/changes.png), [History](docs/audit/scan-history.png), [Compare](docs/audit/compare.png), [Reports](docs/audit/reports.png), [Performance](docs/audit/performance.png), [Settings](docs/audit/settings.png), [minimum window](docs/audit/layout-minimum.png). The [huge-database screenshot](docs/audit/audit-gui-large.png) uses the synthetic fixture.

Remaining limits: native tab/scrollbar styling, physical mixed-DPI/screen-reader validation, full-text substring indexing, automatic disk feedback, exhaustive moved-file discovery, historical data never collected, configured trusted timestamps, optional GPU/light/PDF features, and installation on a clean physical machine. These are recorded explicitly rather than presented as completed validation.

Copyright (c) 2026 Jesse Lee Shelley. All Rights Reserved. [LinkedIn](https://linkedin.com/in/jesse-shelley) · [Project](https://github.com/ultros/DriveWitness) · [License](LICENSE)
