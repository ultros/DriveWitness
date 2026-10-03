# Local validation report

Measured on Windows, Python 3.14.4, 24 logical / 12 physical processors, approximately 63 GiB RAM, and a C: volume detected as NVMe. GPU discovery reported AMD Radeon RX 7900 XT and integrated Radeon graphics. GPU hashing was unavailable and unused. This session was not elevated for C: journal access; full-verification fallback was exercised instead.

## Timing comparison

Dataset: 2,000 files of 4 KiB plus four files of 16 MiB, 2,004 files / 75,300,864 bytes total. Each run used a new database in a temporary directory. Medians of three runs, with a warm OS cache possible:

| Collector | Median elapsed |
|---|---:|
| Original sequential SHA-1 collector | 0.477 s |
| Modern dual-hash collector, one file worker | 2.275 s |
| Modern dual-hash collector, adaptive workers | 1.684 s |

Adaptive concurrency reduced modern scan elapsed time by approximately **26%** relative to the same collector with one worker. The original SHA-1 loop was faster on this workload and did substantially less evidence checking. These results do **not** claim that modernization is faster than the legacy application.

Aggregate instrumented subsystem service time was dominated by **metadata and file identity (65.81%)**, followed by reading (20.01%), SHA-256 (5.91%) and compression (6.39%). BLAKE3 accounted for 0.72%, enumeration 0.51%, Merkle generation 0.53%, SQLite insertion 0.08% and commits 0.04%. Concurrent service times overlap; these percentages are not wall-clock fractions, and scheduler/Python overhead is not separately instrumented. The measured mixed-file workload is **metadata/identity-bound**, with storage reads also material. SQLite is not its limiting resource.

The isolated 64 MiB benchmark reported cached sequential reads around 3,836 MiB/s, BLAKE3 single-thread around 5,499 MiB/s, four-thread BLAKE3 around 14,030 MiB/s, SHA-256 around 2,445 MiB/s and combined CPU hashing around 1,687 MiB/s. Its contiguous-data test was CPU-limited by dual hashing rather than representative of end-to-end small-file scanning. Those numbers may reflect RAM-backed cache and must not be treated as raw-drive throughput or a GPU speedup claim.

The GUI was constructed and entered its event loop in **0.088 s**, excluding Python process launch and Tk import. During a maximum-performance scan of 1,000 files, the largest 20 ms heartbeat gap was **26 ms**, with zero file errors/unstable outcomes. The window was withdrawn for automated testing; asynchronous hardware discovery still ran.

## Reproduce

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\performance_report.py PERFORMANCE_REPORT.json
.\.venv\Scripts\python.exe scripts\gui_report.py
drivewitness benchmark C:\some\representative\folder --no-cache --json
```

See `PERFORMANCE_REPORT.json` and `GUI_TEST_REPORT.json` for raw measurements. The benchmark examines at most 10,000 directory entries, retains at most 16 candidates and reads at most 64 MiB. SQLite benchmarks create only a bounded 5,000-row temporary database. Recommendations are cached for inspection; users can apply explicit worker overrides. Large-file threshold tuning and mmap are still open measurement work.

## Tests and qualification

The final automated suite passed **49 tests** on this Windows machine.

Automated coverage includes known digests, single-read dual hashing, unchanged/new/deleted/renamed content, same-size timestamp-restored changes, directory renames, hard links, zero-byte/Unicode/long paths, a real Windows junction cycle, controlled permission/disappearance failures, repeated mutation, a 65 MiB file, keyed redaction, deterministic/odd Merkle reduction, database tampering, pinned signatures, legacy records, GPU validation/fallback, journal continuity/rolloff/snapshot races, bounded million-item-source simulation, live throttling/pause/cancel, a real process crash and restart, CLI integration and GUI responsiveness.

The million-item test uses a lazy producer and cancels after a bounded prefix; it verifies queue bounds without creating a million real files or claiming million-file throughput. Permission and valid-journal branches use controlled fixtures. An elevated NTFS full-volume USN acceptance test and a production-scale cold-cache scan remain unmeasured. No benchmark can establish that every workload has no bottleneck.
