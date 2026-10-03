"""Format existing measurements without running or changing a scan."""
import json
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
profile = json.loads((repo / 'CSHARP_PERFORMANCE_REPORT.json').read_text())
gui = json.loads((repo / 'CSHARP_GUI_REPORT.json').read_text())
results = profile['results']
labels = {'original_sha1': 'Original Python, SHA-1 only', 'python_serial': 'Modern Python, one file worker', 'python_adaptive': 'Modern Python, adaptive workers', 'csharp_serial': 'C#, one file worker', 'csharp_adaptive': 'C#, adaptive workers'}
table = '\n'.join(f"| {labels[k]} | {v['median_seconds']:.3f} | {v.get('median_engine_seconds', 0):.3f} |" for k, v in results.items())
after = results['csharp_adaptive']
service = profile['csharp_subsystem_service_percent']
percent = 100 * (1 - after['median_seconds'] / results['python_adaptive']['median_seconds'])
concurrency = 100 * (1 - after['median_seconds'] / results['csharp_serial']['median_seconds'])
document = f'''# Windows 11 C# validation and performance

## Before/after profile

Measured locally on Windows 11 build 26220, 24 logical/12 physical CPUs, approximately 63 GiB RAM, and a detected NVMe NTFS volume. Dataset: 2,000 × 4 KiB files plus four × 16 MiB files, **75,300,864 bytes**. Three repetitions per strategy, mostly warm filesystem cache. Maximum performance, no USN optimization. The original SHA-1 loop provides weaker guarantees.

| Implementation | Median seconds | C# engine-only seconds |
|---|---:|---:|
{table}

Python timings exclude module imports. C# process timings include startup/JIT, JSON output, and up to 10 ms observer polling granularity; engine timings exclude process startup. Reverse interoperability checks occur after timed C# processes. Zero in the engine column means that separate measurement was unavailable for Python. Timing variation and cache effects limit conclusions.

C# adaptive collection used **{percent:.1f}% less elapsed time** than modern Python adaptive collection in this sample. Adaptive C# used {concurrency:.1f}% less time than C# with one file worker. The original SHA-1 collector's speed is not an equivalent correctness/performance target.

The measured limiting subsystem is **metadata/identity checking**, about {service['metadata']:.1f}% of aggregate instrumented service time. It includes mandatory native identity/time observations and resolved-handle path checks. SQLite inserts plus commits represent {service['db_insert'] + service.get('db_commit', 0):.1f}%; Merkle construction {service['merkle']:.1f}%; content reads {service['read']:.1f}%. Service times overlap across workers and are not fractions of wall-clock time. Enumeration wall time includes queue backpressure and is excluded from these percentages. Scheduling/JIT are not separately instrumented.

Observed adaptive C# peak process working set in the reported repetition: {after['summary']['peak_working_set_bytes'] / 1048576:.1f} MiB. Queue/task/batch sizes are structurally bounded independently of file count. The 2,000-file queue test validates those ceilings; this is not an empirical million-file or whole-drive memory test.

The bounded benchmark reads at most 16 existing sample files totaling 64 MiB, tests sequential reads, serial/parallel BLAKE3, SHA-256, dual hashing, worker counts, and 5,000 temporary SQLite rows. It includes OS cache effects and recommends settings for review. No huge benchmark files are written, and no GPU accelerator is advertised.

## Published GUI acceptance

- First window shown: **{gui['startup_to_shown_ms']:.1f} ms** from managed program startup; excludes OS process loading before `Main`.
- Maximum-performance sample: 1,000 × 64 KiB, with both digests established in one read and zero file errors.
- UI timer requested 20 ms; largest observed gap **{gui['maximum_heartbeat_gap_ms']:.1f} ms**, {gui['heartbeat_count']} heartbeats.
- Native -10/-1/+1/+10 buttons were exercised and their values checked.
- Background collection completed; form rendering and event-loop responsiveness passed.

The application-owned acceptance form is hidden and captured using WinForms `DrawToBitmap`; no desktop screenshot is required. Measurements include sample creation and scan activity in the heartbeat interval. This is one run, not a percentile or broad DPI/display matrix.

![Native C# WinForms interface](docs/winforms.png)

## Verification

Release build: zero warnings/errors, nullable analysis and warnings-as-errors enabled. **84 C# tests pass**: known digests, single-read baselines, carry-forward/recalculation, timestamp-restored changes, replacement/deletion/renames, hard links, junction loops and ancestor redirection, Unicode/long paths, large/empty files, cancellation/pause/throttle, bounded queues, killed-process recovery, deterministic/empty/odd Merkle reduction, legacy SHA-1 migration, signing/trusted keys/timestamp failure, GPU fallback, and controlled USN continuity/race/failure cases.

The retained Python suite also passes 49 tests after relocation. Python validates newly generated C# roots/manifests and signed manifests; C# validates fixed Python UTF-8/UTF-16 inventory roots and encrypted-key signatures. Published GUI/CLI runs passed, and runtime configuration embeds .NET 10.0.12; CLI live verification also passed with installed-runtime lookup disabled.

Actual raw journal access was denied in this unelevated session; full-hash fallback and its event were observed. Elevated full-volume journal collection and ARM64 execution remain untested. No enabled GPU hasher, trusted timestamp service, ADS/VSS collection, or guarantee of zero bottlenecks is claimed.

Machine-readable evidence: [profile](CSHARP_PERFORMANCE_REPORT.json), [GUI acceptance](CSHARP_GUI_REPORT.json). Reproduce with `scripts/port_performance_report.py` (development Python only), `scripts/build.ps1`, `scripts/publish.ps1`, and `scripts/test-gui.ps1`.
'''
(repo / 'CSHARP_PERFORMANCE_REPORT.md').write_text(document, encoding='utf-8')
print(repo / 'CSHARP_PERFORMANCE_REPORT.md')
