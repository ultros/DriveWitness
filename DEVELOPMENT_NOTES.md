# C# conversion and audit notes

The original repository at `aaaf944` was a sequential SHA-1 Python CLI: pywin32 discovery, synchronous network time, `os.walk`, compressed text fields, unversioned tables, 10,000-file commits, and repeated VACUUM. It had no GUI, scheduler, stable-read checks, manifests, or crash status.

The prior modernization introduced Tkinter, dual hashing, bounded workers, USN/file identities, additive schema 2, and deterministic integrity verification. That implementation and its detailed audit/test reports remain in `legacy/python`. The subsequent user request to convert to C# supersedes the earlier Python implementation constraint: version 3 uses native WinForms and a shared C# engine.

## Architecture

| Component | Responsibility |
|---|---|
| `src/DriveWitness.App` | WinForms, throttle/step controls, background discovery/collection, 4 Hz snapshot polling, 100-point graph, verification/comparison/export, GUI acceptance harness |
| `src/DriveWitness.Cli` | Automation workflows, validated arguments/configuration, Ctrl+C cancellation |
| `Options.cs` | Versioned settings, storage-aware budget, pause/cancel, canonical scope and HMAC policy |
| `NativeWindows.cs`, `JournalAccess.cs` | Windows 11 workstation guard, read-only handles, file IDs/ChangeTime, storage, bounded USN V2/V3 responses, hardware discovery |
| `Hashing.cs` | Rust BLAKE3, .NET SHA-256, shared dual-hash reads, stable-read retries, fail-closed accelerator interface |
| `Scanner.cs` | Streaming enumeration, bounded hash tasks, sole SQLite writer, incremental eligibility, provenance, missing-path classification, finalization |
| `EvidenceDatabase.cs`, `Models.cs` | Schema 2, prepared inserts, compression, WAL/commit policy, process lock, interrupted recovery |
| `CanonicalJson.cs`, `Integrity.cs` | Python-compatible canonicalization, streaming Merkle roots, encrypted Ed25519 PEM support, timestamps, stored/legacy verification |
| `Operations.cs` | Read-only comparison, SQLite backup migration, bounded existing-data benchmarks |

The GUI renders before probes. Workers never mutate controls. The UI polls one latest immutable progress snapshot, avoiding per-file UI messages. Traversal, validation, hashing, SQLite work, journal/network access, and benchmarks run in the background. Closing during collection cancels and waits for partial evidence persistence.

## Concurrency and durability

A dedicated enumeration thread holds depth-first iterators and a bounded queue. The coordinator retains at most 32 small-file tasks and bounded insert batches; it owns every database write. Adaptive queue depth is at most 128. Condition notifications/completion signals avoid per-file polling delays. Lowering the bar drains existing work safely.

Small/medium files use serial BLAKE3 per task. A >=64 MiB file drains other tasks and exclusively reserves the native pool. Rayon is capped before use, default at most eight processors. The live bar selects that pool or serial large-file hashing; changing the cap requires restart. Adaptive storage caps are HDD/remote two, SSD eight, NVMe sixteen, constrained by CPU/32. Explicit worker settings override adaptive storage defaults. Quiet adds cancellable chunk/dispatch pacing. The application raises .NET minimum worker capacity to avoid starvation from its waiting coordinator.

Baseline dual hashes share one read. Verify carries SHA-256 only when BLAKE3 matches; changed files can need a second read. Stability checks include native ChangeTime, identity, size, birth/modification times, and post-read path identity. Unstable files receive no established digest. Hard-link reuse requires reliable per-file USN stability; initial paths may be independently read to avoid an extra metadata handle for every ordinary baseline path.

Prepared batches commit every 2,000 rows or two seconds by default, including during long file hashes. Quick/Verify use NORMAL; Forensic FULL. No recurring VACUUM occurs. A blocked completion checkpoint warns to retain WAL rather than invalidating committed evidence. Cancellation retains partial rows; fatal database failure rolls back the active batch. A killed process leaves RUNNING, recovered as INTERRUPTED under the collector lock.

## Compatibility and tests

Schema 2 and compressed fields are retained; SHA-1 tables remain unchanged. Migration backs up into a new database. C# canonicalization reproduces Python ASCII escaping, Unicode-key ordering, exact integers, and shortest-round-trip floating formatting, including exponent thresholds and negative zero. UTF-16 databases explicitly order paths by UTF-8. xUnit checks fixed Python roots/encrypted signatures; the profiling harness checks Python verification of newly generated C# roots and signed manifests.

Quick stores the journal **start** checkpoint. Serial/ID/retention checks and current per-file tokens guard carry-forward. Changed IDs use disk-backed SQLite storage. Malformed/unavailable journals fall back to full hashing. Completion rechecks continuity: if a journal was reset, became unavailable, or rolled off while content was carried forward, that pass is retained as FAILED and a fresh full Verify pass runs automatically under the same live budget/control. Actual journal access was denied in this unelevated session; fallback was observed. Controlled tests cover valid/dirty/post-checkpoint/recreated/unavailable/malformed cases and content mutation during completion-time journal reset/rolloff. Elevated whole-volume acceptance remains untested.

Missing-path handling uses a disk-backed anti-join and bounded keyset batches. Enumeration gaps suppress confident deletion and carry missing entries as UNVERIFIED. Comparisons pair disappeared/new identity paths one-to-one, including rename plus content change. Reparse targets are recorded as exclusions and never followed.

Testing found and fixed an empty-Merkle C# hex-escape error, malformed/completion-time USN fallback, URI attachment flags in read-only comparison, floating-point/Unicode-key canonicalization, startup timing initialization, and clipped throttle labels. Native hash vectors run before collection; the large-file test independently checks serial Python reference digests against parallel C# hashing. Resolved-path buffers now start small and grow only for long paths, avoiding maximum-path allocations per file. External signing keys are validated before scanning. HMAC/signing key files are excluded; key/password contents are not persisted. Timestamp failure prevents completion and records an event.

Release uses nullable analysis and warnings as errors. The 84 engine tests include a real killed-process recovery test. Build/publish/GUI-test scripts produce reproducible reports and self-contained x64 artifacts. See `CSHARP_PERFORMANCE_REPORT.md` for measured results and startup/heartbeat acceptance.

## Limits

Metadata/identity processing dominates the measured mixed-file profile; SQLite is not its bottleneck. No zero-bottleneck or whole-drive speed guarantee is made. Benchmarks include OS cache effects and cache recommendations for review, without silently changing overrides.

There is no enabled GPU hasher, configured RFC 3161 client, VSS/ADS collector, permission bypass, disk utilization meter, or reliable ETA. Collection trusts the live filesystem and supplied prior baseline. Roots cover logical file inventory/tracked metadata, not every SQLite byte, operational event, or historical scan. External custody and pinned signer trust remain necessary.
