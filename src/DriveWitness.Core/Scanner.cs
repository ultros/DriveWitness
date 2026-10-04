using System.ComponentModel;
using System.Diagnostics;
using System.IO.Enumeration;
using System.Security.Cryptography;
using System.Text.Json;

namespace DriveWitness.Core;

public sealed record ScanRequest(string Database, PathPolicy Paths, ScanOptions Options,
    string? SigningKey = null, string? SigningPassword = null, ITimestampProvider? TimestampProvider = null, IReadOnlyList<string>? IgnoredFiles = null);

// The coordinator is the only SQLite writer. Hash tasks never receive its connection.
public sealed class Scanner(ScanRequest request, ResourceBudget? resourceBudget = null, ScanControl? scanControl = null, IJournalAccess? journalAccess = null)
{
    public ResourceBudget Budget { get; } = resourceBudget ?? new(request.Options);
    public ScanControl Control { get; } = scanControl ?? new();
    public ScanProgress? Progress => Volatile.Read(ref fallback)?.Progress ?? Volatile.Read(ref latest);
    private Scanner? fallback;
    private sealed class JournalFallbackException(string message) : IOException(message);
    private ScanProgress? latest;
    private readonly ScanCounters stats = new();
    private readonly IJournalAccess journal = journalAccess ?? new WindowsJournalAccess();
    private readonly List<FileRecord> rows = [];
    private long scanId;
    private long? parentId;
    private long lastPublish, lastCommit;
    private int written;
    private double enumerationSeconds;
    private int startedOnce;
    private sealed record Work(string Path, long Size = 0, Exception? Error = null, string? Category = null, bool Incomplete = false);
    private sealed record Pending(string Path, FileRecord? Previous, bool IdentityMatch, bool Large, string? Identity, Task<HashResult> Task);
    private sealed record VolumeState(string Root, VolumeInfo Info, JournalCheckpoint? Start, string Continuity, bool Incremental);
    private readonly List<VolumeState> volumes = [];

    private sealed class WorkQueue(ResourceBudget budget, ScanControl control) : IDisposable
    {
        private readonly Queue<Work> queue = new();
        public readonly AutoResetEvent Changed = new(false);
        public bool Done { get; private set; }
        public int Count { get { lock (queue) return queue.Count; } }
        public void Add(Work item)
        {
            lock (queue)
            {
                while (queue.Count >= budget.Snapshot().QueueDepth) { control.Token.ThrowIfCancellationRequested(); Monitor.Wait(queue, 100); }
                control.Token.ThrowIfCancellationRequested(); queue.Enqueue(item); Changed.Set();
            }
        }
        public bool Take(out Work? item)
        {
            lock (queue) { item = queue.Count > 0 ? queue.Dequeue() : null; Monitor.PulseAll(queue); return item != null; }
        }
        public void Complete() { lock (queue) { Done = true; Monitor.PulseAll(queue); Changed.Set(); } }
        public void Dispose() => Changed.Dispose();
    }

    private void Enumerate(WorkQueue queue)
    {
        var ignored = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string db = Path.GetFullPath(request.Database);
        foreach (string suffix in new[] { "", "-wal", "-shm", ".lock", ".manifest.json", ".review.db", ".review.db-wal", ".review.db-shm" }) ignored.Add(db + suffix);
        if (request.SigningKey != null) ignored.Add(Path.GetFullPath(request.SigningKey));
        foreach (string path in request.IgnoredFiles ?? []) ignored.Add(Path.GetFullPath(path));
        long enumerationStart = Stopwatch.GetTimestamp();
        try
        {
            foreach (string root in request.Paths.Roots)
            {
                var stack = new Stack<IEnumerator<FileSystemInfo>>();
                try
                {
                    void Open(string path)
                    {
                        Control.Check();
                        if ((File.GetAttributes(NativeWindows.Extended(path)) & FileAttributes.ReparsePoint) != 0)
                        { queue.Add(new(path, Category: "REPARSE_POINT", Incomplete: true)); return; }
                        stack.Push(new DirectoryInfo(NativeWindows.Extended(path)).EnumerateFileSystemInfos("*", new EnumerationOptions
                        { IgnoreInaccessible = false, AttributesToSkip = 0, RecurseSubdirectories = false, ReturnSpecialDirectories = false }).GetEnumerator());
                        Interlocked.Increment(ref stats.Directories);
                    }
                    Open(root);
                    while (stack.Count > 0)
                    {
                        Control.Check(); var iterator = stack.Peek(); FileSystemInfo entry;
                        try
                        {
                            if (!iterator.MoveNext()) { stack.Pop().Dispose(); continue; }
                            entry = iterator.Current;
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        { stack.Pop().Dispose(); queue.Add(new(root, Error: ex, Category: "ENUMERATION_ERROR", Incomplete: true)); continue; }
                        string path = PathPolicy.Canonical(entry.FullName).Replace('/', '\\');
                        if (ignored.Contains(path) || path.StartsWith(db + ".manifest.json.", StringComparison.OrdinalIgnoreCase)) continue;
                        string canonical = PathPolicy.Canonical(path);
                        if (request.Paths.Excludes.Any(pattern => FileSystemName.MatchesSimpleExpression(pattern, canonical, false))) continue;
                        try
                        {
                            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                            { queue.Add(new(path, Category: "REPARSE_POINT", Incomplete: true)); continue; }
                            if ((entry.Attributes & FileAttributes.Directory) != 0)
                            {
                                try { Open(path); }
                                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                                { queue.Add(new(path, Error: ex, Category: "ENUMERATION_ERROR", Incomplete: true)); }
                                continue;
                            }
                            if (request.Paths.Includes.Length > 0 && !request.Paths.Includes.Any(pattern => FileSystemName.MatchesSimpleExpression(pattern, canonical, false))) continue;
                            Interlocked.Increment(ref stats.Discovered);
                            queue.Add(new(path, ((FileInfo)entry).Length));
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        { queue.Add(new(path, Error: ex, Category: "ENUMERATION_ERROR", Incomplete: true)); }
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                { queue.Add(new(root, Error: ex, Category: "ENUMERATION_ERROR", Incomplete: true)); }
                finally { foreach (var iterator in stack) iterator.Dispose(); }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { try { queue.Add(new(request.Paths.Roots[0], Error: ex, Category: "ENUMERATION_ERROR", Incomplete: true)); } catch (OperationCanceledException) { } }
        finally { enumerationSeconds = Stopwatch.GetElapsedTime(enumerationStart).TotalSeconds; queue.Complete(); }
    }

    public ScanResult Run()
    {
        if (Interlocked.Exchange(ref startedOnce, 1) != 0) throw new InvalidOperationException("Create a new Scanner for each collection pass.");
        try { return RunPass(); }
        catch (JournalFallbackException)
        {
            // RunPass has closed its writer and lock before this new full pass begins.
            var full = new Scanner(request with { Options = request.Options with { Mode = "verify" } }, Budget, Control, journal);
            Volatile.Write(ref fallback, full); return full.Run();
        }
    }
    private ScanResult RunPass()
    {
        using var statistics = stats;
        NativeWindows.RequireWindows11(); request.Options.Validate(); CpuHashBackend.Initialize(request.Options);
        if (request.SigningKey != null) Integrity.Sign(new { preflight = true }, request.SigningKey, request.SigningPassword);
        ThreadPool.GetMinThreads(out int minimum, out int io); ThreadPool.SetMinThreads(Math.Max(minimum, Budget.Limit + 4), io);
        using var evidenceLock = new EvidenceLock(request.Database);
        using var db = new EvidenceDatabase(request.Database, request.Options.Mode == "forensic");
        string started = EvidenceDatabase.Utc(), machine = EvidenceDatabase.MachineId();
        object? parent = db.Scalar("SELECT id FROM dw_scans WHERE status='COMPLETED' AND scope=$p0 ORDER BY id DESC LIMIT 1", request.Paths.Scope);
        parentId = parent == null ? null : Convert.ToInt64(parent);
        db.Execute("INSERT INTO dw_scans(schema_version,status,parent_scan_id,started,machine_id,mode,scope,config) VALUES(2,'RUNNING',$p0,$p1,$p2,$p3,$p4,$p5)",
            parentId, started, machine, request.Options.Mode, request.Paths.Scope, JsonSerializer.Serialize(request.Options, ScanOptions.Json));
        scanId = Convert.ToInt64(db.Scalar("SELECT last_insert_rowid()"));
        lastCommit = Stopwatch.GetTimestamp(); Publish();
        try
        {
            long phase = Stopwatch.GetTimestamp(); PrepareVolumes(db); stats.AddTime("volume_discovery", Stopwatch.GetElapsedTime(phase).TotalSeconds);
            db.Commit(); db.Begin();
            stats.Status = "SCANNING";
            Pipeline(db);
            Control.Check(); stats.Status = "FINALIZING"; Publish();
            phase = Stopwatch.GetTimestamp(); FinalizeMissing(db); Flush(db); db.Commit(); stats.AddTime("finalize_missing", Stopwatch.GetElapsedTime(phase).TotalSeconds);
            phase = Stopwatch.GetTimestamp(); var roots = Integrity.Roots(db.Connection, scanId, () => { Control.Check(); Publish(); }); stats.AddTime("merkle", Stopwatch.GetElapsedTime(phase).TotalSeconds);
            var volumeManifest = new List<Dictionary<string, object?>>();
            foreach (var volume in volumes)
            {
                Control.Check(); JournalCheckpoint? end = null;
                try { if (volume.Start != null) end = journal.Query(volume.Info.Path); }
                catch (Exception ex) when (ex is IOException or Win32Exception or InvalidDataException) { Event(db, "USN_END_ERROR", volume.Root, ex.Message); }
                bool usedJournal = volume.Incremental && Convert.ToInt64(db.Scalar("SELECT COUNT(*) FROM dw_files WHERE scan_id=$p0 AND method='USN_INCREMENTAL'", scanId)) > 0;
                if (usedJournal && (end == null || !NativeWindows.Continuity(volume.Start, end).Valid))
                {
                    string reason = end == null ? "Journal unavailable at completion" : NativeWindows.Continuity(volume.Start, end).Reason;
                    Event(db, "USN_END_INVALID", volume.Root, reason + "; restarting full BLAKE3 verification");
                    throw new JournalFallbackException(reason);
                }
                db.Begin(); db.Execute("UPDATE dw_volumes SET journal_end=$p0 WHERE scan_id=$p1 AND path=$p2", JsonSerializer.Serialize(end, ScanOptions.Json), scanId, request.Paths.Stored(volume.Root));
                volumeManifest.Add(new() { ["path"] = request.Paths.Stored(volume.Root), ["info"] = RedactedInfo(volume),
                    ["journal_start"] = volume.Start, ["journal_end"] = end, ["continuity"] = volume.Continuity });
            }
            string? network = request.Options.NetworkTime ? ObserveTime() : null;
            string completed = EvidenceDatabase.Utc(); stats.Status = "COMPLETED";
            var summary = stats.Snapshot(Budget);
            using var scope = JsonDocument.Parse(request.Paths.Scope);
            var manifest = new Dictionary<string, object?>
            {
                ["drivewitness_version"] = "3.1.1", ["schema_version"] = 2, ["canonicalization"] = "DW-MERKLE-V1", ["scan_id"] = scanId,
                ["machine_id"] = machine, ["started"] = started, ["completed"] = completed, ["system_time"] = completed,
                ["network_time_observation"] = network, ["hash_algorithms"] = new[] { "BLAKE3", "SHA-256" },
                ["file_count"] = db.Scalar("SELECT COUNT(*) FROM dw_files WHERE scan_id=$p0 AND status!='DELETED'", scanId),
                ["directory_count"] = stats.Directories, ["bytes_processed"] = stats.BytesRead, ["verification_mode"] = request.Options.Mode,
                ["volumes"] = volumeManifest, ["scope"] = scope.RootElement, ["summary"] = summary, ["performance"] = request.Options,
                ["final_budget"] = Budget.Snapshot(), ["backend"] = "official BLAKE3 Rust CPU; .NET SHA-256", ["gpu_backend"] = null,
                ["previous_scan_root"] = parentId == null ? null : db.Scalar("SELECT scan_root FROM dw_scans WHERE id=$p0", parentId),
                ["coverage_complete"] = !stats.CoverageIncomplete && stats.Errors == 0 && stats.Unstable == 0 && stats.Skipped == 0,
                ["stream_policy"] = "Default data stream only; reparse targets excluded", ["trusted_timestamp"] = request.TimestampProvider == null ? "not configured" : "separate validated proof",
                ["content_root"] = roots.ContentRoot, ["metadata_root"] = roots.MetadataRoot, ["scan_root"] = roots.ScanRoot
            };
            db.Begin();
            if (request.SigningKey != null)
            {
                var signature = Integrity.Sign(manifest, request.SigningKey, request.SigningPassword);
                db.Execute("INSERT INTO dw_signatures VALUES($p0,'Ed25519',$p1,$p2)", scanId, signature.PublicKey, signature.Signature);
            }
            if (request.TimestampProvider != null)
            {
                byte[] proof;
                try { proof = request.TimestampProvider.Timestamp(SHA256.HashData(CanonicalJson.Bytes(manifest)), Control.Token); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { Event(db, "TIMESTAMP_ERROR", null, request.Paths.AnonymousRoots.Length > 0 ? ex.GetType().Name : ex.Message); db.Commit(); throw; }
                db.Execute("UPDATE dw_scans SET trusted_timestamp_proof=$p0 WHERE id=$p1", proof, scanId);
            }
            Control.Check();
            db.Execute("UPDATE dw_scans SET status='COMPLETED',completed=$p0,content_root=$p1,metadata_root=$p2,scan_root=$p3,manifest=$p4,summary=$p5,network_time_observation=$p6 WHERE id=$p7",
                completed, roots.ContentRoot, roots.MetadataRoot, roots.ScanRoot, CanonicalJson.String(manifest), JsonSerializer.Serialize(summary, ScanOptions.Json), network, scanId);
            db.Commit();
            string? warning = null;
            try { db.Checkpoint(); } catch (IOException ex) { warning = ex.Message; }
            try { Integrity.ExportManifest(request.Database, request.Database + ".manifest.json", scanId); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { warning = (warning == null ? "" : warning + " ") + "Manifest export: " + ex.Message; }
            Publish(); return new(scanId, Path.GetFullPath(request.Database), "COMPLETED", summary, warning);
        }
        catch (JournalFallbackException ex)
        {
            db.Begin(); db.Execute("UPDATE dw_scans SET status='FAILED',failure=$p0,completed=$p1 WHERE id=$p2", "Incremental continuity lost: " + ex.Message + "; automatic full verification follows", EvidenceDatabase.Utc(), scanId); db.Commit();
            stats.Status = "RETRYING FULL VERIFICATION"; Publish(); throw;
        }
        catch (OperationCanceledException)
        {
            stats.Status = "CANCELLED";
            Flush(db); db.Execute("UPDATE dw_scans SET status='CANCELLED',completed=$p0,summary=$p1 WHERE id=$p2", EvidenceDatabase.Utc(), JsonSerializer.Serialize(stats.Snapshot(Budget), ScanOptions.Json), scanId); db.Commit();
            stats.Status = "CANCELLED"; Publish(); return new(scanId, Path.GetFullPath(request.Database), "CANCELLED", latest!);
        }
        catch (Exception ex)
        {
            Control.Cancel();
            try { db.Rollback(); db.Begin(); db.Execute("UPDATE dw_scans SET status='FAILED',failure=$p0,completed=$p1 WHERE id=$p2", request.Paths.AnonymousRoots.Length > 0 ? ex.GetType().Name : ex.Message, EvidenceDatabase.Utc(), scanId); db.Commit(); }
            catch (Exception) { /* A broken database remains RUNNING and is recovered as INTERRUPTED. */ }
            stats.Status = "FAILED"; Publish(); throw;
        }
    }

    private object RedactedInfo(VolumeState volume) => request.Paths.Anonymous(volume.Root)
        ? new { path = request.Paths.Stored(volume.Root), filesystem = volume.Info.Filesystem, serial = volume.Info.Serial, storage = volume.Info.Storage }
        : volume.Info;

    private void PrepareVolumes(EvidenceDatabase db)
    {
        db.Execute("CREATE TEMP TABLE dw_changed(volume TEXT,file_id TEXT,PRIMARY KEY(volume,file_id)) WITHOUT ROWID; CREATE TEMP TABLE dw_objects(volume TEXT,file_id TEXT,size INTEGER,modified_ns INTEGER,usn INTEGER,blake3 BLOB,sha256 BLOB,origin_scan INTEGER,PRIMARY KEY(volume,file_id)) WITHOUT ROWID;");
        foreach (string root in request.Paths.Roots)
        {
            Control.Check(); var info = NativeWindows.Volume(root); JournalCheckpoint? start = null; bool incremental = false; string reason = "USN disabled";
            if (request.Options.UsnEnabled)
            {
                try
                {
                    start = journal.Query(info.Path); JournalCheckpoint? previous = null;
                    string? stored = parentId == null ? null : db.Scalar("SELECT journal_start FROM dw_volumes WHERE scan_id=$p0 AND path=$p1", parentId, request.Paths.Stored(root)) as string;
                    if (stored != null) previous = JsonSerializer.Deserialize<JournalCheckpoint>(stored, ScanOptions.Json);
                    var continuity = NativeWindows.Continuity(previous, start); reason = continuity.Reason;
                    if (request.Options.Mode == "quick" && continuity.Valid)
                    {
                        db.Begin();
                        foreach (var change in journal.Changes(previous!, start, Control))
                            db.Execute("INSERT OR IGNORE INTO dw_changed VALUES($p0,$p1)", info.Path, change.FileId);
                        incremental = true;
                    }
                }
                catch (Exception ex) when (ex is IOException or Win32Exception or JsonException or InvalidDataException)
                { reason = "Full hashing fallback: " + ex.GetType().Name; Event(db, "USN_FALLBACK", root, ex.Message); }
            }
            var volume = new VolumeState(root, info, start, reason, incremental); volumes.Add(volume);
            db.Begin(); db.Execute("INSERT INTO dw_volumes VALUES($p0,$p1,$p2,$p3,NULL,$p4)", scanId, request.Paths.Stored(root), JsonSerializer.Serialize(RedactedInfo(volume), ScanOptions.Json), JsonSerializer.Serialize(start, ScanOptions.Json), reason);
        }
        if (request.Options.Storage == "unknown") Budget.Storage = volumes.Select(v => v.Info.Storage).Contains("hdd") ? "hdd" : volumes.Select(v => v.Info.Storage).Contains("remote") ? "remote" : volumes.Count == 1 ? volumes[0].Info.Storage : "unknown";
        if (request.Options.Gpu == "force") Event(db, "GPU_FALLBACK", null, "No validated GPU hashing backend is installed; using CPU.");
    }

    private void Pipeline(EvidenceDatabase db)
    {
        using var queue = new WorkQueue(Budget, Control);
        var producer = new Thread(() => Enumerate(queue)) { IsBackground = true, Name = "DriveWitness enumeration" };
        var pending = new List<Pending>(); Work? held = null;
        producer.Start();
        try
        {
            while (!queue.Done || queue.Count > 0 || held != null || pending.Count > 0)
            {
                for (int i = pending.Count - 1; i >= 0; i--)
                {
                    var task = pending[i]; if (!task.Task.IsCompleted) continue; pending.RemoveAt(i);
                    try { Store(db, task.Path, task.Task.GetAwaiter().GetResult(), task.Previous, task.IdentityMatch); }
                    catch (OperationCanceledException) { }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or OverflowException or ArgumentOutOfRangeException or InvalidDataException) { StoreError(db, task.Path, ex); }
                }
                if (rows.Count >= Budget.DatabaseBatchRows || written >= Budget.DatabaseBatchRows || Stopwatch.GetElapsedTime(lastCommit).TotalSeconds >= request.Options.DbCommitSeconds)
                { Flush(db); long t = Stopwatch.GetTimestamp(); db.Commit(); stats.AddTime("db_commit", Stopwatch.GetElapsedTime(t).TotalSeconds); db.Begin(); lastCommit = Stopwatch.GetTimestamp(); written = 0; }
                Publish(queue.Count, pending.Count);
                if (Control.Token.IsCancellationRequested)
                {
                    held = null; while (queue.Take(out _)) { }
                    if (pending.Count > 0 || !queue.Done) queue.Changed.WaitOne(50);
                    continue;
                }
                if (Control.IsPaused || pending.Count >= Budget.Snapshot().Workers || pending.Any(p => p.Large)) { queue.Changed.WaitOne(50); continue; }
                if (held == null && !queue.Take(out held)) { queue.Changed.WaitOne(50); continue; }
                var item = held!;
                if (item.Category != null)
                {
                    Event(db, item.Category, item.Path, item.Error?.Message ?? "Reparse target excluded");
                    if (item.Incomplete) stats.CoverageIncomplete = true;
                    if (item.Error != null) stats.Errors++; else stats.Skipped++;
                    held = null; continue;
                }
                bool large = item.Size >= request.Options.LargeFileThreshold;
                if (large && pending.Count > 0) { queue.Changed.WaitOne(50); continue; }
                try
                {
                    string stored = request.Paths.Stored(item.Path); var previous = db.FindPath(parentId, stored);
                    FileSnapshot? snapshot = parentId != null || request.Options.Mode == "quick" ? NativeWindows.Snapshot(item.Path) : null;
                    bool identityMatch = false; string? identity = snapshot == null ? null : snapshot.VolumeSerial + ":" + snapshot.FileId;
                    if (identity != null && pending.Any(p => p.Identity == identity)) { queue.Changed.WaitOne(50); continue; }
                    if (previous == null && snapshot != null) { previous = db.FindIdentity(parentId, snapshot); identityMatch = previous != null; }
                    HashResult? reusable = snapshot == null ? null : Reuse(db, item.Path, snapshot, previous, identityMatch);
                    if (reusable != null) Store(db, item.Path, reusable, previous, identityMatch);
                    else
                    {
                        var task = Task.Run(() => FileHasher.Hash(item.Path, previous, request.Options, Budget, Control, count => Interlocked.Add(ref stats.BytesRead, count)));
                        task.ContinueWith(_ => { try { queue.Changed.Set(); } catch (ObjectDisposedException) { } }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                        pending.Add(new(item.Path, previous, identityMatch, large, identity, task));
                    }
                    stats.CurrentPath = stored;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or OverflowException or ArgumentOutOfRangeException or InvalidDataException) { StoreError(db, item.Path, ex); }
                held = null;
                Control.Pace(Budget.Snapshot().DelayMilliseconds);
            }
        }
        finally
        {
            if (pending.Count > 0 || !queue.Done) Control.Cancel();
            producer.Join();
            stats.AddTime("enumeration_wall_with_backpressure", enumerationSeconds);
            try { Task.WhenAll(pending.Select(p => p.Task)).GetAwaiter().GetResult(); } catch (Exception) { }
        }
        Flush(db);
    }

    private HashResult? Reuse(EvidenceDatabase db, string path, FileSnapshot before, FileRecord? previous, bool renamed)
    {
        if (before.Directory || (before.Attributes & 0x400) != 0) return null;
        try
        {
            if (before.Links > 1)
            {
                using var command = db.Command("SELECT * FROM dw_objects WHERE volume=$p0 AND file_id=$p1 AND size=$p2 AND modified_ns=$p3", before.VolumeSerial, before.FileId, before.Size, before.ModifiedNs);
                using var reader = command.ExecuteReader();
                if (reader.Read())
                {
                    long token = reader.GetInt64(4);
                    if (PathPolicy.Canonical(NativeWindows.FinalPath(path)) == PathPolicy.Canonical(path) && journal.FileToken(path) == token && before.StableEquals(NativeWindows.Snapshot(path)))
                    {
                        byte[] b3 = (byte[])reader.GetValue(5);
                        return new(before, b3, (byte[])reader.GetValue(6), "CARRIED_FORWARD", previous == null ? "ADDED" : previous.Blake3!.AsSpan().SequenceEqual(b3) ? "UNCHANGED" : "MODIFIED", "SAME_SCAN_OBJECT", reader.GetInt64(7), token, []);
                    }
                }
            }
            if (request.Options.Mode != "quick" || renamed || previous?.Blake3 == null || previous.Sha256 == null ||
                (previous.VolumeSerial, previous.FileId, previous.Size, previous.ModifiedNs, previous.CreatedNs) != (before.VolumeSerial, before.FileId, before.Size, before.ModifiedNs, before.CreatedNs)) return null;
            var volume = volumes.FirstOrDefault(v => PathPolicy.IsWithin(path, v.Root));
            if (volume?.Incremental != true || volume.Start == null || db.Scalar("SELECT 1 FROM dw_changed WHERE volume=$p0 AND file_id=$p1", volume.Info.Path, before.FileId) != null) return null;
            if (PathPolicy.Canonical(NativeWindows.FinalPath(path)) != PathPolicy.Canonical(path)) return null;
            // Detect post-checkpoint changes as well as the bounded journal snapshot.
            long usn = journal.FileToken(path);
            if (usn >= volume.Start.NextUsn || !before.StableEquals(NativeWindows.Snapshot(path)) || usn != journal.FileToken(path)) return null;
            return new(before, previous.Blake3, previous.Sha256, "USN_INCREMENTAL", "UNCHANGED", "CARRIED_FORWARD", previous.Sha256OriginScan, usn, []);
        }
        catch (Exception ex) when (ex is Win32Exception or IOException or InvalidDataException) { return null; }
    }

    private void Store(EvidenceDatabase db, string path, HashResult result, FileRecord? previous, bool renamed)
    {
        var s = result.Snapshot; string status = renamed ? "LINK_OR_RENAME" : result.Status;
        bool sameIdentity = previous != null && previous.VolumeSerial == s.VolumeSerial && previous.FileId == s.FileId;
        if (previous != null && !sameIdentity) { status = "MODIFIED"; Event(db, "REPLACED", path, "A different file object occupies this path"); }
        long t = Stopwatch.GetTimestamp();
        rows.Add(new() { ScanId = scanId, CanonicalPath = request.Paths.Stored(path), OriginalPath = EvidenceDatabase.Compress(request.Paths.Anonymous(path) ? request.Paths.Stored(path) : path),
            VolumeSerial = s.VolumeSerial, FileId = s.FileId, Size = s.Size, CreatedNs = s.CreatedNs, ModifiedNs = s.ModifiedNs, AccessedNs = s.AccessedNs,
            Attributes = s.Attributes, Blake3 = result.Blake3, Sha256 = result.Sha256, Method = result.Method, Status = status,
            Sha256OriginScan = result.Sha256OriginScan ?? scanId, Sha256Provenance = result.Sha256Provenance, HardlinkCount = s.Links,
            FirstSeenScan = sameIdentity ? previous!.FirstSeenScan : scanId, LastSeenScan = scanId, CreatedUtc = EvidenceDatabase.Compress(EvidenceDatabase.Iso(s.CreatedNs)),
            ModifiedUtc = EvidenceDatabase.Compress(EvidenceDatabase.Iso(s.ModifiedNs)), AccessedUtc = EvidenceDatabase.Compress(EvidenceDatabase.Iso(s.AccessedNs)), ScanTime = EvidenceDatabase.Compress(EvidenceDatabase.Utc()) });
        stats.AddTime("compression", Stopwatch.GetElapsedTime(t).TotalSeconds);
        if (result.ObjectUsn != null)
            db.Execute("INSERT OR REPLACE INTO dw_objects VALUES($p0,$p1,$p2,$p3,$p4,$p5,$p6,$p7)", s.VolumeSerial, s.FileId, s.Size, s.ModifiedNs, result.ObjectUsn, result.Blake3, result.Sha256, result.Sha256OriginScan ?? scanId);
        stats.Processed++; written++; stats.AddTimings(result.Timings);
        if (result.Sha256Provenance == "RECALCULATED") stats.Sha256Files++;
        if (status == "ADDED") stats.Added++; else if (status == "MODIFIED" || (renamed && previous?.Blake3?.AsSpan().SequenceEqual(result.Blake3) == false)) stats.Modified++;
    }
    private void StoreError(EvidenceDatabase db, string path, Exception error)
    {
        string category = error is UnstableFileException ? "UNSTABLE" : error is OverflowException or ArgumentOutOfRangeException or InvalidDataException ? "INVALID_METADATA" : error is UnauthorizedAccessException || error is Win32Exception { NativeErrorCode: 5 } ? "ACCESS_DENIED" : error is FileNotFoundException or DirectoryNotFoundException ? "DISAPPEARED" : "IO_ERROR";
        string message = request.Paths.Anonymous(path) ? category + " (path redacted)" : error.Message;
        rows.Add(new() { ScanId = scanId, CanonicalPath = request.Paths.Stored(path), OriginalPath = EvidenceDatabase.Compress(request.Paths.Stored(path)), Method = category == "UNSTABLE" ? category : "ERROR", Status = category == "UNSTABLE" ? category : "ERROR", ErrorCode = category, ErrorMessage = message, LastSeenScan = scanId });
        Event(db, category, path, message); stats.Processed++; written++; if (category == "UNSTABLE") stats.Unstable++; else stats.Errors++;
    }
    private void Event(EvidenceDatabase db, string category, string? path, string message)
    {
        if (path != null && request.Paths.Anonymous(path)) message = category + " (path redacted)";
        db.Begin(); db.Execute("INSERT INTO dw_events(scan_id,time,category,path,message) VALUES($p0,$p1,$p2,$p3,$p4)", scanId, EvidenceDatabase.Utc(), category, path == null ? null : request.Paths.Stored(path), message); written++;
    }
    private void Flush(EvidenceDatabase db) { long t = Stopwatch.GetTimestamp(); db.InsertBatch(rows); stats.AddTime("db_insert", Stopwatch.GetElapsedTime(t).TotalSeconds); }
    private void Publish(int queue = 0, int active = 0)
    {
        if (Stopwatch.GetElapsedTime(lastPublish).TotalSeconds < .25 && stats.Status == "SCANNING") return;
        Volatile.Write(ref latest, stats.Snapshot(Budget, queue, rows.Count, active)); lastPublish = Stopwatch.GetTimestamp();
    }
    private void FinalizeMissing(EvidenceDatabase db)
    {
        if (parentId == null) return;
        db.Begin();
        // Snapshot missing paths into a disk-backed temporary table; keyset batches remain bounded.
        db.Execute("CREATE TEMP TABLE dw_missing AS SELECT old.* FROM dw_files old WHERE old.scan_id=$p0 AND old.status!='DELETED' AND NOT EXISTS(SELECT 1 FROM dw_files n WHERE n.scan_id=$p1 AND n.canonical_path=old.canonical_path); CREATE INDEX dw_missing_path ON dw_missing(canonical_path)", parentId, scanId);
        string? after = null;
        while (true)
        {
            Control.Check(); var missing = new List<FileRecord>();
            using (var command = db.Command("SELECT * FROM dw_missing WHERE $p0 IS NULL OR canonical_path>$p0 ORDER BY canonical_path LIMIT $p1", after, request.Options.DbBatchRows))
            using (var reader = command.ExecuteReader()) { while (reader.Read()) missing.Add(EvidenceDatabase.ReadFile(reader)); }
            if (missing.Count == 0) break;
            foreach (var old in missing)
            {
                Control.Check(); after = old.CanonicalPath;
                string? renamed = db.Scalar("SELECT canonical_path FROM dw_files WHERE scan_id=$p0 AND volume_serial=$p1 AND file_id=$p2 AND status='LINK_OR_RENAME' ORDER BY canonical_path LIMIT 1", scanId, old.VolumeSerial, old.FileId) as string;
                if (renamed != null)
                { db.Execute("UPDATE dw_files SET status='RENAMED' WHERE scan_id=$p0 AND canonical_path=$p1", scanId, renamed); db.Execute("INSERT INTO dw_events(scan_id,time,category,path,message) VALUES($p0,$p1,'RENAMED',$p2,$p3)", scanId, EvidenceDatabase.Utc(), old.CanonicalPath, "New path: " + renamed); stats.Renamed++; }
                else
                {
                    bool uncertain = stats.CoverageIncomplete; old.ScanId = scanId; old.Status = uncertain ? "UNVERIFIED" : "DELETED"; old.Method = uncertain ? "UNVERIFIED" : "CARRIED_FORWARD"; old.Sha256Provenance = "CARRIED_FORWARD"; rows.Add(old); if (!uncertain) stats.Deleted++;
                }
            }
            Flush(db); db.Commit(); db.Begin(); Publish();
        }
        stats.Added += Convert.ToInt64(db.Scalar("SELECT COUNT(*) FROM dw_files WHERE scan_id=$p0 AND status='LINK_OR_RENAME'", scanId));
        db.Execute("UPDATE dw_files SET status='ADDED' WHERE scan_id=$p0 AND status='LINK_OR_RENAME'", scanId);
    }
    private string ObserveTime()
    {
        long t = Stopwatch.GetTimestamp();
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
            using var requestMessage = new HttpRequestMessage(HttpMethod.Head, "https://www.cloudflare.com/");
            using var response = http.Send(requestMessage, Control.Token);
            return JsonSerializer.Serialize(new { source = "HTTPS Date header", observed = response.Headers.Date?.ToString("O"), trusted_timestamp = false }, ScanOptions.Json);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { Control.Token.ThrowIfCancellationRequested(); return "Observation unavailable"; }
        finally { stats.AddTime("network_time", Stopwatch.GetElapsedTime(t).TotalSeconds); }
    }
}
