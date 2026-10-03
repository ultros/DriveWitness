using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DriveWitness.Core;
using Microsoft.Data.Sqlite;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace DriveWitness.Tests;

public sealed class Sandbox : IDisposable
{
    public string Home { get; } = Path.Combine(Path.GetTempPath(), "DriveWitness-test-" + Guid.NewGuid().ToString("N"));
    public string Root => Path.Combine(Home, "data");
    public string Database => Path.Combine(Home, "evidence.db");
    public Sandbox() { Directory.CreateDirectory(Root); }
    public string Write(string name, string value = "hello") { string path = Path.Combine(Root, name); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, value); return path; }
    public ScanResult Scan(string mode = "verify", int performance = 100, ScanControl? control = null, PathPolicy? paths = null) => new Scanner(new(Database, paths ?? new([Root]), new() { Mode = mode, Performance = performance, UsnEnabled = false }), scanControl: control).Run();
    public List<FileRecord> Rows(long scan)
    {
        using var db = EvidenceDatabase.Open(Database, true); using var command = db.CreateCommand(); command.CommandText = "SELECT * FROM dw_files WHERE scan_id=$id ORDER BY canonical_path"; command.Parameters.AddWithValue("$id", scan);
        using var reader = command.ExecuteReader(); var result = new List<FileRecord>(); while (reader.Read()) result.Add(EvidenceDatabase.ReadFile(reader)); return result;
    }
    public void Dispose()
    {
        string full = Path.GetFullPath(Home);
        if (Path.GetDirectoryName(full) != Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) || !Path.GetFileName(full).StartsWith("DriveWitness-test-", StringComparison.Ordinal)) throw new IOException("Unsafe test cleanup.");
        Directory.Delete(full, true);
    }
}

public sealed class CoreTests
{
    [Theory]
    [InlineData("", "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]
    [InlineData("abc", "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")]
    public void KnownVectors(string input, string b3, string sha)
    { CpuHashBackend.Initialize(new()); Assert.Equal(b3, Convert.ToHexStringLower(CpuHashBackend.Digest(Encoding.UTF8.GetBytes(input)))); Assert.Equal(sha, Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(input)))); }

    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(1024)] [InlineData(1048577)]
    public void DualHashReadsContentOnce(int size)
    {
        using var s = new Sandbox(); byte[] data = new byte[size]; new Random(0).NextBytes(data); string path = Path.Combine(s.Root, "file"); File.WriteAllBytes(path, data);
        long bytes = 0; var o = new ScanOptions { Performance = 100 }; var hash = FileHasher.Hash(path, null, o, new(o), new(), n => bytes += n);
        Assert.Equal(size, bytes); Assert.Equal(SHA256.HashData(data), hash.Sha256); Assert.Equal(CpuHashBackend.Digest(data), hash.Blake3); Assert.Equal("FULL_DUAL_HASH", hash.Method);
    }

    [Fact] public void UnchangedCarriesEstablishedSha256()
    {
        using var s = new Sandbox(); s.Write("file"); var first = s.Scan(); var second = s.Scan(); var row = Assert.Single(s.Rows(second.ScanId));
        Assert.Equal("UNCHANGED", row.Status); Assert.Equal("FULL_BLAKE3", row.Method); Assert.Equal("CARRIED_FORWARD", row.Sha256Provenance); Assert.Equal(first.ScanId, row.Sha256OriginScan); Assert.Equal(5, second.Summary.BytesRead); Assert.True((bool)Integrity.VerifyDatabase(s.Database)["valid"]!);
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public void SameSizeChangedContentIsFoundEvenWithRestoredTimestamp(bool restore)
    {
        using var s = new Sandbox(); string path = s.Write("file", "aaaa"); s.Scan(); DateTime time = File.GetLastWriteTimeUtc(path); File.WriteAllText(path, "aaab"); if (restore) File.SetLastWriteTimeUtc(path, time);
        var scan = s.Scan(); var row = Assert.Single(s.Rows(scan.ScanId)); Assert.Equal("MODIFIED", row.Status); Assert.Equal("BLAKE3_CHANGED_SHA256", row.Method); Assert.Equal("RECALCULATED", row.Sha256Provenance); Assert.Equal(8, scan.Summary.BytesRead);
    }

    [Fact] public void ForensicRecalculatesBothDigests()
    { using var s = new Sandbox(); s.Write("file"); s.Scan(); var scan = s.Scan("forensic"); Assert.Equal("FULL_DUAL_HASH", Assert.Single(s.Rows(scan.ScanId)).Method); Assert.Equal(5, scan.Summary.BytesRead); }

    [Fact] public void AddedDeletedAndRenamedAreDistinct()
    {
        using var s = new Sandbox(); string rename = s.Write("old"); string delete = s.Write("gone"); s.Scan(); File.Move(rename, Path.Combine(s.Root, "renamed")); File.Delete(delete); s.Write("new", "new");
        var scan = s.Scan(); Assert.Equal(1, scan.Summary.Renamed); Assert.Equal(1, scan.Summary.Deleted); Assert.Equal(1, scan.Summary.Added); Assert.Contains(s.Rows(scan.ScanId), row => row.Status == "RENAMED");
    }

    [Fact] public void DirectoryRenameTracksFileIdentities()
    { using var s = new Sandbox(); s.Write("before/a"); s.Write("before/b"); s.Scan(); Directory.Move(Path.Combine(s.Root, "before"), Path.Combine(s.Root, "after")); var scan = s.Scan(); Assert.Equal(2, scan.Summary.Renamed); Assert.Equal(0, scan.Summary.Deleted); }

    [Fact] public void FileReplacementAtSamePathIsModified()
    { using var s = new Sandbox(); string path = s.Write("file"); var first = s.Scan(); File.Move(path, Path.Combine(s.Home, "kept")); s.Write("file"); var scan = s.Scan(); Assert.Equal("MODIFIED", Assert.Single(s.Rows(scan.ScanId)).Status); Assert.NotEqual(s.Rows(first.ScanId)[0].FileId, s.Rows(scan.ScanId)[0].FileId); }

    [Fact] public void LockedFileDoesNotAbortOtherFiles()
    { using var s = new Sandbox(); string path = s.Write("locked"); s.Write("readable"); using var locked = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None); var scan = s.Scan(); Assert.Equal("COMPLETED", scan.Status); Assert.Equal(1, scan.Summary.Errors); Assert.Contains(s.Rows(scan.ScanId), r => r.Status == "ERROR"); }

    [Fact] public void TimestampBeyondEvidenceIntegerRangeDoesNotAbortOtherFiles()
    {
        using var s = new Sandbox(); string path = s.Write("future"); s.Write("readable"); File.SetLastWriteTimeUtc(path, new DateTime(3000, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var scan = s.Scan(); Assert.Equal("COMPLETED", scan.Status); Assert.Equal(1, scan.Summary.Errors); Assert.Contains(s.Rows(scan.ScanId), r => r.ErrorCode == "INVALID_METADATA" && r.Blake3 == null);
    }

    [Fact] public void MutationDuringHashingIsUnstable()
    {
        using var s = new Sandbox(); string path = s.Write("file", new string('a', 200000)); var o = new ScanOptions { Performance = 100, ChunkBytes = 65536, UnstableRetries = 0 }; bool once = false;
        Assert.Throws<UnstableFileException>(() => FileHasher.Hash(path, null, o, new(o), new(), chunkRead: () => { if (!once) { once = true; File.WriteAllText(path, "changed"); } }));
    }

    [Fact] public void DisappearanceDuringHashingFailsSafely()
    {
        using var s = new Sandbox(); string path = s.Write("file", new string('a', 100000)); var o = new ScanOptions { Performance = 100, UnstableRetries = 0 };
        Assert.ThrowsAny<Exception>(() => FileHasher.Hash(path, null, o, new(o), new(), chunkRead: () => File.Delete(path)));
    }

    [Fact] public void UnicodeAndLongWindowsPathsWork()
    {
        using var s = new Sandbox(); string name = string.Join(Path.DirectorySeparatorChar, Enumerable.Repeat(new string('a', 80), 8)) + "\\café-😀.txt"; string path = s.Write(name);
        Assert.True(path.Length > 512); var scan = s.Scan(); Assert.Equal(0, scan.Summary.Errors); Assert.Equal(PathPolicy.Canonical(path), Assert.Single(s.Rows(scan.ScanId)).CanonicalPath);
    }

    [Fact] public void LargeFileUsesBoundedChunksAndCorrectDigests()
    {
        using var s = new Sandbox(); string path = Path.Combine(s.Root, "large"); using (var file = File.Create(path)) file.SetLength(65 * 1024 * 1024);
        var scan = s.Scan(); Assert.Equal(65 * 1024 * 1024, scan.Summary.BytesRead); Assert.Equal(0, scan.Summary.Errors); Assert.True((bool)Integrity.VerifyDatabase(s.Database)["valid"]!);
        // Independently generated by the retained Python BLAKE3/SHA-256 implementations.
        var row = Assert.Single(s.Rows(scan.ScanId)); Assert.Equal("c7d5e9a4a234b48a92a436fcb54145065325e8a17b0d2f5aced359fa505a95f7", Convert.ToHexStringLower(row.Blake3!)); Assert.Equal("25631f11bd18756ec0029380ec886af0c8824dc6b2706bbdb1d9451c7cf45f42", Convert.ToHexStringLower(row.Sha256!));
    }

    [Fact] public void HardLinkPathsKeepSharedIdentity()
    {
        using var s = new Sandbox(); string path = s.Write("first"); string second = Path.Combine(s.Root, "second");
        using var p = Process.Start(new ProcessStartInfo("fsutil.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, ArgumentList = { "hardlink", "create", second, path } })!;
        p.WaitForExit(); Assert.Equal(0, p.ExitCode); var scan = s.Scan(); var rows = s.Rows(scan.ScanId); Assert.Equal(2, rows.Count); Assert.Equal(rows[0].FileId, rows[1].FileId); Assert.Equal(rows[0].Blake3, rows[1].Blake3); Assert.All(rows, r => Assert.Equal(2, r.HardlinkCount));
    }

    [Fact] public void JunctionLoopIsRecordedWithoutFollowing()
    {
        using var s = new Sandbox(); s.Write("file"); string link = Path.Combine(s.Root, "loop");
        using var p = Process.Start(new ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, ArgumentList = { "/c", "mklink", "/J", link, s.Root } })!;
        p.WaitForExit(); Assert.Equal(0, p.ExitCode);
        try { var scan = s.Scan(); Assert.Equal(1, scan.Summary.Processed); Assert.Equal(1, scan.Summary.Skipped); Assert.True(scan.Summary.ElapsedSeconds < 10); }
        finally { Directory.Delete(link); }
    }

    [Fact] public async Task CancelledScanCannotVerifyAsCompleted()
    {
        using var s = new Sandbox(); for (int i = 0; i < 100; i++) s.Write("f" + i); var control = new ScanControl(); var scanner = new Scanner(new(s.Database, new([s.Root]), new() { Performance = 0, UsnEnabled = false }), scanControl: control);
        var task = Task.Run(scanner.Run); Assert.True(SpinWait.SpinUntil(() => scanner.Progress?.Status == "SCANNING", 5000)); control.Cancel(); var result = await task; Assert.Equal("CANCELLED", result.Status); Assert.False((bool)Integrity.VerifyDatabase(s.Database)["valid"]!);
    }

    [Fact] public async Task PauseAndThrottleAdaptWhileScanRuns()
    {
        using var s = new Sandbox(); for (int i = 0; i < 100; i++) s.Write("f" + i); var options = new ScanOptions { Performance = 0, UsnEnabled = false }; var control = new ScanControl(); var budget = new ResourceBudget(options); var scanner = new Scanner(new(s.Database, new([s.Root]), options), budget, control);
        var task = Task.Run(scanner.Run);
        try
        {
            Assert.True(SpinWait.SpinUntil(() => scanner.Progress?.Status == "SCANNING", 5000)); control.Pause(); await Task.Delay(500); long count = scanner.Progress!.Processed; await Task.Delay(350); Assert.Equal(count, scanner.Progress!.Processed);
            budget.Set(100); control.Resume(); Assert.Equal("COMPLETED", (await task).Status); Assert.Equal(100, scanner.Progress!.Budget.Level);
        }
        finally { control.Cancel(); await task; }
    }

    [Fact] public void InterruptedStatusIsRecoveredWithoutCompletingEvidence()
    {
        using var s = new Sandbox(); using (var db = new EvidenceDatabase(s.Database, false)) db.Execute("INSERT INTO dw_scans(schema_version,status) VALUES(2,'RUNNING')");
        using var reopened = new EvidenceDatabase(s.Database, false); Assert.Equal("INTERRUPTED", reopened.Scalar("SELECT status FROM dw_scans"));
    }

    [Fact] public void MerkleIsDeterministicAndDetectsTampering()
    {
        using var s = new Sandbox(); s.Write("a"); s.Write("b"); var scan = s.Scan(); using var db = EvidenceDatabase.Open(s.Database);
        Assert.Equal(Integrity.Roots(db, scan.ScanId), Integrity.Roots(db, scan.ScanId)); using var command = db.CreateCommand(); command.CommandText = "UPDATE dw_files SET size=size+1 WHERE canonical_path LIKE '%/a'"; command.ExecuteNonQuery(); Assert.False((bool)Integrity.VerifyDatabase(s.Database)["valid"]!);
    }

    [Fact] public void LegacyDatabaseRemainsReadableAfterMigration()
    {
        using var s = new Sandbox(); string path = s.Write("legacy"); using (var db = EvidenceDatabase.Open(s.Database))
        { using var command = db.CreateCommand(); command.CommandText = "CREATE TABLE files(original_path BLOB,sha1 TEXT); INSERT INTO files VALUES($path,$sha)"; command.Parameters.AddWithValue("$path", EvidenceDatabase.Compress(path)); command.Parameters.AddWithValue("$sha", Convert.ToHexStringLower(SHA1.HashData("hello"u8))); command.ExecuteNonQuery(); }
        Assert.True((bool)Integrity.VerifyLegacyLive(s.Database)["valid"]!); string migrated = Path.Combine(s.Home, "migrated.db"); Operations.MigrateLegacy(s.Database, migrated); Assert.True((bool)Integrity.VerifyLegacyLive(migrated)["valid"]!); Assert.True((bool)Integrity.VerifyDatabase(migrated)["legacy"]!);
    }

    private sealed class BadBackend : IHashBackend { public string Name => "faulty"; public string Version => "test"; public byte[] Digest(ReadOnlySpan<byte> input) => new byte[32]; }
    [Fact] public void InvalidAcceleratorFailsClosedToCpu()
    { var accelerator = new ValidatedAccelerator(new BadBackend()); Assert.False(accelerator.Eligible); Assert.Equal(CpuHashBackend.Digest("abc"u8), accelerator.Digest("abc"u8.ToArray())); }

    [Theory] [InlineData("id")] [InlineData("rolloff")] [InlineData("volume")] [InlineData("backwards")]
    public void InvalidUsnContinuityNeverQualifies(string fault)
    {
        var old = new JournalCheckpoint("C:\\", "123", "1", 0, 100, 0); var current = new JournalCheckpoint("C:\\", "123", "1", 0, 200, 0);
        current = fault switch { "id" => current with { JournalId = "2" }, "rolloff" => current with { FirstUsn = 101 }, "volume" => current with { Serial = "456" }, _ => current with { NextUsn = 99 } }; Assert.False(NativeWindows.Continuity(old, current).Valid);
    }
    [Fact] public void ValidUsnContinuityQualifies() => Assert.True(NativeWindows.Continuity(new("C:\\", "123", "1", 0, 100, 0), new("C:\\", "123", "1", 0, 200, 0)).Valid);
    [Fact] public void NoPreviousJournalRequiresBaseline() => Assert.False(NativeWindows.Continuity(null, new("C:\\", "123", "1", 0, 200, 0)).Valid);
    [Theory] [InlineData(0)] [InlineData(9)] [InlineData(20)] [InlineData(68)]
    public void MalformedUsnRecordsRejected(int length) => Assert.Throws<InvalidDataException>(() => NativeWindows.ParseRecords(new byte[length]));
    [Fact] public void ValidV2UsnRecordDecodesIdentity()
    {
        byte[] data = new byte[72]; BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(8), 64); BinaryPrimitives.WriteInt16LittleEndian(data.AsSpan(12), 2); BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(16), 123); BinaryPrimitives.WriteInt64LittleEndian(data.AsSpan(32), 500); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(64), 2); BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(66), 60);
        var record = Assert.Single(NativeWindows.ParseRecords(data)); Assert.Equal(500, record.Usn); Assert.Equal("0000000000000000000000000000007b", record.FileId);
    }
    [Theory] [InlineData(-1)] [InlineData(101)] public void InvalidPerformanceIsRejected(int value) => Assert.Throws<ArgumentException>(() => (new ScanOptions { Performance = value }).Validate());
    [Fact] public void OverlappingScopesAreRejected() { using var s = new Sandbox(); s.Write("child/a"); Assert.Throws<ArgumentException>(() => new PathPolicy([s.Root, Path.Combine(s.Root, "child")])); }
    [Fact] public void AnonymizationKeepsPathsOutOfEvidence()
    {
        using var s = new Sandbox(); s.Write("sensitive-name"); var paths = new PathPolicy([s.Root], [s.Root], Enumerable.Range(0, 32).Select(x => (byte)x).ToArray()); var scan = s.Scan(paths: paths); var row = Assert.Single(s.Rows(scan.ScanId)); Assert.StartsWith("hmac-sha256:", row.CanonicalPath); Assert.Equal(row.CanonicalPath, EvidenceDatabase.Decompress(row.OriginalPath)); Assert.DoesNotContain("sensitive-name", File.ReadAllText(s.Database + ".manifest.json"));
    }
    [Fact] public async Task QueueAndWorkerCountsStayBounded()
    {
        using var s = new Sandbox(); for (int i = 0; i < 2000; i++) s.Write("f" + i, "x"); var scanner = new Scanner(new(s.Database, new([s.Root]), new() { Performance = 100, UsnEnabled = false })); var task = Task.Run(scanner.Run);
        while (!task.IsCompleted) { var p = scanner.Progress; if (p != null) { Assert.InRange(p.HashQueue, 0, 128); Assert.InRange(p.ActiveWorkers, 0, 32); Assert.InRange(p.DbQueue, 0, 2032); } Thread.Sleep(10); }
        Assert.Equal(2000, (await task).Summary.Processed);
    }
    [Fact] public void QuickWithoutJournalFallsBackToFullHash()
    { using var s = new Sandbox(); s.Write("file"); s.Scan(); var scan = s.Scan("quick"); Assert.Equal("FULL_BLAKE3", Assert.Single(s.Rows(scan.ScanId)).Method); }
    [Fact] public void IncludeAndExcludeScopeFiltersWork()
    { using var s = new Sandbox(); s.Write("a.txt"); s.Write("b.txt"); s.Write("c.bin"); var paths = new PathPolicy([s.Root], includes: ["*.txt"], excludes: ["*/b.txt"]); var scan = s.Scan(paths: paths); Assert.EndsWith("/a.txt", Assert.Single(s.Rows(scan.ScanId)).CanonicalPath); }

    [Fact] public void ComparisonPairsRenameAndContentChangeReadOnly()
    {
        using var s = new Sandbox(); string path = s.Write("before", "aaaa"); s.Scan(); string baseline = Path.Combine(s.Home, "baseline.db");
        using (var source = EvidenceDatabase.Open(s.Database, true)) using (var output = EvidenceDatabase.Open(baseline)) source.BackupDatabase(output);
        File.Move(path, Path.Combine(s.Root, "after")); File.WriteAllText(Path.Combine(s.Root, "after"), "aaab"); s.Scan();
        var comparison = Operations.Compare(baseline, s.Database); Assert.Equal(1, comparison["renamed"]); Assert.Equal(1, comparison["modified"]); Assert.Equal(0, comparison["added"]); Assert.Equal(0, comparison["deleted"]);
    }

    [Fact] public void EvidenceLockRejectsAnotherCollector()
    { using var s = new Sandbox(); using var first = new EvidenceLock(s.Database); Assert.Throws<IOException>(() => new EvidenceLock(s.Database)); }

    [Theory]
    [InlineData(0.0, "0.0")] [InlineData(1.0, "1.0")] [InlineData(-1.0, "-1.0")] [InlineData(0.1, "0.1")]
    [InlineData(0.0001, "0.0001")] [InlineData(0.00001, "1e-05")] [InlineData(1e16, "1e+16")] [InlineData(1e15, "1000000000000000.0")]
    [InlineData(1.23456789e-8, "1.23456789e-08")] [InlineData(1.7976931348623157e308, "1.7976931348623157e+308")]
    [InlineData(5e-324, "5e-324")] [InlineData(-0.00123, "-0.00123")]
    public void CanonicalFloatingPointMatchesPython(double value, string expected) => Assert.Equal(expected, CanonicalJson.String(value));
    [Fact] public void CanonicalNegativeZeroMatchesPython() => Assert.Equal("-0.0", CanonicalJson.String(BitConverter.Int64BitsToDouble(long.MinValue)));
    [Fact] public void CanonicalUnicodeKeysUseCodepointOrdering()
    { Assert.Equal("{\"\\ue000\":2,\"\\ud83d\\ude00\":1}", CanonicalJson.String(new Dictionary<string, object?> { ["😀"] = 1, ["\ue000"] = 2 })); }
    [Fact] public void TypedDictionariesRemainCanonicalObjects()
    { Assert.Equal("{\"a\":1e-05,\"b\":1.0}", CanonicalJson.String(new Dictionary<string, double> { ["b"] = 1, ["a"] = .00001 })); }

    [Fact] public void AncestorJunctionCannotRedirectAContentRead()
    {
        using var s = new Sandbox(); string target = Path.Combine(s.Home, "outside"); Directory.CreateDirectory(target); File.WriteAllText(Path.Combine(target, "file"), "outside"); string link = Path.Combine(s.Root, "link");
        using var p = Process.Start(new ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, ArgumentList = { "/c", "mklink", "/J", link, target } })!;
        p.WaitForExit(); Assert.Equal(0, p.ExitCode); long bytes = 0; var options = new ScanOptions { Performance = 100 };
        try { Assert.Throws<IOException>(() => FileHasher.Hash(Path.Combine(link, "file"), null, options, new(options), new(), n => bytes += n)); Assert.Equal(0, bytes); }
        finally { Directory.Delete(link); }
    }

    [Theory] [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(5)] [InlineData(7)] [InlineData(10)] [InlineData(64)]
    public void MerkleMatchesIndependentReductionIncludingEmptyTree(int count)
    {
        var streaming = new MerkleTree(); var level = new List<byte[]>();
        for (int i = 0; i < count; i++) { byte[] leaf = BitConverter.GetBytes(i); streaming.Add(leaf); level.Add(SHA256.HashData(new byte[] { 0 }.Concat(leaf).ToArray())); }
        while (level.Count > 1) { var next = new List<byte[]>(); for (int i = 0; i < level.Count; i += 2) next.Add(i + 1 == level.Count ? level[i] : SHA256.HashData(new byte[] { 1 }.Concat(level[i]).Concat(level[i + 1]).ToArray())); level = next; }
        Assert.Equal(level.Count == 0 ? SHA256.HashData(new byte[] { 2 }.Concat(Encoding.ASCII.GetBytes("DW-MERKLE-V1")).ToArray()) : level[0], streaming.Root());
    }

    private sealed class FailingTimestamp : ITimestampProvider { public byte[] Timestamp(ReadOnlySpan<byte> digest, CancellationToken token) => throw new IOException("Test timestamp service failure"); }
    [Fact] public void TimestampFailurePreventsCompletionAndRetainsEvent()
    {
        using var s = new Sandbox(); s.Write("file"); Assert.Throws<IOException>(() => new Scanner(new(s.Database, new([s.Root]), new() { Performance = 100, UsnEnabled = false }, TimestampProvider: new FailingTimestamp())).Run());
        using var db = EvidenceDatabase.Open(s.Database, true); using var command = db.CreateCommand(); command.CommandText = "SELECT status FROM dw_scans"; Assert.Equal("FAILED", command.ExecuteScalar()); command.CommandText = "SELECT COUNT(*) FROM dw_events WHERE category='TIMESTAMP_ERROR'"; Assert.Equal(1L, command.ExecuteScalar()); Assert.False((bool)Integrity.VerifyDatabase(s.Database)["valid"]!);
    }
    [Fact] public void SignedScanChecksSignatureAndTrustedKey()
    {
        using var s = new Sandbox(); s.Write("file"); using var fixture = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "python-v2.json"))); var f = fixture.RootElement;
        string key = Path.Combine(s.Home, "test-only.pem"); File.WriteAllText(key, f.GetProperty("encrypted_pem").GetString());
        new Scanner(new(s.Database, new([s.Root]), new() { Performance = 100, UsnEnabled = false }, key, "test-only")).Run();
        Assert.True((bool)Integrity.VerifyDatabase(s.Database, Convert.FromBase64String(f.GetProperty("public_key").GetString()!))["valid"]!);
        Assert.False((bool)Integrity.VerifyDatabase(s.Database, new byte[32])["valid"]!);
    }
    [Fact] public async Task RealProcessCrashRetainsCommittedPartialRowsAndReleasesLock()
    {
        using var s = new Sandbox(); for (int i = 0; i < 100; i++) s.Write("file" + i);
        var repository = new DirectoryInfo(AppContext.BaseDirectory); while (repository != null && !File.Exists(Path.Combine(repository.FullName, "DriveWitness.slnx"))) repository = repository.Parent;
        Assert.NotNull(repository);
        string configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name;
        string cli = Path.Combine(repository.FullName, "src", "DriveWitness.Cli", "bin", configuration, "net10.0-windows10.0.22000.0", "drivewitness-cli.exe");
        using var process = new Process { StartInfo = new(cli) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, ArgumentList = { "scan", s.Root, "--db", s.Database, "--performance", "0", "--db-batch-rows", "10", "--db-commit-seconds", "0.1", "--no-usn", "--json" } } };
        process.Start(); var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync(); bool committed = false;
        try
        {
            var elapsed = Stopwatch.StartNew();
            while (!process.HasExited && elapsed.Elapsed.TotalSeconds < 10)
            {
                try { using var db = EvidenceDatabase.Open(s.Database, true); using var command = db.CreateCommand(); command.CommandText = "SELECT COUNT(*) FROM dw_files"; if (Convert.ToInt64(command.ExecuteScalar()) > 0) { committed = true; break; } }
                catch (SqliteException) { }
                await Task.Delay(20);
            }
            Assert.True(committed, "Child must commit at least one partial batch before the forced exit.");
        }
        finally { if (!process.HasExited) process.Kill(true); await process.WaitForExitAsync(); await stdout; await stderr; }
        using var recovered = new EvidenceDatabase(s.Database, false); Assert.Equal("INTERRUPTED", recovered.Scalar("SELECT status FROM dw_scans")); Assert.True(Convert.ToInt64(recovered.Scalar("SELECT COUNT(*) FROM dw_files")) > 0);
    }

    private sealed class SimulatedJournal : IJournalAccess
    {
        public string Id = "1"; public long Next = 100, Token = 50; public string? ChangedFile; public bool Unavailable, Malformed;
        public int QueryCount, ChangeAtQuery; public long First; public string? EndFault; public Action? OnFault;
        public JournalCheckpoint Query(string volume)
        {
            if (++QueryCount == ChangeAtQuery) { OnFault?.Invoke(); if (EndFault == "rolloff") { First = 300; Next = 400; } else Id = "2"; }
            return Unavailable ? throw new IOException("Non-NTFS/unavailable journal") : new(volume, "simulation-volume", Id, First, Next, First);
        }
        public IEnumerable<UsnRecord> Changes(JournalCheckpoint previous, JournalCheckpoint current, ScanControl control)
        { if (Malformed) throw new InvalidDataException("Malformed IOCTL response"); if (ChangedFile != null) yield return new(ChangedFile, 150, 1); }
        public long FileToken(string path) => Token;
    }
    [Theory] [InlineData("valid")] [InlineData("changed")] [InlineData("after-checkpoint")] [InlineData("journal-replaced")] [InlineData("unavailable")] [InlineData("malformed")]
    public void QuickUsesOnlyEligibleJournalEvidence(string situation)
    {
        using var s = new Sandbox(); string path = s.Write("file", "aaaa"); var journal = new SimulatedJournal(); var options = new ScanOptions { Performance = 100 };
        new Scanner(new(s.Database, new([s.Root]), options), journalAccess: journal).Run(); journal.Next = 200;
        if (situation == "changed") { DateTime time = File.GetLastWriteTimeUtc(path); File.WriteAllText(path, "aaab"); File.SetLastWriteTimeUtc(path, time); journal.ChangedFile = NativeWindows.Snapshot(path).FileId; }
        if (situation == "after-checkpoint") journal.Token = 250;
        if (situation == "journal-replaced") journal.Id = "2";
        if (situation == "unavailable") journal.Unavailable = true;
        if (situation == "malformed") journal.Malformed = true;
        var scan = new Scanner(new(s.Database, new([s.Root]), options with { Mode = "quick" }), journalAccess: journal).Run(); var row = Assert.Single(s.Rows(scan.ScanId));
        Assert.Equal(situation == "valid" ? "USN_INCREMENTAL" : situation == "changed" ? "BLAKE3_CHANGED_SHA256" : "FULL_BLAKE3", row.Method);
        Assert.Equal(situation == "valid" ? 0 : situation == "changed" ? 8 : 4, scan.Summary.BytesRead);
    }
    [Theory] [InlineData("journal-replaced")] [InlineData("rolloff")]
    public void QuickLosingContinuityAtCompletionAutomaticallyReverifiesContent(string fault)
    {
        using var s = new Sandbox(); string path = s.Write("file", "aaaa"); var journal = new SimulatedJournal(); var options = new ScanOptions { Performance = 100 };
        new Scanner(new(s.Database, new([s.Root]), options), journalAccess: journal).Run(); journal.Next = 200; journal.ChangeAtQuery = 4; journal.EndFault = fault;
        journal.OnFault = () => { DateTime time = File.GetLastWriteTimeUtc(path); File.WriteAllText(path, "aaab"); File.SetLastWriteTimeUtc(path, time); };
        var scanner = new Scanner(new(s.Database, new([s.Root]), options with { Mode = "quick" }), journalAccess: journal); var scan = scanner.Run();
        Assert.Equal(3, scan.ScanId); Assert.Equal("COMPLETED", scan.Status); Assert.Equal("MODIFIED", Assert.Single(s.Rows(scan.ScanId)).Status); Assert.Equal("BLAKE3_CHANGED_SHA256", s.Rows(scan.ScanId)[0].Method); Assert.Equal(8, scan.Summary.BytesRead); Assert.Equal("COMPLETED", scanner.Progress!.Status);
        using var db = EvidenceDatabase.Open(s.Database, true); using var command = db.CreateCommand(); command.CommandText = "SELECT status FROM dw_scans WHERE id=2"; Assert.Equal("FAILED", command.ExecuteScalar()); command.CommandText = "SELECT mode FROM dw_scans WHERE id=3"; Assert.Equal("verify", command.ExecuteScalar()); Assert.True((bool)Integrity.VerifyDatabase(s.Database)["valid"]!);
    }

    [Theory] [InlineData("UTF-8")] [InlineData("UTF-16le")]
    public void PythonV2RootsAndEncryptedSignaturesAreCompatible(string encoding)
    {
        using var s = new Sandbox(); using var fixture = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "python-v2.json"))); var f = fixture.RootElement;
        using (var initial = EvidenceDatabase.Open(s.Database)) { using var cmd = initial.CreateCommand(); cmd.CommandText = $"PRAGMA encoding='{encoding}'"; cmd.ExecuteNonQuery(); }
        using (var db = new EvidenceDatabase(s.Database, false))
        {
            db.Execute("INSERT INTO dw_scans(id,schema_version,status) VALUES(1,2,'COMPLETED')"); db.Begin();
            foreach (var jsonRow in f.GetProperty("rows").EnumerateArray())
            {
                object?[] values = jsonRow.EnumerateArray().Select(x => x.ValueKind switch { JsonValueKind.Null => null, JsonValueKind.Number => (object)x.GetInt64(), JsonValueKind.String => x.GetString(), _ => Convert.FromBase64String(x.GetProperty("base64").GetString()!) }).ToArray();
                db.Execute("INSERT INTO dw_files VALUES(" + string.Join(',', Enumerable.Range(0, 26).Select(i => "$p" + i)) + ")", values);
            }
            db.Commit(); var roots = Integrity.Roots(db.Connection, 1); Assert.Equal(f.GetProperty("roots").GetProperty("content_root").GetString(), roots.ContentRoot); Assert.Equal(f.GetProperty("roots").GetProperty("metadata_root").GetString(), roots.MetadataRoot); Assert.Equal(f.GetProperty("roots").GetProperty("scan_root").GetString(), roots.ScanRoot);
        }
        var manifest = f.GetProperty("manifest"); Assert.Equal(f.GetProperty("canonical").GetString(), CanonicalJson.String(manifest)); Assert.True(Integrity.VerifySignature(Convert.FromBase64String(f.GetProperty("public_key").GetString()!), Convert.FromBase64String(f.GetProperty("signature").GetString()!), manifest));
        string pem = Path.Combine(s.Home, "test-only.pem"); File.WriteAllText(pem, f.GetProperty("encrypted_pem").GetString()); var signed = Integrity.Sign(manifest, pem, "test-only"); Assert.Equal(Convert.FromBase64String(f.GetProperty("signature").GetString()!), signed.Signature);
    }
}
