using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using DriveWitness.Core;
using Xunit;

namespace DriveWitness.Tests;

public sealed class ExplorerTests
{
    [Fact] public void ReviewSetAndUnreviewedFiltersRequireSetMembership()
    {
        using var s = new Sandbox(); s.Write("one"); s.Write("two"); s.Write("three"); s.Scan(); var q = new DatabaseQueryService(s.Database);
        Assert.Empty(q.SearchFiles(new() { Review = "unreviewed", ReviewSet = "Case" }).Rows);
        var rows = q.SearchFiles(new()).Rows; var review = new ReviewStore(s.Database); review.Save(rows[0], false, false, "", "Case"); review.Save(rows[1], false, true, "", "Case");
        Assert.Equal(rows[0].CanonicalPath, Assert.Single(q.SearchFiles(new() { Review = "unreviewed", ReviewSet = "Case" }).Rows).CanonicalPath);
        string output = Path.Combine(s.Home, "set.json"); q.Export(new() { Review = "unreviewed", ReviewSet = "Case" }, output, "json");
        using var doc = JsonDocument.Parse(File.ReadAllText(output)); Assert.Single(doc.RootElement.GetProperty("records").EnumerateArray());
    }
    [Fact] public void FullDualVerificationDetectsAnIncorrectStoredSha256()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); var row = Assert.Single(new DatabaseQueryService(s.Database).SearchFiles(new()).Rows); row.Sha256 = new byte[32];
        Assert.Equal("CONTENT DIFFERENT", LiveFileComparison.Compare(row, true).Result);
    }
    [Fact] public void CollectorExcludesItsReviewSidecarInsideTheScope()
    {
        using var s = new Sandbox(); s.Write("file"); string db = Path.Combine(s.Root, "evidence.db");
        ScanResult Scan() => new Scanner(new(db, new([s.Root]), new() { Performance = 100, UsnEnabled = false })).Run();
        Scan(); var row = Assert.Single(new DatabaseQueryService(db).SearchFiles(new()).Rows); new ReviewStore(db).Save(row, true, false, "note", "Case");
        var result = Scan(); Assert.Equal(1, result.Summary.Processed); Assert.Equal(0, result.Summary.Added); Assert.True((bool)Integrity.VerifyDatabase(db)["valid"]!);
    }
    [Theory] [InlineData(false)] [InlineData(true)]
    public void HardlinkChangesArePathsAndNotExtraRenames(bool remove)
    {
        using var s = new Sandbox(); string original = s.Write("original"), link = Path.Combine(s.Root, "link");
        void Link() { using var p = Process.Start(new ProcessStartInfo("fsutil.exe") { UseShellExecute = false, CreateNoWindow = true, ArgumentList = { "hardlink", "create", link, original } })!; p.WaitForExit(); Assert.Equal(0, p.ExitCode); }
        if (remove) Link(); var before = s.Scan(); if (remove) File.Delete(link); else Link(); var after = s.Scan(); var q = new DatabaseQueryService(s.Database);
        var result = q.CompareScans(before.ScanId, after.ScanId); Assert.Equal(1, result[remove ? "DELETED" : "ADDED"]); Assert.False(result.ContainsKey("RENAMED"));
        Assert.Equal(2, q.SearchFiles(new() { ScanId = after.ScanId, BaselineScanId = before.ScanId }).Rows.Count);
    }
    [Fact] public void PreviousVersionPrefersTheSameHardlinkPath()
    {
        using var s = new Sandbox(); string path = s.Write("a"), link = Path.Combine(s.Root, "z");
        using (var p = Process.Start(new ProcessStartInfo("fsutil.exe") { UseShellExecute = false, CreateNoWindow = true, ArgumentList = { "hardlink", "create", link, path } })!) { p.WaitForExit(); Assert.Equal(0, p.ExitCode); }
        s.Scan(); var next = s.Scan(); var q = new DatabaseQueryService(s.Database); var row = Assert.Single(q.SearchFiles(new() { ScanId = next.ScanId, PathContains = "/z" }).Rows);
        Assert.Equal(row.CanonicalPath, q.GetPreviousVersion(row)!.CanonicalPath);
    }
    [Fact] public void ExportAndTableUseTheSameDescendingTieOrder()
    {
        using var s = new Sandbox(); s.Write("a"); s.Write("b"); s.Scan(); s.Scan(); var q = new DatabaseQueryService(s.Database); var query = new EvidenceQuery { Sort = "size", Descending = true };
        string output = Path.Combine(s.Home, "sorted.json"); q.Export(query, output, "json"); using var doc = JsonDocument.Parse(File.ReadAllText(output));
        Assert.Equal(q.SearchFiles(query).Rows.Select(r => $"{r.ScanId}:{r.CanonicalPath}"), doc.RootElement.GetProperty("records").EnumerateArray().Select(r => $"{r.GetProperty("scan_id")}:{r.GetProperty("canonical_path").GetString()}"));
    }
    [Fact] public void ArbitrarySqliteFilesAreRejected()
    {
        using var s = new Sandbox(); using (var db = EvidenceDatabase.Open(s.Database)) { using var c = db.CreateCommand(); c.CommandText = "CREATE TABLE unrelated(value TEXT)"; c.ExecuteNonQuery(); }
        Assert.Throws<InvalidDataException>(() => new DatabaseQueryService(s.Database).GetScans());
    }
    [Fact] public void SetManagementAndVerificationHistoryLeaveEvidenceIntact()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); var row = Assert.Single(new DatabaseQueryService(s.Database).SearchFiles(new()).Rows); var store = new ReviewStore(s.Database); var before = SHA256.HashData(File.ReadAllBytes(s.Database));
        store.Save(row, true, false, "Keep this note", "Old"); store.RenameSet("Old", "New"); Assert.Equal(new[] { "New" }, store.GetSets()); store.RemoveSet("New"); Assert.Equal("Keep this note", store.Get(row)!.Note); Assert.Empty(store.GetSets());
        store.AppendVerification(row, new("FILE MISSING", row, null, EvidenceDatabase.Utc())); Assert.Single(store.GetVerifications(row)); Assert.NotNull(store.LastVerification()); Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(s.Database)));
    }
    [Fact] public void ManifestSignatureVerificationChecksTrustedKeysAndTampering()
    {
        using var s = new Sandbox(); s.Write("file"); using var fixture = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "python-v2.json"))); var f = fixture.RootElement;
        string key = Path.Combine(s.Home, "test-only.pem"); File.WriteAllText(key, f.GetProperty("encrypted_pem").GetString()); new Scanner(new(s.Database, new([s.Root]), new() { Performance = 100, UsnEnabled = false }, key, "test-only")).Run();
        string manifest = Path.Combine(s.Home, "manifest.json"); Integrity.ExportManifest(s.Database, manifest); Assert.True((bool)Integrity.VerifyManifestFile(manifest, Convert.FromBase64String(f.GetProperty("public_key").GetString()!))["valid"]!); Assert.False((bool)Integrity.VerifyManifestFile(manifest, new byte[32])["valid"]!);
        string data = File.ReadAllText(manifest); using (var doc = JsonDocument.Parse(data)) { string root = doc.RootElement.GetProperty("manifest").GetProperty("scan_root").GetString()!; File.WriteAllText(manifest, data.Replace(root, new string('0', 64))); } Assert.False((bool)Integrity.VerifyManifestFile(manifest)["valid"]!);
    }
    [Fact] public void DateAndCarriedHashFiltersComposeWithStatus()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); var scan = s.Scan(); var q = new DatabaseQueryService(s.Database); var row = Assert.Single(q.SearchFiles(new() { ScanId = scan.ScanId }).Rows);
        Assert.Single(q.SearchFiles(new() { ScanId = scan.ScanId, Status = "UNCHANGED", Method = "FULL_BLAKE3", HashSource = "CARRIED_FORWARD", CreatedAfterNs = row.CreatedNs, CreatedBeforeNs = row.CreatedNs, ModifiedAfterNs = row.ModifiedNs, ModifiedBeforeNs = row.ModifiedNs }).Rows);
        Assert.Empty(q.SearchFiles(new() { CreatedAfterNs = row.CreatedNs + 1 }).Rows);
    }
    [Fact] public void ExportCannotReplaceEvidenceThroughAJunction()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); string alias = Path.Combine(s.Home, "alias");
        using (var p = Process.Start(new ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, ArgumentList = { "/c", "mklink", "/J", alias, s.Home } })!) { p.WaitForExit(); Assert.Equal(0, p.ExitCode); }
        try { Assert.Throws<ArgumentException>(() => new DatabaseQueryService(s.Database).Export(new(), Path.Combine(alias, "evidence.db"), "json")); Assert.True((bool)Integrity.VerifyDatabase(s.Database)["valid"]!); }
        finally { Directory.Delete(alias); }
    }
    [Fact] public void CryptographicVerificationHonorsCancellation()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        Assert.Throws<OperationCanceledException>(() => Integrity.VerifyDatabase(s.Database, token: cancellation.Token));
    }
    [Fact] public void HashMismatchViewUsesTheLatestSavedVerification()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); var q = new DatabaseQueryService(s.Database); var row = Assert.Single(q.SearchFiles(new()).Rows); Assert.Empty(q.SearchFiles(new() { HashMismatch = true }).Rows);
        var store = new ReviewStore(s.Database); store.AppendVerification(row, new("CONTENT DIFFERENT", row, null, EvidenceDatabase.Utc())); Assert.Single(q.SearchFiles(new() { HashMismatch = true }).Rows);
        store.AppendVerification(row, new("UNCHANGED", row, row, EvidenceDatabase.Utc())); Assert.Empty(q.SearchFiles(new() { HashMismatch = true }).Rows);
    }
    [Fact] public void QuietBudgetStillReducesExplicitWorkerAndBatchCaps()
    {
        var options = new ScanOptions { Performance = 100, Workers = 8, DbBatchRows = 4000 }; var budget = new ResourceBudget(options); var maximum = budget.Snapshot(); budget.Set(0); var quiet = budget.Snapshot();
        Assert.Equal(1, quiet.Workers); Assert.True(quiet.DatabaseBatchRows < maximum.DatabaseBatchRows); Assert.Equal(options.DbBatchRows, maximum.DatabaseBatchRows); Assert.True(maximum.Workers <= Math.Min(8, Environment.ProcessorCount));
    }
    [Fact] public async Task CliLiveVerificationUsesTheSelectedHistoricalScan()
    {
        using var s = new Sandbox(); string file = s.Write("file", "old"); var first = s.Scan(); File.WriteAllText(file, "new"); s.Scan(); File.WriteAllText(file, "old");
        var repository = new DirectoryInfo(AppContext.BaseDirectory); while (repository != null && !File.Exists(Path.Combine(repository.FullName, "DriveWitness.slnx"))) repository = repository.Parent;
        string cli = Path.Combine(repository!.FullName, "src", "DriveWitness.Cli", "bin", new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name, "net10.0-windows10.0.22000.0", "drivewitness-cli.exe");
        using var process = new Process { StartInfo = new(cli) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, ArgumentList = { "verify", "--db", s.Database, "--scan-id", first.ScanId.ToString(), "--live", "--json" } } };
        process.Start(); var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync(); Assert.Equal("", await stderr); Assert.Equal(0, process.ExitCode); using var result = JsonDocument.Parse(await stdout); Assert.Equal(first.ScanId, result.RootElement.GetProperty("scan_id").GetInt64()); Assert.True(result.RootElement.GetProperty("valid").GetBoolean());
    }
    [Theory]
    [InlineData("path", false)] [InlineData("path", true)] [InlineData("size", false)] [InlineData("size", true)]
    [InlineData("status", false)] [InlineData("scan", true)]
    public void KeysetPagesHaveNoGapsOrDuplicates(string sort, bool descending)
    {
        using var s = new Sandbox(); for (int i = 0; i < 17; i++) s.Write($"{i:00}.txt", new string('a', i % 3 + 1));
        s.Scan(); s.Scan(); var service = new DatabaseQueryService(s.Database); var keys = new List<string>(); QueryCursor? cursor = null;
        do { var page = service.SearchFiles(new() { Sort = sort, Descending = descending }, cursor, 3); keys.AddRange(page.Rows.Select(r => r.ScanId + ":" + r.CanonicalPath)); if (!page.HasMore) break; cursor = page.Next; } while (true);
        Assert.Equal(34, keys.Count); Assert.Equal(34, keys.Distinct().Count());
    }
    [Fact] public void FiltersAndHashLookupRunOnEvidence()
    {
        using var s = new Sandbox(); s.Write("payload.exe", "content"); s.Write("readme.txt", "hello"); var scan = s.Scan();
        var q = new DatabaseQueryService(s.Database); var row = Assert.Single(q.SearchFiles(new() { Extension = ".exe", MinimumSize = 6, ScanId = scan.ScanId }).Rows);
        Assert.Single(q.SearchFiles(new() { Blake3 = Convert.ToHexStringLower(row.Blake3!) }).Rows);
        Assert.Single(q.SearchFiles(new() { Blake3 = Convert.ToHexStringLower(row.Blake3!)[..5] }).Rows);
        Assert.Empty(q.SearchFiles(new() { Search = "' OR 1=1 --" }).Rows);
        Assert.Throws<ArgumentException>(() => q.SearchFiles(new() { Sort = "size;DROP TABLE dw_files" }));
    }
    [Fact] public void CancellationInterruptsQuery()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); using var cancel = new CancellationTokenSource(); cancel.Cancel();
        Assert.Throws<OperationCanceledException>(() => new DatabaseQueryService(s.Database).SearchFiles(new(), token: cancel.Token));
    }
    [Fact] public void ReviewAndLiveChecksLeaveHistoricalEvidenceUntouched()
    {
        using var s = new Sandbox(); string file = s.Write("file"); s.Scan(); var q = new DatabaseQueryService(s.Database); var row = Assert.Single(q.SearchFiles(new()).Rows);
        byte[] before = SHA256.HashData(File.ReadAllBytes(s.Database));
        var review = new ReviewStore(s.Database); review.Save(row, true, true, "Investigated", "Known Good");
        Assert.Equal("Investigated", review.Get(row)!.Note);
        Assert.Single(q.SearchFiles(new() { Review = "flagged" }).Rows);
        Assert.Empty(q.SearchFiles(new() { Review = "unreviewed" }).Rows);
        var live = LiveFileComparison.Compare(row); Assert.Equal("UNCHANGED", live.Result); Assert.Equal("CARRIED_FORWARD", live.Current!.Sha256Provenance);
        File.WriteAllText(file, "different"); live = LiveFileComparison.Compare(row); Assert.Equal("CONTENT DIFFERENT", live.Result);
        review.AppendVerification(row, live); Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(s.Database)));
        Assert.True((bool)Integrity.VerifyDatabase(s.Database)["valid"]!);
    }
    [Theory] [InlineData("json")] [InlineData("jsonl")] [InlineData("csv")] [InlineData("html")]
    public void ExportsIncludeProvenance(string format)
    {
        using var s = new Sandbox(); s.Write("payload&test.txt"); s.Scan(); string file = Path.Combine(s.Home, "export." + format);
        var q = new DatabaseQueryService(s.Database); q.Export(new(), file, format); string data = File.ReadAllText(file);
        Assert.Contains("source_database", data); Assert.Contains("Jesse Lee Shelley", data);
        if (format == "json") { using var doc = JsonDocument.Parse(data); Assert.Single(doc.RootElement.GetProperty("records").EnumerateArray()); }
        if (format == "html") Assert.Contains("payload&amp;test", data);
        Assert.Throws<ArgumentException>(() => q.Export(new(), s.Database, format));
    }
    [Fact] public void LegacySha1DatabaseOpensWithoutMigration()
    {
        using var s = new Sandbox(); using (var db = EvidenceDatabase.Open(s.Database))
        { using var c = db.CreateCommand(); c.CommandText = "CREATE TABLE files(original_path BLOB,sha1 TEXT);INSERT INTO files VALUES($path,'123')"; c.Parameters.AddWithValue("$path", EvidenceDatabase.Compress("C:/old.txt")); c.ExecuteNonQuery(); }
        byte[] before = SHA256.HashData(File.ReadAllBytes(s.Database)); var q = new DatabaseQueryService(s.Database);
        var row = Assert.Single(q.SearchFiles(new() { Search = "old" }).Rows); Assert.Equal("LEGACY", row.Method); Assert.Equal("123", row.LegacySha1);
        Assert.Equal(before, SHA256.HashData(File.ReadAllBytes(s.Database)));
    }
    [Fact] public void VersionsTrackIdentityAndComparisonDetectsMetadataAndContent()
    {
        using var s = new Sandbox(); var path = s.Write("file"); var first = s.Scan(); File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddDays(-2)); var second = s.Scan();
        var q = new DatabaseQueryService(s.Database); Assert.Equal(1, q.CompareScans(first.ScanId, second.ScanId)["METADATA_CHANGED"]);
        File.WriteAllText(path, "new content"); var third = s.Scan(); Assert.Equal(1, q.CompareScans(second.ScanId, third.ScanId)["MODIFIED"]);
        var row = Assert.Single(q.SearchFiles(new() { ScanId = third.ScanId }).Rows); Assert.Equal(3, q.GetFileVersions(row).Rows.Count);
        Assert.Single(q.SearchFiles(new() { ScanId = third.ScanId, BaselineScanId = first.ScanId, Status = "MODIFIED" }).Rows);
    }
    [Fact] public void RenamesAndDeletionComparisonRetainHistoricalVersions()
    {
        using var s = new Sandbox(); string path = s.Write("before"); s.Write("removed"); var old = s.Scan(); File.Move(path, Path.Combine(s.Root, "after")); File.Delete(Path.Combine(s.Root, "removed")); var newer = s.Scan();
        var q = new DatabaseQueryService(s.Database); var result = q.CompareScans(old.ScanId, newer.ScanId); Assert.Equal(1, result["RENAMED"]); Assert.Equal(1, result["DELETED"]);
        Assert.True((bool)Integrity.VerifyDatabase(s.Database, scanId: old.ScanId)["valid"]!);
        var row = Assert.Single(q.SearchFiles(new() { ScanId = newer.ScanId, Status = "RENAMED" }).Rows); Assert.Equal("before", Path.GetFileName(q.GetPreviousVersion(row)!.CanonicalPath));
    }
    [Fact] public void CancelledExportRetainsExistingOutput()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); string output = Path.Combine(s.Home, "report.json"); File.WriteAllText(output, "original"); using var cancel = new CancellationTokenSource(); cancel.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => new DatabaseQueryService(s.Database).Export(new(), output, "json", cancel.Token)); Assert.Equal("original", File.ReadAllText(output)); Assert.Empty(Directory.GetFiles(s.Home, "*.tmp"));
        Assert.Throws<ArgumentException>(() => Integrity.ExportManifest(s.Database, s.Database));
    }
    [Fact] public void StructuralIntegrityDoesNotClaimCryptographicValidity()
    {
        using var s = new Sandbox(); s.Write("file"); s.Scan(); using (var db = EvidenceDatabase.Open(s.Database)) { using var c = db.CreateCommand(); c.CommandText = "UPDATE dw_files SET size=999"; c.ExecuteNonQuery(); }
        Assert.Equal("ok", new DatabaseQueryService(s.Database).CheckSqliteIntegrity()); Assert.False((bool)Integrity.VerifyDatabase(s.Database)["valid"]!);
    }
    [Fact] public void MigratedLegacyEvidenceRemainsVisibleUntilAModernScanExists()
    {
        using var s = new Sandbox(); using (var db = EvidenceDatabase.Open(s.Database)) { using var c = db.CreateCommand(); c.CommandText = "CREATE TABLE files(original_path BLOB,sha1 TEXT);INSERT INTO files VALUES($p,'abc')"; c.Parameters.AddWithValue("$p", EvidenceDatabase.Compress("C:/legacy")); c.ExecuteNonQuery(); }
        string upgraded = Path.Combine(s.Home, "upgraded.db"); Operations.MigrateLegacy(s.Database, upgraded);
        Assert.Equal("LEGACY", Assert.Single(new DatabaseQueryService(upgraded).SearchFiles(new()).Rows).Method);
    }
    [Fact] public async Task CliUsesSharedQueryExportAndHealthServices()
    {
        using var s = new Sandbox(); s.Write("file.txt"); var scan = s.Scan();
        var repository = new DirectoryInfo(AppContext.BaseDirectory); while (repository != null && !File.Exists(Path.Combine(repository.FullName, "DriveWitness.slnx"))) repository = repository.Parent; Assert.NotNull(repository);
        string configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent!.Name, cli = Path.Combine(repository.FullName, "src", "DriveWitness.Cli", "bin", configuration, "net10.0-windows10.0.22000.0", "drivewitness-cli.exe");
        async Task<JsonDocument> Run(params string[] args)
        {
            using var process = new Process { StartInfo = new(cli) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true } }; foreach (string argument in args.Concat(["--db", s.Database])) process.StartInfo.ArgumentList.Add(argument);
            process.Start(); var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync(); string error = await stderr; Assert.True(process.ExitCode == 0, error); return JsonDocument.Parse(await stdout);
        }
        using var found = await Run("search", "--extension", ".txt", "--limit", "1"); Assert.Equal(64, found.RootElement.GetProperty("records")[0].GetProperty("blake3").GetString()!.Length);
        using var health = await Run("health", "--integrity"); Assert.Equal("ok", health.RootElement.GetProperty("sqlite_integrity").GetString());
        string output = Path.Combine(s.Home, "records.jsonl"); using var exported = await Run("export", "--format", "jsonl", "--output", output); Assert.Contains("source_database", File.ReadAllText(output));
        using var verified = await Run("verify", "--scan-id", scan.ScanId.ToString()); Assert.True(verified.RootElement.GetProperty("valid").GetBoolean());
    }
}
