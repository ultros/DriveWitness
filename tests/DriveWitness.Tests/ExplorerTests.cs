using System.Security.Cryptography;
using System.Diagnostics;
using System.Text.Json;
using DriveWitness.Core;
using Xunit;

namespace DriveWitness.Tests;

public sealed class ExplorerTests
{
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
