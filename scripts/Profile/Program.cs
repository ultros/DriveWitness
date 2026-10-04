using System.Diagnostics;
using System.Text.Json;
using DriveWitness.Core;

int count = args.Length > 0 ? int.Parse(args[0]) : 1_000_000;
string output = Path.GetFullPath(args.Length > 1 ? args[1] : "artifacts/explorer-performance.json");
if (count is < 1000 or > 10_000_000) throw new ArgumentException("Profile count must be 1,000–10,000,000.");
string temporary = Path.Combine(Path.GetTempPath(), "DriveWitness-profile-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temporary);
try
{
    string path = Path.Combine(temporary, "profile.db"); var build = Stopwatch.StartNew();
    using (var db = new EvidenceDatabase(path, false))
    {
        db.Execute("INSERT INTO dw_scans(id,schema_version,status,mode,scope) VALUES(1,2,'BENCHMARK','verify','synthetic query profile')");
        db.Begin(); db.Execute("""
          WITH RECURSIVE numbers(n) AS (SELECT 0 UNION ALL SELECT n+1 FROM numbers WHERE n+1<$p0)
          INSERT INTO dw_files(scan_id,canonical_path,volume_serial,file_id,size,modified_ns,blake3,sha256,status,method,sha256_provenance)
          SELECT 1,'C:/Profile/file-'||printf('%07d',n)||'.dat','PROFILE',printf('%032x',n),n*4096,1700000000000000000+n,
          CASE WHEN n=1234 THEN $p1 ELSE randomblob(32) END,randomblob(32),CASE WHEN n%100=0 THEN 'MODIFIED' ELSE 'UNCHANGED' END,'FULL_DUAL_HASH','RECALCULATED' FROM numbers
          """, count, Convert.FromHexString("fedcb".PadRight(64, '0')));
        db.Commit(); db.Checkpoint();
    }
    build.Stop();
    var service = new DatabaseQueryService(path); var observations = new List<object>();
    void Measure(string name, EvidenceQuery query, QueryCursor? cursor = null)
    {
        var rates = new List<double>(); int rows = 0; long largestManaged = 0; GC.Collect(); long before = GC.GetTotalMemory(true);
        for (int i = 0; i < 5; i++) { var timer = Stopwatch.StartNew(); var page = service.SearchFiles(query, cursor); rates.Add(timer.Elapsed.TotalMilliseconds); rows = page.Rows.Count; largestManaged = Math.Max(largestManaged, GC.GetTotalMemory(false) - before); }
        double first = rates[0]; rates.Sort(); observations.Add(new { name, median_ms = rates[2], first_ms = first, all_ms = rates, returned_records = rows, managed_allocation_peak_delta = largestManaged });
    }
    Measure("first window", new() { ScanId = 1 });
    string deepPath = $"C:/Profile/file-{count / 2:0000000}.dat"; Measure("deep keyset window", new() { ScanId = 1 }, new(deepPath, 1, deepPath));
    Measure("changed status", new() { ScanId = 1, Status = "MODIFIED" });
    Measure("indexed size sort", new() { ScanId = 1, Sort = "size", Descending = true });
    Measure("indexed modified sort", new() { ScanId = 1, Sort = "modified", Descending = true });
    Measure("indexed odd hash prefix", new() { Blake3 = "fedcb" });
    Measure("universal substring near end", new() { Search = $"file-{count - 1:0000000}" });
    bool cancelled = false; double cancellationMs; using (var cancel = new CancellationTokenSource())
    { cancel.CancelAfter(10); var timer = Stopwatch.StartNew(); try { service.SearchFiles(new() { Search = "no-match-profile" }, token: cancel.Token); } catch (OperationCanceledException) { cancelled = true; } cancellationMs = timer.Elapsed.TotalMilliseconds; }
    string export = Path.Combine(temporary, "records.jsonl"); var exportTime = Stopwatch.StartNew(); service.Export(new() { Status = "MODIFIED" }, export, "jsonl"); exportTime.Stop();
    var scanPairs = new List<object>();
    if (args.Length >= 4)
    {
        string oldCli = Path.GetFullPath(args[2]), newCli = Path.GetFullPath(args[3]); string root = Path.Combine(temporary, "data"); Directory.CreateDirectory(root); byte[] sample = new byte[4096]; new Random(0).NextBytes(sample);
        for (int i = 0; i < 5000; i++) File.WriteAllBytes(Path.Combine(root, "file-" + i), sample);
        string config = Path.Combine(temporary, "config.json"); new ScanOptions { Performance = 100, UsnEnabled = false }.Save(config);
        JsonElement Run(string executable, string db)
        {
            using var process = new Process { StartInfo = new(executable) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true } };
            foreach (string argument in new[] { "scan", root, "--db", db, "--mode", "verify", "--performance", "100", "--no-usn", "--config", config, "--quiet", "--json" }) process.StartInfo.ArgumentList.Add(argument);
            process.Start(); var stderr = process.StandardError.ReadToEndAsync(); string data = process.StandardOutput.ReadToEnd(); process.WaitForExit(); if (process.ExitCode != 0) throw new IOException(stderr.GetAwaiter().GetResult()); using var doc = JsonDocument.Parse(data); return doc.RootElement.Clone();
        }
        for (int i = 0; i < 5; i++)
        {
            var old = Run(oldCli, Path.Combine(temporary, $"old-{i}.db")); var newer = Run(newCli, Path.Combine(temporary, $"new-{i}.db"));
            scanPairs.Add(new { repeat = i, old_seconds = old.GetProperty("summary").GetProperty("elapsed_seconds").GetDouble(), new_seconds = newer.GetProperty("summary").GetProperty("elapsed_seconds").GetDouble(), old_timings = old.GetProperty("summary").GetProperty("timings"), new_timings = newer.GetProperty("summary").GetProperty("timings") });
        }
    }
    using var current = Process.GetCurrentProcess();
    var report = new { generated_utc = EvidenceDatabase.Utc(), records = count, database_bytes = new FileInfo(path).Length, fixture_creation_seconds = build.Elapsed.TotalSeconds,
        query_page_limit = 256, observations, cancellation_interrupted = cancelled, cancellation_ms = cancellationMs, export_changed_records = (count + 99) / 100, export_seconds = exportTime.Elapsed.TotalSeconds,
        process_working_set_bytes = current.WorkingSet64, managed_heap_bytes = GC.GetTotalMemory(true), scan_pairs = scanPairs,
        limitations = "Synthetic SQL fixture; local Windows filesystem cache; 5,000 × 4 KiB warm scan sample if CLI paths are supplied. Not a whole-volume claim. No GPU accelerator installed." };
    Directory.CreateDirectory(Path.GetDirectoryName(output)!); File.WriteAllText(output, JsonSerializer.Serialize(report, ScanOptions.Json)); Console.WriteLine(output);
}
finally
{
    string full = Path.GetFullPath(temporary), parent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
    if (Path.GetDirectoryName(full) != parent || !Path.GetFileName(full).StartsWith("DriveWitness-profile-", StringComparison.Ordinal)) throw new IOException("Unsafe profile cleanup path.");
    Directory.Delete(full, true);
}
