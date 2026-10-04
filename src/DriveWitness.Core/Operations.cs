using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Blake3;

namespace DriveWitness.Core;

public static class Operations
{
    public static Dictionary<string, long> Compare(string baseline, string newer, long? baselineScanId = null, long? currentScanId = null, CancellationToken token = default)
    {
        using var connection = EvidenceDatabase.Open(newer, true, enableUri: true);
        using var cancellation = token.Register(() => SQLitePCL.raw.sqlite3_interrupt(connection.Handle)); token.ThrowIfCancellationRequested();
        using var command = connection.CreateCommand();
        command.CommandText = "PRAGMA temp_store=FILE; ATTACH DATABASE $old AS baseline";
        command.Parameters.AddWithValue("$old", new Uri(Path.GetFullPath(baseline)).AbsoluteUri + "?mode=ro"); command.ExecuteNonQuery(); command.Parameters.Clear();
        long Id(string schema, long? selected)
        { command.CommandText = selected == null ? $"SELECT MAX(id) FROM {schema}.dw_scans WHERE status='COMPLETED'" : $"SELECT id FROM {schema}.dw_scans WHERE status='COMPLETED' AND id={selected}"; object? value = command.ExecuteScalar(); return value is null or DBNull ? throw new InvalidOperationException("Comparison requires completed scans.") : Convert.ToInt64(value); }
        long old = Id("baseline", baselineScanId), next = Id("main", currentScanId);
        string Scope(string schema, long id) { command.CommandText = $"SELECT scope FROM {schema}.dw_scans WHERE id={id}"; return (string)command.ExecuteScalar()!; }
        if (Scope("baseline", old) != Scope("main", next)) throw new ArgumentException("Comparison scopes/anonymization keys differ.");
        command.CommandText = "CREATE TEMP TABLE pairs(old_path TEXT PRIMARY KEY,new_path TEXT UNIQUE,old_hash BLOB,new_hash BLOB)"; command.ExecuteNonQuery();
        command.CommandText = """
          WITH old_missing AS (
           SELECT a.*,ROW_NUMBER() OVER(PARTITION BY a.volume_serial,a.file_id ORDER BY a.canonical_path) rank
           FROM baseline.dw_files a WHERE a.scan_id=$old AND a.status NOT IN ('DELETED','ERROR','UNSTABLE','UNVERIFIED')
           AND NOT EXISTS(SELECT 1 FROM dw_files b WHERE b.scan_id=$next AND b.status!='DELETED' AND b.canonical_path=a.canonical_path)),
          new_only AS (
           SELECT b.*,ROW_NUMBER() OVER(PARTITION BY b.volume_serial,b.file_id ORDER BY b.canonical_path) rank
           FROM dw_files b WHERE b.scan_id=$next AND b.status NOT IN ('DELETED','ERROR','UNSTABLE','UNVERIFIED')
           AND NOT EXISTS(SELECT 1 FROM baseline.dw_files a WHERE a.scan_id=$old AND a.status!='DELETED' AND a.canonical_path=b.canonical_path))
          INSERT INTO pairs SELECT a.canonical_path,b.canonical_path,a.blake3,b.blake3
          FROM old_missing a JOIN new_only b ON a.volume_serial=b.volume_serial AND a.file_id=b.file_id AND a.rank=b.rank
          """;
        command.Parameters.AddWithValue("$old", old); command.Parameters.AddWithValue("$next", next); command.ExecuteNonQuery();
        long Count(string sql) { command.CommandText = sql; return Convert.ToInt64(command.ExecuteScalar()); }
        var counts = new Dictionary<string, long> { ["added"] = 0, ["deleted"] = 0, ["modified"] = Count("SELECT COUNT(*) FROM pairs WHERE old_hash!=new_hash"), ["unchanged"] = 0, ["renamed"] = Count("SELECT COUNT(*) FROM pairs"), ["unverified"] = 0 };
        command.CommandText = """
          SELECT a.blake3,b.blake3,a.canonical_path,b.canonical_path,a.status,b.status,a.volume_serial,b.volume_serial,a.file_id,b.file_id,
          EXISTS(SELECT 1 FROM pairs WHERE old_path=a.canonical_path) FROM
          (SELECT * FROM baseline.dw_files WHERE scan_id=$old AND status!='DELETED') a
          LEFT JOIN (SELECT * FROM dw_files WHERE scan_id=$next AND status!='DELETED') b ON a.canonical_path=b.canonical_path
          UNION ALL SELECT NULL,b.blake3,NULL,b.canonical_path,NULL,b.status,NULL,b.volume_serial,NULL,b.file_id,
          EXISTS(SELECT 1 FROM pairs WHERE new_path=b.canonical_path) FROM dw_files b WHERE b.scan_id=$next AND b.status!='DELETED'
          AND NOT EXISTS(SELECT 1 FROM baseline.dw_files a WHERE a.scan_id=$old AND a.status!='DELETED' AND a.canonical_path=b.canonical_path)
          """;
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            if (reader.GetBoolean(10)) continue;
            string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);
            bool uncertain = new[] { Text(4), Text(5) }.Any(s => s is "ERROR" or "UNSTABLE" or "UNVERIFIED");
            string label = uncertain ? "unverified" : reader.IsDBNull(2) ? "added" : reader.IsDBNull(3) ? "deleted" :
                !reader.IsDBNull(0) && !reader.IsDBNull(1) && ((byte[])reader.GetValue(0)).AsSpan().SequenceEqual((byte[])reader.GetValue(1)) && Text(6) == Text(7) && Text(8) == Text(9) ? "unchanged" : "modified";
            counts[label]++;
        }
        return counts;
    }

    public static void MigrateLegacy(string source, string output)
    {
        if (Path.GetFullPath(source).Equals(Path.GetFullPath(output), StringComparison.OrdinalIgnoreCase) || File.Exists(output)) throw new ArgumentException("Migration output must be a new database path.");
        using (var input = EvidenceDatabase.Open(source, true))
        using (var destination = EvidenceDatabase.Open(output)) input.BackupDatabase(destination);
        using var evidenceLock = new EvidenceLock(output);
        using var upgraded = new EvidenceDatabase(output, true); upgraded.Checkpoint();
        // The original SHA-1 tables remain authoritative legacy observations. New scans append v2 tables.
    }

    public static Dictionary<string, object?> Benchmark(string root, ScanOptions options, CancellationToken token = default)
    {
        NativeWindows.RequireWindows11(); options.Validate(); CpuHashBackend.Initialize(options);
        root = PathPolicy.NormalizeRoot(root);
        var files = new List<(string Path, long Size)>(); long remaining = 64 * 1024 * 1024; int inspected = 0;
        var enumeration = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System };
        foreach (string path in Directory.EnumerateFiles(NativeWindows.Extended(root), "*", enumeration))
        {
            token.ThrowIfCancellationRequested(); if (inspected++ >= 20000 || files.Count >= 16) break;
            try { long size = new FileInfo(path).Length; if (size > 0 && size <= remaining) { files.Add((path, size)); remaining -= size; } }
            catch (IOException) { }
            if (remaining == 0) break;
        }
        byte[] sample = new byte[8 * 1024 * 1024]; new Random(0).NextBytes(sample);
        double Measure(Action action) { token.ThrowIfCancellationRequested(); long t = Stopwatch.GetTimestamp(); for (int i = 0; i < 8; i++) { token.ThrowIfCancellationRequested(); action(); } return 64 / Math.Max(.000001, Stopwatch.GetElapsedTime(t).TotalSeconds); }
        var cpu = new Dictionary<string, double>
        {
            ["blake3_single_mib_s"] = Measure(() => CpuHashBackend.Digest(sample)),
            ["blake3_parallel_mib_s"] = Measure(() => { using var h = Hasher.New(); h.UpdateWithJoin(sample); byte[] digest = new byte[32]; h.Finalize(digest); }),
            ["sha256_mib_s"] = Measure(() => SHA256.HashData(sample)),
            ["dual_hash_mib_s"] = Measure(() => { CpuHashBackend.Digest(sample); SHA256.HashData(sample); })
        };
        var workerResults = new Dictionary<int, double>(); long readBytes = 0, sampleErrors = 0;
        (long Bytes, double Rate) Read(int workers, bool hash)
        {
            long t = Stopwatch.GetTimestamp(); long bytes = 0;
            Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = workers, CancellationToken = token }, sampleFile =>
            {
                try
                {
                    using var stream = NativeWindows.OpenContent(sampleFile.Path); byte[] buffer = new byte[1024 * 1024]; int count; long left = sampleFile.Size;
                    using var primary = Hasher.New(); using var secondary = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    while (left > 0 && (count = stream.Read(buffer, 0, (int)Math.Min(buffer.Length, left))) > 0)
                    { left -= count; token.ThrowIfCancellationRequested(); Interlocked.Add(ref bytes, count); if (hash) { primary.Update(buffer.AsSpan(0, count)); secondary.AppendData(buffer, 0, count); } }
                    if (hash) { byte[] digest = new byte[32]; primary.Finalize(digest); secondary.GetHashAndReset(); }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception) { Interlocked.Increment(ref sampleErrors); }
            });
            return (bytes, bytes / 1048576d / Math.Max(.000001, Stopwatch.GetElapsedTime(t).TotalSeconds));
        }
        Read(1, false); // Warm the code path; observations still include the OS cache.
        var sequential = Read(1, false);
        foreach (int workers in new[] { 1, 2, 4, 8 }.Where(w => w <= Environment.ProcessorCount))
        {
            var rates = new List<double>();
            for (int repeat = 0; repeat < 3; repeat++) { var reading = Read(workers, true); readBytes = reading.Bytes; rates.Add(reading.Rate); }
            rates.Sort(); workerResults[workers] = rates[1];
        }
        double dbRows; string temp = Path.Combine(Path.GetTempPath(), "DriveWitness-benchmark-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp);
        try
        {
            using var db = new EvidenceDatabase(Path.Combine(temp, "benchmark.db"), false);
            db.Execute("INSERT INTO dw_scans(id,schema_version,status) VALUES(1,2,'BENCHMARK')");
            var batch = Enumerable.Range(0, 5000).Select(i => new FileRecord { ScanId = 1, CanonicalPath = "benchmark/" + i, OriginalPath = EvidenceDatabase.Compress("benchmark/" + i), Size = 4096, Blake3 = new byte[32], Sha256 = new byte[32], Status = "ADDED", Method = "BENCHMARK" }).ToList();
            long t = Stopwatch.GetTimestamp(); db.InsertBatch(batch); db.Commit(); dbRows = 5000 / Stopwatch.GetElapsedTime(t).TotalSeconds;
        }
        finally
        {
            string full = Path.GetFullPath(temp);
            if (Path.GetDirectoryName(full) != Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) || !Path.GetFileName(full).StartsWith("DriveWitness-benchmark-", StringComparison.Ordinal)) throw new IOException("Unsafe benchmark cleanup path.");
            Directory.Delete(full, true);
        }
        double fastest = workerResults.Values.DefaultIfEmpty(0).Max();
        int recommendation = files.Count < 2 || readBytes < 1048576 ? 1 : workerResults.Where(p => p.Value >= fastest * .85).Select(p => p.Key).DefaultIfEmpty(1).Min();
        return new() { ["time"] = EvidenceDatabase.Utc(), ["volume"] = NativeWindows.Volume(root), ["sample_files"] = files.Count, ["sample_bytes"] = readBytes,
            ["cpu"] = cpu, ["sequential_read_mib_s"] = sequential.Rate, ["dual_hash_worker_mib_s"] = workerResults, ["sample_errors"] = sampleErrors, ["sqlite_rows_per_second"] = dbRows,
            ["recommendation"] = new { workers = recommendation, blake3_threads = CpuHashBackend.ThreadCap, large_file_threshold = 64 * 1024 * 1024, gpu = "off" },
            ["limitations"] = "Read measurements include Windows filesystem cache. No GPU hashing backend is installed. A bounded sample may not represent the entire drive." };
    }
}
