using System.Diagnostics;

namespace DriveWitness.Core;

public sealed record FileRecord
{
    public long ScanId { get; set; }
    public string CanonicalPath { get; set; } = "";
    public byte[]? OriginalPath { get; set; }
    public string? VolumeSerial { get; set; }
    public string? FileId { get; set; }
    public long? Size { get; set; }
    public long? CreatedNs { get; set; }
    public long? ModifiedNs { get; set; }
    public long? AccessedNs { get; set; }
    public long? Attributes { get; set; }
    public byte[]? Blake3 { get; set; }
    public byte[]? Sha256 { get; set; }
    public string? LegacySha1 { get; set; }
    public string? Method { get; set; }
    public string? Status { get; set; }
    public long? Sha256OriginScan { get; set; }
    public string? Sha256Provenance { get; set; }
    public string? ErrorCode { get; set; }
    public string? ErrorMessage { get; set; }
    public long? HardlinkCount { get; set; }
    public long? FirstSeenScan { get; set; }
    public long? LastSeenScan { get; set; }
    public byte[]? CreatedUtc { get; set; }
    public byte[]? ModifiedUtc { get; set; }
    public byte[]? AccessedUtc { get; set; }
    public byte[]? ScanTime { get; set; }
    public static readonly string[] Columns = ["scan_id", "canonical_path", "original_path", "volume_serial", "file_id", "size", "created_ns", "modified_ns", "accessed_ns", "attributes", "blake3", "sha256", "legacy_sha1", "method", "status", "sha256_origin_scan", "sha256_provenance", "error_code", "error_message", "hardlink_count", "first_seen_scan", "last_seen_scan", "created_utc", "modified_utc", "accessed_utc", "scan_time"];
    public object?[] Values() => [ScanId, CanonicalPath, OriginalPath, VolumeSerial, FileId, Size, CreatedNs, ModifiedNs, AccessedNs,
        Attributes, Blake3, Sha256, LegacySha1, Method, Status, Sha256OriginScan, Sha256Provenance, ErrorCode, ErrorMessage,
        HardlinkCount, FirstSeenScan, LastSeenScan, CreatedUtc, ModifiedUtc, AccessedUtc, ScanTime];
}

public sealed record ScanProgress(string Status, string CurrentPath, long Discovered, long Processed, long Added,
    long Modified, long Deleted, long Renamed, long Unstable, long Errors, long Skipped, long Directories,
    long BytesRead, long Sha256Files, double ElapsedSeconds, double ReadMbPerSecond, double FilesPerSecond,
    double ProcessCpuPercent, int HashQueue, int DbQueue, int ActiveWorkers, BudgetSnapshot Budget,
    Dictionary<string, double> Timings);
public sealed record ScanResult(long ScanId, string Database, string Status, ScanProgress Summary, string? ManifestExportError = null);

public sealed class ScanCounters : IDisposable
{
    public long Discovered, Processed, Added, Modified, Deleted, Renamed, Unstable, Errors, Skipped, Directories, BytesRead, Sha256Files;
    public bool CoverageIncomplete;
    public string Status = "STARTING", CurrentPath = "";
    private readonly Stopwatch elapsed = Stopwatch.StartNew();
    private readonly Queue<(double Time, long Bytes, long Files)> samples = new();
    private readonly Dictionary<string, double> times = new();
    private readonly Process process = Process.GetCurrentProcess();
    private double lastCpu, lastTime;
    public void Dispose() => process.Dispose();
    public void AddTimings(Dictionary<string, double> data) { foreach (var pair in data) AddTime(pair.Key, pair.Value); }
    public void AddTime(string name, double seconds) => times[name] = times.GetValueOrDefault(name) + seconds;
    public ScanProgress Snapshot(ResourceBudget budget, int hashQueue = 0, int dbQueue = 0, int active = 0)
    {
        double now = elapsed.Elapsed.TotalSeconds;
        long bytes = Interlocked.Read(ref BytesRead), files = Interlocked.Read(ref Processed);
        samples.Enqueue((now, bytes, files)); while (samples.Count > 20) samples.Dequeue();
        var first = samples.Peek(); double delta = Math.Max(.001, now - first.Time);
        double cpu = process.TotalProcessorTime.TotalSeconds;
        double usage = Math.Clamp(100 * (cpu - lastCpu) / Math.Max(.001, now - lastTime) / Environment.ProcessorCount, 0, 100);
        lastCpu = cpu; lastTime = now;
        return new(Status, CurrentPath, Interlocked.Read(ref Discovered), files, Added, Modified, Deleted, Renamed, Unstable,
            Errors, Skipped, Interlocked.Read(ref Directories), bytes, Sha256Files, now, (bytes - first.Bytes) / delta / 1048576,
            (files - first.Files) / delta, usage, hashQueue, dbQueue, active, budget.Snapshot(), new(times));
    }
}
