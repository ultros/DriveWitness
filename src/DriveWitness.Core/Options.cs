using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DriveWitness.Core;

public sealed record ScanOptions
{
    public int Version { get; init; } = 1;
    public int Performance { get; init; } = 60;
    public string Mode { get; init; } = "verify";
    public string Gpu { get; init; } = "auto";
    public int? Workers { get; init; }
    public int? Blake3Threads { get; init; }
    public long LargeFileThreshold { get; init; } = 64 * 1024 * 1024;
    public int ChunkBytes { get; init; } = 1024 * 1024;
    public int DbBatchRows { get; init; } = 2000;
    public double DbCommitSeconds { get; init; } = 2;
    public int UnstableRetries { get; init; } = 1;
    public bool UsnEnabled { get; init; } = true;
    public bool NetworkTime { get; init; }
    public string Storage { get; init; } = "unknown";
    public JsonElement? BenchmarkCache { get; init; }

    public ScanOptions Validate()
    {
        if (Version != 1) throw new ArgumentException("Unsupported configuration version.");
        if (Performance is < 0 or > 100) throw new ArgumentException("Performance must be 0–100.");
        if (Mode is not ("quick" or "verify" or "forensic")) throw new ArgumentException("Invalid scan mode.");
        if (Gpu is not ("auto" or "off" or "force")) throw new ArgumentException("Invalid GPU mode.");
        if (Workers is < 1 or > 32 || Blake3Threads is < 1 or > 32) throw new ArgumentException("Workers/threads must be 1–32.");
        if (ChunkBytes is < 65536 or > 16777216 || LargeFileThreshold < ChunkBytes) throw new ArgumentException("Invalid chunk/large-file threshold.");
        if (DbBatchRows is < 1 or > 10000 || !double.IsFinite(DbCommitSeconds) || DbCommitSeconds is < .1 or > 10 || UnstableRetries is < 0 or > 5)
            throw new ArgumentException("Invalid commit/retry configuration.");
        if (Storage is not ("unknown" or "hdd" or "ssd" or "nvme" or "remote")) throw new ArgumentException("Invalid storage strategy.");
        return this;
    }

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Skip
    };
    public static string SettingsPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DriveWitness", "csharp-config.json");
    public static ScanOptions Load(string? path = null) => File.Exists(path ?? SettingsPath)
        ? (JsonSerializer.Deserialize<ScanOptions>(File.ReadAllText(path ?? SettingsPath), Json) ?? new()).Validate() : new();
    public void Save(string? path = null)
    {
        Validate();
        path ??= SettingsPath;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        string temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temp, JsonSerializer.Serialize(this, Json)); File.Move(temp, path, true); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}

public sealed record BudgetSnapshot(int Level, string Label, int Workers, int LargeThreads, int QueueDepth, int DelayMilliseconds, string Storage);

public sealed class ResourceBudget(ScanOptions options)
{
    private int level = options.Performance;
    public int Limit { get; } = Math.Clamp(Environment.ProcessorCount, 1, 32);
    public string Storage { get; set; } = options.Storage;
    public void Set(int value) => Volatile.Write(ref level, Math.Clamp(value, 0, 100));
    public BudgetSnapshot Snapshot()
    {
        int value = Volatile.Read(ref level);
        string label = value <= 20 ? "Quiet" : value <= 45 ? "Low" : value <= 70 ? "Balanced" : value <= 90 ? "Fast" : "Maximum";
        int cap = Storage switch { "hdd" or "remote" => 2, "ssd" => 8, "nvme" => 16, _ => 4 };
        int workers = Math.Min(Limit, options.Workers ?? (value <= 20 ? 1 : 1 + value * (cap - 1) / 100));
        int threads = value <= 45 ? 1 : CpuHashBackend.ThreadCap;
        return new(value, label, workers, threads, Math.Max(4, workers * 4), Math.Max(0, 25 - value), Storage);
    }
}

public sealed class ScanControl
{
    private int paused;
    private readonly CancellationTokenSource cancellation = new();
    public CancellationToken Token => cancellation.Token;
    public bool IsPaused => Volatile.Read(ref paused) != 0;
    public void Pause() => Volatile.Write(ref paused, 1);
    public void Resume() => Volatile.Write(ref paused, 0);
    public void Cancel() { cancellation.Cancel(); Resume(); }
    public void Check()
    {
        Token.ThrowIfCancellationRequested();
        while (IsPaused) { if (Token.WaitHandle.WaitOne(40)) Token.ThrowIfCancellationRequested(); }
    }
    public void Pace(int milliseconds)
    {
        Check();
        if (milliseconds > 0 && Token.WaitHandle.WaitOne(milliseconds)) Token.ThrowIfCancellationRequested();
    }
}

public sealed class PathPolicy
{
    public string[] Roots { get; }
    public string[] AnonymousRoots { get; }
    private readonly byte[]? key;
    public string[] Includes { get; }
    public string[] Excludes { get; }
    public PathPolicy(IEnumerable<string> roots, IEnumerable<string>? anonymous = null, byte[]? key = null,
        IEnumerable<string>? includes = null, IEnumerable<string>? excludes = null)
    {
        Roots = roots.Select(NormalizeRoot).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        AnonymousRoots = (anonymous ?? []).Select(NormalizeRoot).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        this.key = key;
        if (Roots.Length == 0) throw new ArgumentException("Select an existing drive or directory.");
        if (AnonymousRoots.Length != 0 && (key == null || key.Length < 32)) throw new ArgumentException("Anonymization requires a 32+ byte external key file.");
        for (int i = 0; i < Roots.Length; i++)
            if (Roots.Where((_, j) => i != j).Any(other => IsWithin(Roots[i], other))) throw new ArgumentException("Selected roots overlap.");
        Includes = (includes ?? []).Order(StringComparer.Ordinal).ToArray();
        Excludes = (excludes ?? []).Order(StringComparer.Ordinal).ToArray();
    }
    public static string NormalizeRoot(string path)
    {
        if (path.Length == 2 && path[1] == ':') path += "\\";
        path = Path.GetFullPath(path);
        if (!Directory.Exists(path)) throw new ArgumentException("Scan roots must be existing directories.");
        if ((File.GetAttributes(NativeWindows.Extended(path)) & FileAttributes.ReparsePoint) != 0) throw new ArgumentException("A scan root must not be a junction or reparse point; select its explicit target directory.");
        return NativeWindows.FinalPath(path);
    }
    public static string Canonical(string path)
    {
        path = Path.GetFullPath(path);
        if (path.StartsWith(@"\\?\UNC\", StringComparison.Ordinal)) path = @"\\" + path[8..];
        else if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) path = path[4..];
        return path.Replace('\\', '/');
    }
    public static bool IsWithin(string path, string root)
    {
        path = Canonical(path); root = Canonical(root).TrimEnd('/');
        return path == root || path.StartsWith(root + "/", StringComparison.Ordinal);
    }
    public bool Anonymous(string path) => AnonymousRoots.Any(root => IsWithin(path, root));
    public string Stored(string path) => Anonymous(path) ? "hmac-sha256:" + Convert.ToHexStringLower(HMACSHA256.HashData(key!, Encoding.UTF8.GetBytes(Canonical(path)))) : Canonical(path);
    public string Scope => CanonicalJson.String(new Dictionary<string, object?>
    {
        ["roots"] = Roots.Select(Stored).ToArray(), ["anonymize"] = AnonymousRoots.Select(Stored).Order(StringComparer.Ordinal).ToArray(),
        ["exclude"] = Excludes, ["include"] = Includes,
        ["key_id"] = AnonymousRoots.Length != 0 ? Convert.ToHexStringLower(SHA256.HashData(key!)) : null
    });
}
