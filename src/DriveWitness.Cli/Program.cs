using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using DriveWitness.Core;

return await Cli.Run(args);

internal static class Cli
{
    private const string Help = """
      DriveWitness 3.1.1 — Windows 11
      DriveWitness by Jesse Lee Shelley · https://linkedin.com/in/jesse-shelley
      Project: https://github.com/ultros/DriveWitness · Free-Use No-Resale License
      drivewitness-cli list
      drivewitness-cli capabilities
      drivewitness-cli scan C: D: --db evidence.db --mode verify --performance 60
      drivewitness-cli verify evidence.db [--live] [--trusted-public-key public.raw]
      drivewitness-cli verify-manifest manifest.json [--trusted-public-key public.raw]
      drivewitness-cli compare baseline.db newer.db
      drivewitness-cli export evidence.db --output manifest.json
      drivewitness-cli errors evidence.db
      drivewitness-cli migrate legacy.db --output upgraded.db
      drivewitness-cli benchmark C:\Evidence [--save-settings]
      drivewitness-cli search --db evidence.db [--search TEXT] [--scan-id N] [--status STATUS]
      drivewitness-cli history --db evidence.db
      drivewitness-cli health --db evidence.db [--integrity]
      drivewitness-cli versions --db evidence.db --path CANONICAL_PATH --scan-id N
      drivewitness-cli compare-scans --db evidence.db --baseline-scan N --scan-id N
      drivewitness-cli export --db evidence.db --format csv|json|jsonl|html --output FILE
      drivewitness-cli verify-file --db evidence.db --path CANONICAL_PATH --scan-id N [--dual] [--persist]
      Evidence filters: --extension EXT --min-size BYTES --max-size BYTES --blake3 HEX_PREFIX
        --sha256 HEX_PREFIX --file-id ID --sort path|size|modified|created|status|scan
        --path-contains TEXT --modified-after UTC --modified-before UTC --created-after UTC --created-before UTC
        --hash-source RECALCULATED|CARRIED_FORWARD|SAME_SCAN_OBJECT
        --changed-only --duplicates --hash-mismatch --review flagged|reviewed|unreviewed --review-set NAME
        --limit 1..1024 --cursor FILE (JSON next cursor from a previous search)
      Scan options:
        --mode quick|verify|forensic  --performance 0..100  --gpu auto|off|force
        --workers 1..32  --blake3-threads 1..32  --large-file-threshold BYTES
        --db-batch-rows N  --db-commit-seconds N  --chunk-bytes N  --unstable-retries N
        --no-usn  --network-time  --include GLOB  --exclude GLOB
        --anonymize ROOT (repeatable) --anonymization-key KEYFILE (32+ bytes)
        --sign-key ED25519.pem [--sign-password-env VARIABLE]
        --resume (append a fresh pass to an existing database; no unverified work is skipped)
        --config FILE --json --quiet --log-file FILE
      --scan/--list aliases are supported. Ctrl+C retains partial evidence.
      Verify checks stored integrity; --live reads the original scope into a temporary
      forensic scan. An anonymized scope additionally requires --root/--anonymize and its key.
      """;
    public static async Task<int> Run(string[] input)
    {
        if (input.Length == 0 || input[0] is "--help" or "-h" or "help") { Console.WriteLine(Help); return 0; }
        if (input[0] is "--scan" or "--list") input[0] = input[0][2..];
        ScanControl? runningControl = null;
        try
        {
            NativeWindows.RequireWindows11();
            var arguments = new Arguments(input[1..]); string action = input[0];
            var control = new ScanControl(); runningControl = control; Console.CancelKeyPress += (_, e) => { e.Cancel = true; control.Cancel(); };
            ScanOptions options = ScanOptions.Load(arguments.One("config"));
            options = options with
            {
                Mode = arguments.One("mode") ?? options.Mode, Performance = arguments.Int("performance") ?? options.Performance,
                Gpu = arguments.Has("no-gpu") ? "off" : arguments.One("gpu") ?? options.Gpu, Workers = arguments.Int("workers") ?? options.Workers,
                Blake3Threads = arguments.Int("blake3-threads") ?? options.Blake3Threads,
                ChunkBytes = arguments.Int("chunk-bytes") ?? options.ChunkBytes,
                LargeFileThreshold = arguments.Long("large-file-threshold") ?? options.LargeFileThreshold,
                DbBatchRows = arguments.Int("db-batch-rows") ?? options.DbBatchRows, DbCommitSeconds = arguments.Double("db-commit-seconds") ?? options.DbCommitSeconds,
                UnstableRetries = arguments.Int("unstable-retries") ?? options.UnstableRetries,
                UsnEnabled = arguments.Has("no-usn") ? false : options.UsnEnabled, NetworkTime = arguments.Has("network-time") || options.NetworkTime
            };
            options.Validate();
            object? output;
            switch (action)
            {
                case "list": output = NativeWindows.Drives(); break;
                case "capabilities": output = await NativeWindows.CapabilitiesAsync(control.Token); break;
                case "scan":
                {
                    string database = arguments.One("db") ?? $"drive_witness_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{EvidenceDatabase.MachineId()[..12]}_{Guid.NewGuid().ToString("N")[..8]}.db";
                    if (arguments.Has("resume") && !File.Exists(database)) throw new ArgumentException("--resume requires an existing database.");
                    byte[]? key = ReadKey(arguments);
                    var paths = new PathPolicy(arguments.Positional, arguments.Many("anonymize"), key, arguments.Many("include"), arguments.Many("exclude"));
                    string? passwordVariable = arguments.One("sign-password-env");
                    string? password = passwordVariable == null ? null : Environment.GetEnvironmentVariable(passwordVariable) ?? throw new ArgumentException("The signing password environment variable is unset.");
                    var scanner = new Scanner(new(database, paths, options, arguments.One("sign-key"), password, IgnoredFiles: arguments.One("anonymization-key") is string keyPath ? [keyPath] : null), scanControl: control);
                    var scan = Task.Run(scanner.Run);
                    while (!scan.IsCompleted)
                    {
                        await Task.WhenAny(scan, Task.Delay(250)); var p = scanner.Progress;
                        if (p != null && !arguments.Has("quiet") && !arguments.Has("json")) Console.Error.Write($"\r{p.Status,-12} {p.Processed:N0}/{p.Discovered:N0} files  {p.ReadMbPerSecond:N1} MiB/s  {p.Errors} errors  {p.Budget.Label,-8}   ");
                    }
                    var result = await scan; if (!arguments.Has("quiet") && !arguments.Has("json")) Console.Error.WriteLine();
                    Emit(result, arguments); return result.Status == "COMPLETED" ? 0 : 130;
                }
                case "verify":
                {
                    string database = arguments.One("db") ?? arguments.Position(0);
                    var result = Integrity.VerifyDatabase(database, arguments.One("trusted-public-key") is string publicPath ? File.ReadAllBytes(publicPath) : null, arguments.Long("scan-id"), control.Token);
                    if (arguments.Has("live"))
                    {
                        if (result.ContainsKey("legacy")) result = Integrity.VerifyLegacyLive(database, control.Token);
                        else
                        {
                            if (!Equals(result.GetValueOrDefault("valid"), true)) { Emit(result, arguments); return 2; }
                            using var db = EvidenceDatabase.Open(database, true); using var command = db.CreateCommand();
                            long selectedScan = Convert.ToInt64(result["scan_id"]);
                            command.CommandText = "SELECT scope FROM dw_scans WHERE id=$scan"; command.Parameters.AddWithValue("$scan", selectedScan);
                            using var scope = JsonDocument.Parse((string)command.ExecuteScalar()!);
                            var roots = arguments.Many("root"); if (roots.Length == 0) roots = scope.RootElement.GetProperty("roots").EnumerateArray().Select(x => x.GetString()!).ToArray();
                            if (roots.Any(r => r.StartsWith("hmac-sha256:", StringComparison.Ordinal))) throw new ArgumentException("Supply the original --root, --anonymize and --anonymization-key for live anonymous verification.");
                            string temp = Path.Combine(Path.GetTempPath(), "DriveWitness-live-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(temp);
                            try
                            {
                                string snapshot = Path.Combine(temp, "live.db");
                                string[] Get(string field) => scope.RootElement.GetProperty(field).EnumerateArray().Select(x => x.GetString()!).ToArray();
                                var paths = new PathPolicy(roots, arguments.Many("anonymize"), ReadKey(arguments), Get("include"), Get("exclude"));
                                string[] ignored = new[] { "", "-wal", "-shm", ".lock", ".manifest.json", ".review.db", ".review.db-wal", ".review.db-shm" }.Select(s => Path.GetFullPath(database) + s).Concat(arguments.One("anonymization-key") is string keyPath ? [keyPath] : Array.Empty<string>()).ToArray();
                                var scan = new Scanner(new(snapshot, paths, options with { Mode = "forensic", UsnEnabled = false }, IgnoredFiles: ignored), scanControl: control).Run();
                                if (scan.Status != "COMPLETED") throw new OperationCanceledException();
                                var comparison = Operations.Compare(database, snapshot, selectedScan, scan.ScanId, control.Token);
                                result["live_comparison"] = comparison; result["valid"] = comparison.Where(p => p.Key != "unchanged").All(p => p.Value == 0);
                                result["scope"] = "Live disk inventory and content comparison";
                            }
                            finally { DeleteOwnedTemp(temp, "DriveWitness-live-"); }
                        }
                    }
                    Emit(result, arguments); return Equals(result.GetValueOrDefault("valid"), true) ? 0 : 2;
                }
                case "compare": output = Operations.Compare(arguments.Position(0), arguments.Position(1), token: control.Token); break;
                case "verify-manifest":
                {
                    var result = Integrity.VerifyManifestFile(arguments.Position(0), arguments.One("trusted-public-key") is string file ? File.ReadAllBytes(file) : null);
                    Emit(result, arguments); return Equals(result.GetValueOrDefault("valid"), true) ? 0 : 2;
                }
                case "export":
                {
                    string database = arguments.One("db") ?? arguments.Position(0), target = arguments.Required("output");
                    if (arguments.One("format") is string format) new DatabaseQueryService(database).Export(Query(arguments), target, format, control.Token);
                    else Integrity.ExportManifest(database, target, arguments.Long("scan-id"));
                    output = new { exported = Path.GetFullPath(target) }; break;
                }
                case "search":
                {
                    var query = Query(arguments); var service = new DatabaseQueryService(arguments.One("db") ?? arguments.Position(0));
                    QueryCursor? cursor = arguments.One("cursor") is string file ? JsonSerializer.Deserialize<QueryCursor>(File.ReadAllText(file), ScanOptions.Json) : null;
                    if (cursor?.SortValue is JsonElement scalar) cursor = cursor with { SortValue = scalar.ValueKind == JsonValueKind.Number ? (object)scalar.GetInt64() : scalar.GetString()! };
                    var page = service.SearchFiles(query, cursor, arguments.Int("limit") ?? 256, control.Token);
                    output = new { source_database = service.Database, query, records = page.Rows.Select(DatabaseQueryService.DisplayRecord), page.HasMore, page.Next }; break;
                }
                case "history": output = new DatabaseQueryService(arguments.One("db") ?? arguments.Position(0)).GetScans(control.Token); break;
                case "health":
                {
                    var service = new DatabaseQueryService(arguments.One("db") ?? arguments.Position(0)); var health = service.GetHealth(control.Token);
                    if (arguments.Has("integrity")) health["sqlite_integrity"] = service.CheckSqliteIntegrity(control.Token); output = health; break;
                }
                case "compare-scans": output = new DatabaseQueryService(arguments.One("db") ?? arguments.Position(0)).CompareScans(arguments.Long("baseline-scan") ?? throw new ArgumentException("--baseline-scan is required"), arguments.Long("scan-id") ?? throw new ArgumentException("--scan-id is required"), control.Token); break;
                case "versions":
                case "verify-file":
                {
                    var service = new DatabaseQueryService(arguments.One("db") ?? arguments.Position(0)); string path = arguments.Required("path");
                    var row = service.GetRecord(arguments.Long("scan-id") ?? throw new ArgumentException("--scan-id is required"), path, control.Token) ?? throw new ArgumentException("Observation not found.");
                    if (action == "versions") { var page = service.GetFileVersions(row, token: control.Token); output = new { records = page.Rows.Select(DatabaseQueryService.DisplayRecord), page.HasMore, page.Next }; }
                    else { var live = LiveFileComparison.Compare(row, arguments.Has("dual"), control); if (arguments.Has("persist")) new ReviewStore(service.Database).AppendVerification(row, live); output = live; }
                    break;
                }
                case "migrate": Operations.MigrateLegacy(arguments.Position(0), arguments.Required("output")); output = new { migrated = Path.GetFullPath(arguments.Required("output")), legacy_sha1_preserved = true }; break;
                case "errors":
                {
                    using var db = EvidenceDatabase.Open(arguments.Position(0), true); using var command = db.CreateCommand();
                    command.CommandText = "SELECT category,path,error_code,message FROM dw_events WHERE scan_id=(SELECT MAX(id) FROM dw_scans) ORDER BY id";
                    using var reader = command.ExecuteReader();
                    while (reader.Read()) Console.WriteLine(JsonSerializer.Serialize(new { category = reader.GetString(0), path = reader.IsDBNull(1) ? null : reader.GetString(1), code = reader.IsDBNull(2) ? null : reader.GetString(2), message = reader.IsDBNull(3) ? null : reader.GetString(3) }));
                    return 0;
                }
                case "benchmark":
                {
                    var report = Operations.Benchmark(arguments.Position(0), options, control.Token);
                    if (arguments.Has("save-settings")) { var cache = JsonSerializer.SerializeToElement(report, ScanOptions.Json); (options with { BenchmarkCache = cache }).Save(arguments.One("config")); }
                    output = report; break;
                }
                default: throw new ArgumentException("Unknown command: " + action);
            }
            Emit(output, arguments); return 0;
        }
        catch (OperationCanceledException) { Console.Error.WriteLine("Cancelled."); return 130; }
        catch (Microsoft.Data.Sqlite.SqliteException) when (runningControl?.Token.IsCancellationRequested == true) { Console.Error.WriteLine("Cancelled."); return 130; }
        catch (Exception ex) { Console.Error.WriteLine(ex.GetType().Name + ": " + ex.Message); return 1; }
    }
    private static byte[]? ReadKey(Arguments arguments) => arguments.One("anonymization-key") is string path ? File.ReadAllBytes(path) : null;
    private static EvidenceQuery Query(Arguments a) => new()
    {
        ScanId = a.Long("scan-id"), BaselineScanId = a.Long("baseline-scan"), Search = a.One("search") ?? "", Status = a.One("status"),
        Method = a.One("verification"), HashSource = a.One("hash-source"), PathContains = a.One("path-contains"), Extension = a.One("extension"), MinimumSize = a.Long("min-size"), MaximumSize = a.Long("max-size"),
        ModifiedAfterNs = QueryTime(a.One("modified-after")), ModifiedBeforeNs = QueryTime(a.One("modified-before")), CreatedAfterNs = QueryTime(a.One("created-after")), CreatedBeforeNs = QueryTime(a.One("created-before")),
        Blake3 = a.One("blake3"), Sha256 = a.One("sha256"), FileId = a.One("file-id"), VolumeSerial = a.One("volume-id"), Sort = a.One("sort") ?? "path",
        Descending = a.Has("descending"), ChangedOnly = a.Has("changed-only"), Duplicates = a.Has("duplicates"), HashMismatch = a.Has("hash-mismatch"), Review = a.One("review"), ReviewSet = a.One("review-set")
    };
    private static long? QueryTime(string? value) => value == null ? null : checked((DateTimeOffset.Parse(value, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal).UtcTicks - DateTime.UnixEpoch.Ticks) * 100);
    private static void Emit(object? result, Arguments arguments)
    {
        string json = JsonSerializer.Serialize(result, ScanOptions.Json); Console.WriteLine(json);
        if (arguments.One("log-file") is string file)
        {
            if (File.Exists(file) && new FileInfo(file).Length > 5 * 1024 * 1024) File.Move(file, file + ".1", true);
            File.AppendAllText(file, JsonSerializer.Serialize(new { time = EvidenceDatabase.Utc(), result }, new JsonSerializerOptions(ScanOptions.Json) { WriteIndented = false }) + Environment.NewLine);
        }
    }
    private static void DeleteOwnedTemp(string path, string prefix)
    {
        string full = Path.GetFullPath(path);
        if (Path.GetDirectoryName(full) != Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar) || !Path.GetFileName(full).StartsWith(prefix, StringComparison.Ordinal)) throw new IOException("Temporary cleanup path check failed.");
        Directory.Delete(full, true);
    }
    private sealed class Arguments
    {
        private readonly Dictionary<string, List<string>> values = new();
        public List<string> Positional { get; } = [];
        public Arguments(string[] input)
        {
            string[] flags = ["json", "quiet", "no-usn", "no-gpu", "network-time", "resume", "live", "save-settings", "integrity", "dual", "persist", "descending", "changed-only", "duplicates", "hash-mismatch"];
            string[] parameters = ["db", "mode", "performance", "gpu", "workers", "blake3-threads", "large-file-threshold", "chunk-bytes", "db-batch-rows", "db-commit-seconds", "unstable-retries", "include", "exclude", "root", "anonymize", "anonymization-key", "sign-key", "sign-password-env", "trusted-public-key", "output", "config", "log-file", "scan-id", "baseline-scan", "search", "status", "verification", "hash-source", "path-contains", "modified-after", "modified-before", "created-after", "created-before", "extension", "min-size", "max-size", "blake3", "sha256", "file-id", "volume-id", "sort", "review", "review-set", "limit", "cursor", "format", "path"];
            for (int i = 0; i < input.Length; i++)
            {
                string argument = input[i]; if (!argument.StartsWith("--", StringComparison.Ordinal)) { Positional.Add(argument); continue; }
                string name = argument[2..]; string value;
                if (flags.Contains(name)) value = "true";
                else if (parameters.Contains(name)) { if (++i >= input.Length || input[i].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException("Missing value for --" + name); value = input[i]; }
                else throw new ArgumentException("Unknown option: " + argument);
                if (!values.TryGetValue(name, out var list)) values[name] = list = [];
                list.Add(value);
            }
        }
        public bool Has(string name) => values.ContainsKey(name);
        public string? One(string name) => values.TryGetValue(name, out var list) ? list.Count == 1 ? list[0] : throw new ArgumentException("Repeated option --" + name) : null;
        public string Required(string name) => One(name) ?? throw new ArgumentException("Missing --" + name);
        public string[] Many(string name) => values.TryGetValue(name, out var list) ? list.ToArray() : [];
        public string Position(int index) => Positional.Count > index ? Positional[index] : throw new ArgumentException("Missing path argument.");
        public int? Int(string name) => One(name) is string value ? int.Parse(value, System.Globalization.CultureInfo.InvariantCulture) : null;
        public long? Long(string name) => One(name) is string value ? long.Parse(value, System.Globalization.CultureInfo.InvariantCulture) : null;
        public double? Double(string name) => One(name) is string value ? double.Parse(value, System.Globalization.CultureInfo.InvariantCulture) : null;
    }
}
