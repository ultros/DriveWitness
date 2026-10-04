using System.Globalization;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace DriveWitness.Core;

public sealed record EvidenceQuery
{
    public long? ScanId { get; init; }
    public string Search { get; init; } = "";
    public string? Status { get; init; }
    public string? Method { get; init; }
    public string? Extension { get; init; }
    public string? PathContains { get; init; }
    public long? MinimumSize { get; init; }
    public long? MaximumSize { get; init; }
    public long? ModifiedAfterNs { get; init; }
    public string? Blake3 { get; init; }
    public string? Sha256 { get; init; }
    public string? FileId { get; init; }
    public string? VolumeSerial { get; init; }
    public bool ChangedOnly { get; init; }
    public bool Duplicates { get; init; }
    public string? Review { get; init; }
    public string? ReviewSet { get; init; }
    public long? BaselineScanId { get; init; }
    public string Sort { get; init; } = "path";
    public bool Descending { get; init; }
}

public sealed record QueryCursor(object SortValue, long ScanId, string Path);
public sealed record EvidencePage(IReadOnlyList<FileRecord> Rows, bool HasMore, QueryCursor? Next);
public sealed record EvidenceEvent(long Id, long ScanId, string Time, string Category, string? Path, string? ErrorCode, string? Message);
public sealed record ScanEntry(long Id, string Started, string Completed, string Mode, string Status,
    string Scope, string Root, string Summary, string Manifest)
{
    public override string ToString() => $"{Started.Replace('T', ' ')[..Math.Min(19, Started.Length)]} · {Mode} · #{Id} · {Status}";
}

/// <summary>Read-only, bounded SQLite queries shared by the GUI and CLI. Call on a worker thread.</summary>
public sealed class DatabaseQueryService(string database)
{
    public string Database { get; } = Path.GetFullPath(database);
    private static readonly Dictionary<string, string> Sorts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["path"] = "canonical_path", ["scan"] = "scan_id", ["size"] = "COALESCE(size,-1)",
        ["modified"] = "COALESCE(modified_ns,-1)", ["created"] = "COALESCE(created_ns,-1)",
        ["status"] = "COALESCE(status,'')", ["verification"] = "COALESCE(method,'')"
    };

    private SqliteConnection Open()
    {
        var db = EvidenceDatabase.Open(Database, true, enableUri: true);
        db.CreateFunction<byte[], string?>("dw_text", EvidenceDatabase.Decompress, isDeterministic: true);
        using var command = db.CreateCommand();
        command.CommandText = "PRAGMA query_only=ON; PRAGMA temp_store=FILE; PRAGMA cache_size=-8192";
        command.ExecuteNonQuery(); return db;
    }
    private static bool HasTable(SqliteConnection db, string name)
    {
        using var c = db.CreateCommand(); c.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$name";
        c.Parameters.AddWithValue("$name", name); return c.ExecuteScalar() != null;
    }
    private static bool Modern(SqliteConnection db) => HasTable(db, "dw_files");
    private static bool Legacy(SqliteConnection db)
    {
        if (!HasTable(db, "files")) return false;
        if (!Modern(db)) return true;
        using var c = db.CreateCommand(); c.CommandText = "SELECT 1 FROM dw_scans LIMIT 1"; return c.ExecuteScalar() == null;
    }
    private static string Source(SqliteConnection db)
    {
        if (Modern(db) && !Legacy(db)) return "dw_files";
        if (!HasTable(db, "files")) throw new InvalidDataException("This is not a DriveWitness evidence database.");
        // Legacy compressed paths stay compressed on disk. SQL decodes only for the requested query.
        return "(SELECT 0 AS scan_id, dw_text(original_path) AS canonical_path, original_path, " +
            "NULL AS volume_serial,NULL AS file_id,NULL AS size,NULL AS created_ns,NULL AS modified_ns,NULL AS accessed_ns," +
            "NULL AS attributes,NULL AS blake3,NULL AS sha256,sha1 AS legacy_sha1,'LEGACY' AS method,'LEGACY' AS status," +
            "NULL AS sha256_origin_scan,'LEGACY' AS sha256_provenance,NULL AS error_code,NULL AS error_message," +
            "NULL AS hardlink_count,NULL AS first_seen_scan,NULL AS last_seen_scan,NULL AS created_utc,NULL AS modified_utc," +
            "NULL AS accessed_utc,NULL AS scan_time FROM files)";
    }
    private static CancellationTokenRegistration Interrupt(SqliteConnection db, CancellationToken token)
        => token.Register(() => SQLitePCL.raw.sqlite3_interrupt(db.Handle));
    private static string Where(SqliteCommand c, EvidenceQuery q)
    {
        var parts = new List<string>();
        string Param(object value) { string key = "$q" + c.Parameters.Count; c.Parameters.AddWithValue(key, value); return key; }
        void Equal(string field, object? value) { if (value != null) parts.Add(field + "=" + Param(value)); }
        Equal("scan_id", q.ScanId); Equal("status", q.Status); Equal("method", q.Method);
        Equal("file_id", q.FileId); Equal("volume_serial", q.VolumeSerial);
        if (q.MinimumSize != null) parts.Add("size>=" + Param(q.MinimumSize));
        if (q.MaximumSize != null) parts.Add("size<=" + Param(q.MaximumSize));
        if (q.ModifiedAfterNs != null) parts.Add("modified_ns>=" + Param(q.ModifiedAfterNs));
        if (q.PathContains is { Length: > 0 }) parts.Add("instr(lower(canonical_path),lower(" + Param(q.PathContains) + "))>0");
        if (q.Extension is { Length: > 0 }) parts.Add("substr(lower(canonical_path),-length(" + Param(q.Extension) + "))=lower(" + Param(q.Extension) + ")");
        void Hash(string column, string? digest)
        {
            if (string.IsNullOrWhiteSpace(digest)) return;
            if (digest.Length > 64 || !digest.All(Uri.IsHexDigit)) throw new ArgumentException("Digest must contain hexadecimal characters, up to 64.");
            if (digest.Length == 64) parts.Add(column + "=" + Param(Convert.FromHexString(digest)));
            else
            {
                // A blob range preserves the hash index, including prefixes with an odd nibble count.
                parts.Add(column + ">=" + Param(Convert.FromHexString(digest.PadRight(64, '0'))));
                var upper = digest.ToLowerInvariant().ToCharArray(); int i = upper.Length - 1;
                while (i >= 0 && upper[i] == 'f') { upper[i] = '0'; i--; }
                if (i >= 0) { upper[i] = "0123456789abcdef"["0123456789abcdef".IndexOf(upper[i]) + 1]; parts.Add(column + "<" + Param(Convert.FromHexString(new string(upper).PadRight(64, '0')))); }
            }
        }
        Hash("blake3", q.Blake3); Hash("sha256", q.Sha256);
        if (q.ChangedOnly) parts.Add("status NOT IN ('UNCHANGED','LEGACY')");
        if (q.Duplicates) parts.Add("blake3 IN (SELECT blake3 FROM dw_files WHERE blake3 IS NOT NULL" + (q.ScanId == null ? "" : " AND scan_id=" + Param(q.ScanId)) + " GROUP BY blake3 HAVING COUNT(DISTINCT canonical_path)>1)");
        if (q.Review != null || q.ReviewSet != null)
        {
            string match = "a.scan_id=f.scan_id AND a.path=f.canonical_path";
            if (q.ReviewSet != null) match += " AND a.review_set=" + Param(q.ReviewSet);
            if (q.Review == "flagged") match += " AND a.flagged=1";
            if (q.Review == "reviewed" || q.Review == "unreviewed") match += " AND a.reviewed=1";
            parts.Add((q.Review == "unreviewed" ? "NOT " : "") + "EXISTS(SELECT 1 FROM review.annotations a WHERE " + match + ")");
        }
        if (q.Search.Length > 0)
        {
            string p = Param(q.Search);
            parts.Add($"(instr(lower(canonical_path),lower({p}))>0 OR instr(lower(hex(blake3)),lower({p}))>0 OR instr(lower(hex(sha256)),lower({p}))>0 OR instr(lower(legacy_sha1),lower({p}))>0 OR instr(lower(file_id),lower({p}))>0 OR CAST(scan_id AS TEXT)={p})");
        }
        return parts.Count == 0 ? "1=1" : string.Join(" AND ", parts);
    }

    private bool AttachReviews(SqliteConnection db, EvidenceQuery query)
    {
        if (query.Review == null && query.ReviewSet == null) return true;
        string review = Database + ".review.db";
        if (!File.Exists(review)) return false;
        using var c = db.CreateCommand(); c.CommandText = "ATTACH DATABASE $review AS review";
        c.Parameters.AddWithValue("$review", new Uri(review).AbsoluteUri + "?mode=ro"); c.ExecuteNonQuery(); return true;
    }

    private static string ComparisonSource(SqliteConnection db, EvidenceQuery q)
    {
        if (q.ScanId == null || q.BaselineScanId == null || q.ScanId == q.BaselineScanId) throw new ArgumentException("Select two different scans.");
        using var c = db.CreateCommand(); c.CommandText = "SELECT scope,status,manifest FROM dw_scans WHERE id=$id";
        c.Parameters.AddWithValue("$id", q.BaselineScanId);
        (string Scope, bool Coverage) ReadScope(long id)
        {
            c.Parameters[0].Value = id; using var r = c.ExecuteReader();
            if (!r.Read() || r.GetString(1) != "COMPLETED") throw new InvalidOperationException("Comparison requires completed scans.");
            bool coverage = false;
            if (!r.IsDBNull(2)) { using var manifest = JsonDocument.Parse(r.GetString(2)); coverage = manifest.RootElement.TryGetProperty("coverage_complete", out var complete) && complete.ValueKind == JsonValueKind.True; }
            return (r.GetString(0), coverage);
        }
        var currentScope = ReadScope(q.ScanId.Value);
        if (currentScope.Scope != ReadScope(q.BaselineScanId.Value).Scope) throw new InvalidOperationException("Scan scopes or anonymization keys differ.");
        string status = """
          CASE WHEN n.status IN ('ERROR','UNSTABLE','UNVERIFIED','DELETED') THEN n.status
          WHEN o.canonical_path IS NULL THEN 'ADDED'
          WHEN n.blake3 IS NOT o.blake3 OR n.sha256 IS NOT o.sha256 OR n.file_id IS NOT o.file_id OR n.volume_serial IS NOT o.volume_serial THEN 'MODIFIED'
          WHEN n.canonical_path!=o.canonical_path THEN 'RENAMED'
          WHEN n.size IS NOT o.size OR n.created_ns IS NOT o.created_ns OR n.modified_ns IS NOT o.modified_ns OR n.attributes IS NOT o.attributes THEN 'METADATA_CHANGED'
          ELSE 'UNCHANGED' END
          """;
        string projection = string.Join(',', FileRecord.Columns.Select(name => name == "status" ? status + " AS status" : "n." + name));
        string removed = string.Join(',', FileRecord.Columns.Select(name => name switch
        {
            "status" => (currentScope.Coverage ? "'DELETED'" : "'UNVERIFIED'") + " AS status",
            "method" => "'COMPARISON_INFERRED' AS method", "sha256_provenance" => "'CARRIED_FORWARD' AS sha256_provenance",
            "scan_time" => "NULL AS scan_time", _ => "o." + name
        }));
        // IDs are typed longs. The identity index resolves renamed paths without a Python/C# result-set join.
        return $"""
          (WITH old AS (SELECT {string.Join(',', FileRecord.Columns)} FROM dw_files WHERE scan_id={q.BaselineScanId} AND status!='DELETED'),
          current AS (SELECT {string.Join(',', FileRecord.Columns)} FROM dw_files WHERE scan_id={q.ScanId})
          SELECT {projection} FROM current n LEFT JOIN old o ON o.canonical_path=COALESCE(
            (SELECT p.canonical_path FROM old p WHERE p.canonical_path=n.canonical_path LIMIT 1),
            (SELECT p.canonical_path FROM old p WHERE p.volume_serial=n.volume_serial AND p.file_id=n.file_id ORDER BY p.canonical_path LIMIT 1))
          UNION ALL SELECT {removed} FROM old o WHERE NOT EXISTS(SELECT 1 FROM current n WHERE n.canonical_path=o.canonical_path)
          AND NOT EXISTS(SELECT 1 FROM current n WHERE n.volume_serial=o.volume_serial AND n.file_id=o.file_id AND n.status!='DELETED'))
          """;
    }

    public EvidencePage SearchFiles(EvidenceQuery query, QueryCursor? after = null, int limit = 256, CancellationToken token = default)
    {
        if (limit is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(limit));
        if (!Sorts.TryGetValue(query.Sort, out string? sort)) throw new ArgumentException("Unsupported sort column.");
        using var db = Open(); using var cancel = Interrupt(db, token); token.ThrowIfCancellationRequested();
        try
        {
            if (query.Duplicates && !Modern(db)) throw new InvalidOperationException("Duplicate BLAKE3 search requires modern evidence.");
            bool reviews = AttachReviews(db, query);
            if (!reviews && query.Review != "unreviewed") return new([], false, null);
            if (!reviews) query = query with { Review = null, ReviewSet = null };
            string source = query.BaselineScanId == null ? Source(db) : ComparisonSource(db, query);
            using var c = db.CreateCommand(); string where = Where(c, query.BaselineScanId == null ? query : query with { ScanId = null }), op = query.Descending ? "<" : ">", direction = query.Descending ? " DESC" : " ASC";
            if (after != null)
            {
                where += $" AND ({sort},scan_id,canonical_path) {op} ($sort,$scan,$path)";
                c.Parameters.AddWithValue("$sort", after.SortValue); c.Parameters.AddWithValue("$scan", after.ScanId); c.Parameters.AddWithValue("$path", after.Path);
            }
            c.CommandText = $"SELECT {string.Join(',', FileRecord.Columns)},{sort} AS sort_value FROM {source} f WHERE {where} ORDER BY {sort}{direction},scan_id{direction},canonical_path{direction} LIMIT $limit";
            c.Parameters.AddWithValue("$limit", limit + 1);
            var rows = new List<FileRecord>(limit); QueryCursor? next = null; bool more = false;
            using var r = c.ExecuteReader();
            while (r.Read())
            {
                token.ThrowIfCancellationRequested(); if (rows.Count == limit) { more = true; break; }
                var row = EvidenceDatabase.ReadFile(r); rows.Add(row); next = new(r.GetValue(26), row.ScanId, row.CanonicalPath);
            }
            return new(rows, more, next);
        }
        catch (SqliteException) when (token.IsCancellationRequested) { throw new OperationCanceledException(token); }
    }
    public Dictionary<string, long> CompareScans(long baseline, long current, CancellationToken token = default)
    {
        using var db = Open(); using var cancel = Interrupt(db, token); token.ThrowIfCancellationRequested();
        string source = ComparisonSource(db, new() { ScanId = current, BaselineScanId = baseline });
        using var c = db.CreateCommand(); c.CommandText = "SELECT status,COUNT(*) FROM " + source + " GROUP BY status";
        using var r = c.ExecuteReader(); var result = new Dictionary<string, long>();
        while (r.Read()) { token.ThrowIfCancellationRequested(); result[r.GetString(0)] = r.GetInt64(1); } return result;
    }

    public IReadOnlyList<ScanEntry> GetScans(CancellationToken token = default)
    {
        using var db = Open(); using var cancel = Interrupt(db, token); token.ThrowIfCancellationRequested();
        if (!HasTable(db, "dw_scans") || Legacy(db)) return [new(0, "Legacy", "", "SHA-1", "LEGACY", "", "", "", "")];
        using var c = db.CreateCommand(); c.CommandText = "SELECT id,started,completed,mode,status,scope,scan_root,summary,manifest FROM dw_scans ORDER BY id DESC LIMIT 500";
        using var r = c.ExecuteReader(); var scans = new List<ScanEntry>();
        while (r.Read()) { token.ThrowIfCancellationRequested(); string T(int i) => r.IsDBNull(i) ? "" : r.GetString(i); scans.Add(new(r.GetInt64(0), T(1), T(2), T(3), T(4), T(5), T(6), T(7), T(8))); }
        return scans;
    }
    public EvidencePage GetFileVersions(FileRecord record, QueryCursor? after = null, CancellationToken token = default)
    {
        // Identity lookup includes the volume; identical file IDs on different volumes are unrelated.
        var q = new EvidenceQuery { Sort = "scan", Descending = true, FileId = record.FileId, VolumeSerial = record.VolumeSerial };
        if (record.FileId == null || record.VolumeSerial == null) q = q with { PathContains = record.CanonicalPath };
        // Exact path comparison is used when no durable file identity exists.
        if (record.FileId == null || record.VolumeSerial == null)
            return ExactPathVersions(record.CanonicalPath, after, token);
        return SearchFiles(q, after, token: token);
    }
    private EvidencePage ExactPathVersions(string path, QueryCursor? after, CancellationToken token)
    {
        using var db = Open(); using var cancel = Interrupt(db, token); using var c = db.CreateCommand();
        c.CommandText = $"SELECT {string.Join(',', FileRecord.Columns)} FROM {Source(db)} WHERE canonical_path=$path AND scan_id<$scan ORDER BY scan_id DESC LIMIT 257";
        c.Parameters.AddWithValue("$path", path); c.Parameters.AddWithValue("$scan", after?.ScanId ?? long.MaxValue);
        using var r = c.ExecuteReader(); var rows = new List<FileRecord>(); bool more = false;
        while (r.Read()) { token.ThrowIfCancellationRequested(); if (rows.Count == 256) { more = true; break; } rows.Add(EvidenceDatabase.ReadFile(r)); }
        var last = rows.LastOrDefault(); return new(rows, more, last == null ? null : new(last.ScanId, last.ScanId, last.CanonicalPath));
    }
    public FileRecord? GetRecord(long scanId, string path, CancellationToken token = default)
    {
        using var db = Open(); using var cancel = Interrupt(db, token); token.ThrowIfCancellationRequested(); using var c = db.CreateCommand();
        c.CommandText = $"SELECT {string.Join(',', FileRecord.Columns)} FROM {Source(db)} WHERE scan_id=$scan AND canonical_path=$path LIMIT 1";
        c.Parameters.AddWithValue("$scan", scanId); c.Parameters.AddWithValue("$path", path); using var r = c.ExecuteReader(); return r.Read() ? EvidenceDatabase.ReadFile(r) : null;
    }
    public FileRecord? GetPreviousVersion(FileRecord row, CancellationToken token = default)
    {
        using var db = Open(); using var cancel = Interrupt(db, token); token.ThrowIfCancellationRequested(); using var c = db.CreateCommand();
        bool identity = row.FileId != null && row.VolumeSerial != null;
        c.CommandText = $"SELECT {string.Join(',', FileRecord.Columns)} FROM {Source(db)} WHERE scan_id<$scan AND " + (identity ? "file_id=$id AND volume_serial=$volume" : "canonical_path=$path") + " ORDER BY scan_id DESC,canonical_path LIMIT 1";
        c.Parameters.AddWithValue("$scan", row.ScanId); if (identity) { c.Parameters.AddWithValue("$id", row.FileId!); c.Parameters.AddWithValue("$volume", row.VolumeSerial!); } else c.Parameters.AddWithValue("$path", row.CanonicalPath);
        using var r = c.ExecuteReader(); return r.Read() ? EvidenceDatabase.ReadFile(r) : null;
    }
    public Dictionary<string, object?> GetHealth(CancellationToken token = default)
    {
        using var db = Open(); using var cancel = Interrupt(db, token); token.ThrowIfCancellationRequested();
        using var c = db.CreateCommand(); object? Scalar(string sql) { c.CommandText = sql; return c.ExecuteScalar(); }
        bool modern = Modern(db) && !Legacy(db);
        return new() { ["database"] = Database, ["bytes"] = new FileInfo(Database).Length,
            ["schema"] = Scalar("PRAGMA user_version"), ["journal_mode"] = Scalar("PRAGMA journal_mode"),
            ["scans"] = modern ? Scalar("SELECT COUNT(*) FROM dw_scans") : 1,
            ["observations"] = Scalar("SELECT COUNT(*) FROM " + (modern ? "dw_files" : "files")),
            ["last_completed"] = modern ? Scalar("SELECT MAX(completed) FROM dw_scans WHERE status='COMPLETED'") : null,
            ["signature_count"] = HasTable(db, "dw_signatures") ? Scalar("SELECT COUNT(*) FROM dw_signatures") : 0,
            ["integrity"] = "Not checked", ["cryptographic_roots"] = modern ? "Not checked" : "Unavailable (legacy SHA-1)" };
    }
    public string CheckSqliteIntegrity(CancellationToken token = default)
    {
        using var db = Open(); using var cancel = Interrupt(db, token); token.ThrowIfCancellationRequested();
        using var c = db.CreateCommand(); c.CommandText = "PRAGMA integrity_check";
        using var r = c.ExecuteReader(); var errors = new List<string>();
        while (r.Read()) { token.ThrowIfCancellationRequested(); if (errors.Count < 100) errors.Add(r.GetString(0)); }
        return string.Join(Environment.NewLine, errors);
    }
    public IReadOnlyList<EvidenceEvent> GetEvents(long? scanId = null, CancellationToken token = default)
    {
        using var db = Open(); using var cancel = Interrupt(db, token); token.ThrowIfCancellationRequested();
        if (!HasTable(db, "dw_events")) return [];
        using var c = db.CreateCommand(); c.CommandText = "SELECT id,scan_id,time,category,path,error_code,message FROM dw_events WHERE scan_id=" + (scanId == null ? "(SELECT MAX(id) FROM dw_scans)" : "$scan") + " ORDER BY id LIMIT 1000";
        if (scanId != null) c.Parameters.AddWithValue("$scan", scanId);
        using var r = c.ExecuteReader(); var rows = new List<EvidenceEvent>();
        while (r.Read()) { token.ThrowIfCancellationRequested(); string? T(int i) => r.IsDBNull(i) ? null : r.GetString(i); rows.Add(new(r.GetInt64(0), r.GetInt64(1), T(2) ?? "", T(3) ?? "", T(4), T(5), T(6))); } return rows;
    }
    public void Export(EvidenceQuery query, string output, string format, CancellationToken token = default, IReadOnlyList<FileRecord>? selected = null)
    {
        if (format is not ("csv" or "json" or "jsonl" or "html")) throw new ArgumentException("Choose CSV, JSON, JSONL or HTML.");
        string target = Path.GetFullPath(output);
        ValidateExportTarget(Database, target);
        var provenance = new { source_database = Database, scan_ids = query.ScanId, query, export_time = EvidenceDatabase.Utc(), drivewitness_version = "3.1.0", attribution = "DriveWitness by Jesse Lee Shelley · https://github.com/ultros/DriveWitness · https://linkedin.com/in/jesse-shelley" };
        string temp = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var writer = new StreamWriter(temp, false, new UTF8Encoding(false)))
            {
                string meta = JsonSerializer.Serialize(provenance);
                if (format == "json") writer.Write("{\"provenance\":" + meta + ",\"records\":[");
                else if (format == "jsonl") writer.WriteLine(JsonSerializer.Serialize(new { provenance }));
                else if (format == "csv") writer.WriteLine("scan_id,path,status,size,blake3,sha256,legacy_sha1,verification,sha256_origin_scan,sha256_provenance,error,provenance");
                else writer.Write("<!doctype html><meta charset=utf-8><title>DriveWitness Evidence Report</title><style>body{font:14px 'Segoe UI',sans-serif;background:#0b111a;color:#dfe8f5;margin:32px}td,th{padding:8px;border-bottom:1px solid #28364a;text-align:left;overflow-wrap:anywhere}table{width:100%;table-layout:fixed}pre{white-space:pre-wrap}a{color:#64aaff}</style><h1>DriveWitness · Evidence Report</h1><p>DriveWitness by <a href=\"https://linkedin.com/in/jesse-shelley\">Jesse Lee Shelley</a> · <a href=\"https://github.com/ultros/DriveWitness\">Project</a></p><pre>" + System.Net.WebUtility.HtmlEncode(meta) + "</pre><table><tr><th>Scan</th><th>Path</th><th>Status</th><th>Size</th><th>BLAKE3</th><th>SHA-256</th><th>Verification</th></tr>");
                bool first = true;
                void Write(FileRecord row)
                {
                    token.ThrowIfCancellationRequested(); string? B(byte[]? b) => b == null ? null : Convert.ToHexStringLower(b);
                    if (format == "json" || format == "jsonl") { if (format == "json" && !first) writer.Write(','); writer.Write(JsonSerializer.Serialize(DisplayRecord(row), ScanOptions.JsonCompact)); if (format == "jsonl") writer.WriteLine(); }
                    else if (format == "csv")
                    {
                        string Quote(object? v) => "\"" + Convert.ToString(v, CultureInfo.InvariantCulture)?.Replace("\"", "\"\"") + "\"";
                        writer.WriteLine(string.Join(',', new object?[] { row.ScanId, row.CanonicalPath, row.Status, row.Size, B(row.Blake3), B(row.Sha256), row.LegacySha1, row.Method, row.Sha256OriginScan, row.Sha256Provenance, row.ErrorMessage, meta }.Select(Quote)));
                    }
                    else writer.Write("<tr>" + string.Join("", new object?[] { row.ScanId, row.CanonicalPath, row.Status, row.Size, B(row.Blake3), B(row.Sha256), row.Method }.Select(v => "<td>" + System.Net.WebUtility.HtmlEncode(v?.ToString()) + "</td>")) + "</tr>");
                    first = false;
                }
                if (selected != null) foreach (var row in selected) Write(row);
                else
                {
                    // One read transaction pins a consistent SQLite snapshot throughout a streaming export.
                    using var db = Open(); using var cancel = Interrupt(db, token);
                    bool reviews = AttachReviews(db, query);
                    var effective = !reviews && query.Review == "unreviewed" ? query with { Review = null, ReviewSet = null } : query;
                    string source = query.BaselineScanId == null ? Source(db) : ComparisonSource(db, query);
                    using var tx = db.BeginTransaction(deferred: true); using var c = db.CreateCommand(); c.Transaction = tx;
                    c.CommandText = $"SELECT {string.Join(',', FileRecord.Columns)} FROM {source} f WHERE " + (!reviews && query.Review != "unreviewed" ? "0=1" : Where(c, effective.BaselineScanId == null ? effective : effective with { ScanId = null })) + $" ORDER BY {Sorts[query.Sort]}" + (query.Descending ? " DESC" : " ASC") + ",scan_id,canonical_path";
                    using var r = c.ExecuteReader(); while (r.Read()) Write(EvidenceDatabase.ReadFile(r));
                }
                if (format == "json") writer.Write("]}"); if (format == "html") writer.Write("</table>");
            }
            token.ThrowIfCancellationRequested(); File.Move(temp, target, true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public static Dictionary<string, object?> DisplayRecord(FileRecord row)
    {
        var data = FileRecord.Columns.Zip(row.Values()).ToDictionary(pair => pair.First, pair => pair.Second);
        foreach (string hash in new[] { "blake3", "sha256" }) if (data[hash] is byte[] bytes) data[hash] = Convert.ToHexStringLower(bytes);
        foreach (string field in new[] { "original_path", "created_utc", "modified_utc", "accessed_utc", "scan_time" }) if (data[field] is byte[] bytes) data[field] = EvidenceDatabase.Decompress(bytes);
        return data;
    }
    public static void ValidateExportTarget(string database, string output)
    {
        string source = Path.GetFullPath(database), target = Path.GetFullPath(output);
        if (new[] { "", "-wal", "-shm", ".lock", ".review.db", ".review.db-wal", ".review.db-shm" }.Select(s => source + s).Contains(target, StringComparer.OrdinalIgnoreCase)) throw new ArgumentException("Export cannot overwrite an evidence database or its support files.");
    }
}
