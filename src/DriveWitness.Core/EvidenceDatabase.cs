using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Win32;

namespace DriveWitness.Core;

public sealed class EvidenceDatabase : IDisposable
{
    public const int SchemaVersion = 2;
    public SqliteConnection Connection { get; }
    private SqliteTransaction? transaction;
    private SqliteCommand? insert;
    public EvidenceDatabase(string path, bool forensic)
    {
        Connection = Open(path);
        try
        {
            int version = Convert.ToInt32(Scalar("PRAGMA user_version"));
            if (version is not (0 or SchemaVersion)) throw new InvalidDataException($"Unsupported evidence schema {version}.");
            Execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=" + (forensic ? "FULL" : "NORMAL") + "; PRAGMA foreign_keys=ON; PRAGMA temp_store=FILE; PRAGMA cache_size=-16384;");
            transaction = Connection.BeginTransaction();
            Execute("""
              CREATE TABLE IF NOT EXISTS dw_scans (
                id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL, status TEXT NOT NULL,
                parent_scan_id INTEGER, started TEXT, completed TEXT, machine_id TEXT, mode TEXT,
                scope TEXT, config TEXT, network_time_observation TEXT, content_root TEXT,
                metadata_root TEXT, scan_root TEXT, manifest TEXT, summary TEXT,
                trusted_timestamp_proof BLOB, failure TEXT);
              CREATE TABLE IF NOT EXISTS dw_volumes (
                scan_id INTEGER, path TEXT, info TEXT, journal_start TEXT, journal_end TEXT,
                continuity TEXT, PRIMARY KEY(scan_id,path));
              CREATE TABLE IF NOT EXISTS dw_files (
                scan_id INTEGER NOT NULL, canonical_path TEXT NOT NULL, original_path BLOB,
                volume_serial TEXT, file_id TEXT, size INTEGER, created_ns INTEGER,
                modified_ns INTEGER, accessed_ns INTEGER, attributes INTEGER,
                blake3 BLOB, sha256 BLOB, legacy_sha1 TEXT, method TEXT, status TEXT,
                sha256_origin_scan INTEGER, sha256_provenance TEXT, error_code TEXT, error_message TEXT,
                hardlink_count INTEGER, first_seen_scan INTEGER, last_seen_scan INTEGER,
                created_utc BLOB, modified_utc BLOB, accessed_utc BLOB, scan_time BLOB,
                PRIMARY KEY(scan_id,canonical_path), FOREIGN KEY(scan_id) REFERENCES dw_scans(id));
              CREATE INDEX IF NOT EXISTS dw_identity ON dw_files(scan_id,volume_serial,file_id);
              CREATE INDEX IF NOT EXISTS dw_status ON dw_files(scan_id,status);
              CREATE INDEX IF NOT EXISTS dw_history_path ON dw_files(canonical_path,scan_id);
              CREATE INDEX IF NOT EXISTS dw_history_identity ON dw_files(volume_serial,file_id,scan_id);
              CREATE INDEX IF NOT EXISTS dw_blake3 ON dw_files(blake3,scan_id);
              CREATE INDEX IF NOT EXISTS dw_sha256 ON dw_files(sha256,scan_id);
              CREATE INDEX IF NOT EXISTS dw_size ON dw_files(scan_id,COALESCE(size,-1),canonical_path);
              CREATE INDEX IF NOT EXISTS dw_modified ON dw_files(scan_id,COALESCE(modified_ns,-1),canonical_path);
              CREATE TABLE IF NOT EXISTS dw_events (
                id INTEGER PRIMARY KEY, scan_id INTEGER, time TEXT, category TEXT,
                path TEXT, error_code TEXT, message TEXT);
              CREATE TABLE IF NOT EXISTS dw_signatures (
                scan_id INTEGER PRIMARY KEY, algorithm TEXT, public_key BLOB, signature BLOB);
              PRAGMA user_version=2;
              UPDATE dw_scans SET status='INTERRUPTED',failure='Collector exited before finalization' WHERE status='RUNNING';
              """);
            Commit();
        }
        catch { transaction?.Rollback(); Dispose(); throw; }
    }
    public static SqliteConnection Open(string path, bool readOnly = false, bool enableUri = false)
    {
        var builder = new SqliteConnectionStringBuilder { DataSource = enableUri ? new Uri(Path.GetFullPath(path)).AbsoluteUri : Path.GetFullPath(path),
            Mode = readOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate, Pooling = false, DefaultTimeout = 30 };
        var connection = new SqliteConnection(builder.ConnectionString);
        try { connection.Open(); return connection; } catch { connection.Dispose(); throw; }
    }
    public SqliteCommand Command(string sql, params object?[] values)
    {
        var command = Connection.CreateCommand(); command.CommandText = sql; command.Transaction = transaction;
        for (int i = 0; i < values.Length; i++) command.Parameters.AddWithValue("$p" + i, values[i] ?? DBNull.Value);
        return command;
    }
    public void Execute(string sql, params object?[] values) { using var command = Command(sql, values); command.ExecuteNonQuery(); }
    public object? Scalar(string sql, params object?[] values) { using var command = Command(sql, values); return command.ExecuteScalar(); }
    public void Begin() { transaction ??= Connection.BeginTransaction(); }
    public void Commit()
    {
        if (transaction == null) return;
        transaction.Commit(); transaction.Dispose(); transaction = null;
        if (insert != null) insert.Transaction = null;
    }
    public void Rollback() { if (transaction != null) { transaction.Rollback(); transaction.Dispose(); transaction = null; } }
    public void InsertBatch(List<FileRecord> rows)
    {
        if (rows.Count == 0) return;
        Begin();
        if (insert == null)
        {
            insert = Connection.CreateCommand();
            insert.CommandText = "INSERT INTO dw_files(" + string.Join(',', FileRecord.Columns) + ") VALUES (" + string.Join(',', Enumerable.Range(0, 26).Select(i => "$v" + i)) + ")";
            for (int i = 0; i < 26; i++) insert.Parameters.Add(new SqliteParameter("$v" + i, DBNull.Value));
            insert.Transaction = transaction; insert.Prepare();
        }
        insert.Transaction = transaction;
        foreach (var row in rows)
        {
            var values = row.Values();
            for (int i = 0; i < values.Length; i++) insert.Parameters[i].Value = values[i] ?? DBNull.Value;
            insert.ExecuteNonQuery();
        }
        rows.Clear();
    }
    public FileRecord? FindPath(long? scan, string path)
    {
        if (scan == null) return null;
        using var command = Command("SELECT * FROM dw_files WHERE scan_id=$p0 AND canonical_path=$p1 AND status NOT IN ('DELETED','ERROR','UNSTABLE','UNVERIFIED')", scan, path);
        using var reader = command.ExecuteReader(); return reader.Read() ? ReadFile(reader) : null;
    }
    public FileRecord? FindIdentity(long? scan, FileSnapshot snapshot)
    {
        if (scan == null) return null;
        using var command = Command("SELECT * FROM dw_files WHERE scan_id=$p0 AND volume_serial=$p1 AND file_id=$p2 AND blake3 IS NOT NULL AND status NOT IN ('DELETED','ERROR','UNSTABLE','UNVERIFIED') ORDER BY canonical_path LIMIT 1", scan, snapshot.VolumeSerial, snapshot.FileId);
        using var reader = command.ExecuteReader(); return reader.Read() ? ReadFile(reader) : null;
    }
    public static FileRecord ReadFile(SqliteDataReader r)
    {
        string? Text(int i) => r.IsDBNull(i) ? null : r.GetString(i);
        long? Number(int i) => r.IsDBNull(i) ? null : r.GetInt64(i);
        byte[]? Blob(int i) => r.IsDBNull(i) ? null : (byte[])r.GetValue(i);
        return new() { ScanId = r.GetInt64(0), CanonicalPath = r.GetString(1), OriginalPath = Blob(2), VolumeSerial = Text(3),
            FileId = Text(4), Size = Number(5), CreatedNs = Number(6), ModifiedNs = Number(7), AccessedNs = Number(8),
            Attributes = Number(9), Blake3 = Blob(10), Sha256 = Blob(11), LegacySha1 = Text(12), Method = Text(13), Status = Text(14),
            Sha256OriginScan = Number(15), Sha256Provenance = Text(16), ErrorCode = Text(17), ErrorMessage = Text(18),
            HardlinkCount = Number(19), FirstSeenScan = Number(20), LastSeenScan = Number(21), CreatedUtc = Blob(22),
            ModifiedUtc = Blob(23), AccessedUtc = Blob(24), ScanTime = Blob(25) };
    }
    public void Checkpoint() { using var command = Command("PRAGMA wal_checkpoint(TRUNCATE)"); using var reader = command.ExecuteReader(); if (reader.Read() && reader.GetInt32(0) != 0) throw new IOException("WAL checkpoint blocked by another database reader; retain the WAL with the evidence database."); }
    public void Dispose() { insert?.Dispose(); transaction?.Dispose(); Connection.Dispose(); }

    public static string Utc() => DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.ffffff'+00:00'", System.Globalization.CultureInfo.InvariantCulture);
    public static string Iso(long ns) => DateTime.UnixEpoch.AddTicks(ns / 100).ToString("yyyy-MM-ddTHH:mm:ss.ffffff'+00:00'", System.Globalization.CultureInfo.InvariantCulture);
    public static byte[] Compress(string value)
    {
        using var output = new MemoryStream();
        using (var stream = new ZLibStream(output, CompressionLevel.Fastest, true)) stream.Write(Encoding.UTF8.GetBytes(value));
        return output.ToArray();
    }
    public static string? Decompress(byte[]? value)
    {
        if (value == null) return null;
        using var input = new MemoryStream(value); using var stream = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream(); byte[] buffer = new byte[4096];
        int count;
        while ((count = stream.Read(buffer)) > 0)
        { output.Write(buffer, 0, count); if (output.Length > 1024 * 1024) throw new InvalidDataException("Compressed display field exceeds its safe limit."); }
        return new UTF8Encoding(false, true).GetString(output.ToArray());
    }
    public static string MachineId()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
        string input = Environment.MachineName + "\0" + (key?.GetValue("MachineGuid")?.ToString() ?? "") + "\0" + Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER");
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(input)));
    }
}

public sealed class EvidenceLock : IDisposable
{
    private readonly FileStream stream;
    public EvidenceLock(string database)
    {
        stream = new FileStream(Path.GetFullPath(database) + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
        try { if (stream.Length == 0) { stream.WriteByte(0); stream.Flush(); } stream.Lock(0, 1); }
        catch (IOException) { stream.Dispose(); throw new IOException("Another collector is using this evidence database."); }
    }
    public void Dispose() { try { stream.Unlock(0, 1); } finally { stream.Dispose(); } }
}
