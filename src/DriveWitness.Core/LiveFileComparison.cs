namespace DriveWitness.Core;

public sealed record LiveComparison(string Result, FileRecord Historical, FileRecord? Current, string ObservedUtc, string? Error = null);

public static class LiveFileComparison
{
    public static string? DiskPath(FileRecord row)
    {
        if (row.CanonicalPath.StartsWith("hmac-sha256:", StringComparison.Ordinal)) return null;
        return EvidenceDatabase.Decompress(row.OriginalPath) ?? row.CanonicalPath.Replace('/', '\\');
    }
    public static LiveComparison Compare(FileRecord historical, bool fullDualHash = false, ScanControl? control = null)
    {
        string? path = DiskPath(historical);
        if (path == null) return new("PATH UNAVAILABLE", historical, null, EvidenceDatabase.Utc(), "Anonymized observations require the original path supplied by the analyst.");
        try
        {
            var options = new ScanOptions { Mode = fullDualHash ? "forensic" : "verify", Performance = 60 };
            var hash = FileHasher.Hash(path, historical, options, new(options), control ?? new());
            var s = hash.Snapshot;
            var current = new FileRecord { CanonicalPath = PathPolicy.Canonical(path), VolumeSerial = s.VolumeSerial, FileId = s.FileId, Size = s.Size,
                CreatedNs = s.CreatedNs, ModifiedNs = s.ModifiedNs, AccessedNs = s.AccessedNs, Attributes = s.Attributes,
                Blake3 = hash.Blake3, Sha256 = hash.Sha256, Method = hash.Method, Sha256Provenance = hash.Sha256Provenance, Sha256OriginScan = hash.Sha256OriginScan };
            string result = historical.Blake3 == null ? "NO BLAKE3 BASELINE" : !historical.Blake3.AsSpan().SequenceEqual(hash.Blake3) ||
                (fullDualHash && historical.Sha256 != null && !historical.Sha256.AsSpan().SequenceEqual(hash.Sha256)) ? "CONTENT DIFFERENT" :
                historical.FileId != s.FileId || historical.VolumeSerial != s.VolumeSerial ? "FILE IDENTITY DIFFERENT" :
                historical.CanonicalPath != current.CanonicalPath ? "PATH CHANGED" :
                (historical.Size, historical.ModifiedNs, historical.CreatedNs, historical.Attributes) != (s.Size, s.ModifiedNs, s.CreatedNs, (long?)s.Attributes) ? "METADATA DIFFERENT" : "UNCHANGED";
            return new(result, historical, current, EvidenceDatabase.Utc());
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException || ex is System.ComponentModel.Win32Exception { NativeErrorCode: 2 or 3 })
        { return new("FILE MISSING", historical, null, EvidenceDatabase.Utc(), ex.Message); }
        catch (UnstableFileException ex) { return new("UNSTABLE", historical, null, EvidenceDatabase.Utc(), ex.Message); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        { return new("READ ERROR", historical, null, EvidenceDatabase.Utc(), ex.Message); }
    }
    public static IReadOnlyList<(string Field, string Old, string New, bool Changed)> Differences(FileRecord old, FileRecord newer)
    {
        string Hash(byte[]? b) => b == null ? "Unavailable" : Convert.ToHexStringLower(b);
        var fields = new (string, object?, object?)[] { ("Path", old.CanonicalPath, newer.CanonicalPath), ("Size", old.Size, newer.Size),
            ("Created (Unix ns)", old.CreatedNs, newer.CreatedNs), ("Modified (Unix ns)", old.ModifiedNs, newer.ModifiedNs), ("Accessed (Unix ns)", old.AccessedNs, newer.AccessedNs),
            ("Attributes", old.Attributes, newer.Attributes), ("BLAKE3", Hash(old.Blake3), Hash(newer.Blake3)), ("SHA-256", Hash(old.Sha256), Hash(newer.Sha256)),
            ("File ID", old.FileId, newer.FileId), ("Volume", old.VolumeSerial, newer.VolumeSerial), ("Verification", old.Method, newer.Method) };
        return fields.Select(f => (f.Item1, f.Item2?.ToString() ?? "Unavailable", f.Item3?.ToString() ?? "Unavailable", !Equals(f.Item2, f.Item3))).ToArray();
    }
}
