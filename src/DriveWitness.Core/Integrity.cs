using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;

namespace DriveWitness.Core;

public sealed class MerkleTree
{
    private readonly List<byte[]?> stack = [];
    public void Add(ReadOnlySpan<byte> leaf)
    {
        byte[] input = new byte[leaf.Length + 1]; leaf.CopyTo(input.AsSpan(1));
        byte[] value = SHA256.HashData(input); int level = 0;
        while (level < stack.Count && stack[level] != null)
        { value = Parent(stack[level]!, value); stack[level] = null; level++; }
        if (level == stack.Count) stack.Add(value); else stack[level] = value;
    }
    private static byte[] Parent(byte[] left, byte[] right)
    {
        byte[] data = new byte[65]; data[0] = 1; left.CopyTo(data, 1); right.CopyTo(data, 33); return SHA256.HashData(data);
    }
    public byte[] Root()
    {
        byte[]? result = null;
        foreach (byte[]? node in stack) if (node != null) result = result == null ? node : Parent(node, result);
        return result ?? SHA256.HashData("\u0002DW-MERKLE-V1"u8);
    }
}

public sealed record ScanRoots(string ContentRoot, string MetadataRoot, string ScanRoot);
public interface ITimestampProvider
{
    // Implementations must validate the proof's message imprint and provider trust chain.
    byte[] Timestamp(ReadOnlySpan<byte> canonicalManifestSha256, CancellationToken token);
}

public static class Integrity
{
    public static ScanRoots Roots(SqliteConnection connection, long scanId, Action? progress = null, SqliteTransaction? transaction = null, CancellationToken token = default)
    {
        using var cancellation = token.Register(() => SQLitePCL.raw.sqlite3_interrupt(connection.Handle)); token.ThrowIfCancellationRequested();
        string collation = "BINARY";
        using (var encoding = connection.CreateCommand())
        {
            encoding.Transaction = transaction; encoding.CommandText = "PRAGMA encoding";
            if ((string?)encoding.ExecuteScalar() != "UTF-8")
            {
                connection.CreateCollation("DW_UTF8", (a, b) => Encoding.UTF8.GetBytes(a).AsSpan().SequenceCompareTo(Encoding.UTF8.GetBytes(b)));
                collation = "DW_UTF8";
            }
        }
        using var command = connection.CreateCommand(); command.Transaction = transaction;
        command.CommandText = $"SELECT * FROM dw_files WHERE scan_id=$id ORDER BY canonical_path COLLATE {collation},volume_serial,file_id";
        command.Parameters.AddWithValue("$id", scanId);
        using var reader = command.ExecuteReader(); var content = new MerkleTree(); var metadata = new MerkleTree(); int count = 0;
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            if (count++ % 512 == 0) progress?.Invoke();
            var row = EvidenceDatabase.ReadFile(reader);
            var leaf = new Dictionary<string, object?> { ["scheme"] = "DW-MERKLE-V1", ["path"] = row.CanonicalPath,
                ["volume"] = row.VolumeSerial, ["file_id"] = row.FileId, ["size"] = row.Size,
                ["status"] = row.Status is "ADDED" or "MODIFIED" or "UNCHANGED" or "RENAMED" ? "PRESENT" : row.Status,
                ["blake3"] = row.Blake3 == null ? null : Convert.ToHexStringLower(row.Blake3),
                ["sha256"] = row.Sha256 == null ? null : Convert.ToHexStringLower(row.Sha256), ["error_code"] = row.ErrorCode };
            if (row.Status != "DELETED") content.Add(CanonicalJson.Bytes(leaf));
            leaf["created_ns"] = row.CreatedNs; leaf["modified_ns"] = row.ModifiedNs; leaf["accessed_ns"] = row.AccessedNs;
            leaf["attributes"] = row.Attributes; leaf["verification_method"] = row.Method; leaf["sha256_provenance"] = row.Sha256Provenance;
            leaf["sha256_origin_scan"] = row.Sha256OriginScan; leaf["hardlink_count"] = row.HardlinkCount;
            leaf["original_path"] = EvidenceDatabase.Decompress(row.OriginalPath); leaf["created_utc"] = EvidenceDatabase.Decompress(row.CreatedUtc);
            leaf["modified_utc"] = EvidenceDatabase.Decompress(row.ModifiedUtc); leaf["accessed_utc"] = EvidenceDatabase.Decompress(row.AccessedUtc);
            leaf["error_message"] = row.ErrorMessage;
            metadata.Add(CanonicalJson.Bytes(leaf));
        }
        byte[] c = content.Root(), m = metadata.Root();
        byte[] scan = "DRIVEWITNESS-SCAN-V1"u8.ToArray().Concat(c).Concat(m).ToArray();
        return new(Convert.ToHexStringLower(c), Convert.ToHexStringLower(m), Convert.ToHexStringLower(SHA256.HashData(scan)));
    }
    private sealed class Password(string password) : IPasswordFinder { public char[] GetPassword() => password.ToCharArray(); }
    public static (byte[] PublicKey, byte[] Signature) Sign(object manifest, string keyPath, string? password = null)
    {
        using var text = new StringReader(File.ReadAllText(keyPath));
        object imported = password == null ? new PemReader(text).ReadObject() : new PemReader(text, new Password(password)).ReadObject();
        var key = imported as Ed25519PrivateKeyParameters ?? (imported as AsymmetricCipherKeyPair)?.Private as Ed25519PrivateKeyParameters
            ?? throw new CryptographicException("Signing requires an Ed25519 PKCS8 PEM private key.");
        var signer = new Ed25519Signer(); signer.Init(true, key); byte[] data = CanonicalJson.Bytes(manifest); signer.BlockUpdate(data, 0, data.Length);
        return (key.GeneratePublicKey().GetEncoded(), signer.GenerateSignature());
    }
    public static bool VerifySignature(byte[] publicKey, byte[] signature, object manifest)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        var signer = new Ed25519Signer(); signer.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        byte[] data = CanonicalJson.Bytes(manifest); signer.BlockUpdate(data, 0, data.Length); return signer.VerifySignature(signature);
    }
    public static Dictionary<string, object?> VerifyDatabase(string database, byte[]? trustedPublicKey = null, long? scanId = null, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        using var connection = EvidenceDatabase.Open(database, true);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='dw_scans'";
        if (Convert.ToInt64(command.ExecuteScalar()) == 0) return LegacyResult();
        command.CommandText = "SELECT id,status,content_root,metadata_root,scan_root,manifest FROM dw_scans " + (scanId == null ? "ORDER BY id DESC LIMIT 1" : "WHERE id=$scan");
        if (scanId != null) command.Parameters.AddWithValue("$scan", scanId);
        long id; string c, m, root, json;
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read()) return LegacyResult();
            if (reader.GetString(1) != "COMPLETED") return new() { ["valid"] = false, ["reason"] = "Latest scan is incomplete." };
            if (Enumerable.Range(2, 4).Any(reader.IsDBNull)) return new() { ["valid"] = false, ["reason"] = "Completed scan is missing roots or manifest." };
            id = reader.GetInt64(0); c = reader.GetString(2); m = reader.GetString(3); root = reader.GetString(4); json = reader.GetString(5);
        }
        try
        {
            var calculated = Roots(connection, id, token: token); using var document = JsonDocument.Parse(json); var manifest = document.RootElement;
            bool valid = calculated.ContentRoot == c && calculated.MetadataRoot == m && calculated.ScanRoot == root &&
                manifest.GetProperty("content_root").GetString() == c && manifest.GetProperty("metadata_root").GetString() == m && manifest.GetProperty("scan_root").GetString() == root;
            command.CommandText = "SELECT algorithm,public_key,signature FROM dw_signatures WHERE scan_id=$id"; command.Parameters.AddWithValue("$id", id);
            bool signed = false, trusted = false;
            using (var reader = command.ExecuteReader())
            {
                if (reader.Read())
                {
                    byte[] publicKey = (byte[])reader.GetValue(1), signature = (byte[])reader.GetValue(2);
                    signed = reader.GetString(0) == "Ed25519" && VerifySignature(publicKey, signature, manifest); valid &= signed;
                    if (trustedPublicKey != null) { trusted = publicKey.AsSpan().SequenceEqual(trustedPublicKey); valid &= trusted; }
                }
                else if (trustedPublicKey != null) valid = false;
            }
            return new() { ["valid"] = valid, ["scan_id"] = id, ["signature_valid"] = signed,
                ["trusted_public_key"] = trusted, ["content_root"] = c, ["metadata_root"] = m, ["scan_root"] = root,
                ["scope"] = "Stored inventory roots; not a live disk verification" };
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException or InvalidCastException or ArgumentException or KeyNotFoundException)
        { return new() { ["valid"] = false, ["reason"] = "Malformed inventory or manifest: " + ex.Message }; }
    }
    private static Dictionary<string, object?> LegacyResult() => new() { ["valid"] = false, ["legacy"] = true, ["hash_algorithm"] = "SHA-1", ["reason"] = "Legacy evidence has no Merkle roots." };
    public static void ExportManifest(string database, string output, long? scanId = null)
    {
        DatabaseQueryService.ValidateExportTarget(database, output);
        using var connection = EvidenceDatabase.Open(database, true); using var command = connection.CreateCommand();
        command.CommandText = "SELECT id,status,manifest FROM dw_scans " + (scanId == null ? "ORDER BY id DESC LIMIT 1" : "WHERE id=$id");
        if (scanId != null) command.Parameters.AddWithValue("$id", scanId);
        string json; long id;
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read() || reader.GetString(1) != "COMPLETED" || reader.IsDBNull(2)) throw new InvalidOperationException("No completed manifest for this scan.");
            id = reader.GetInt64(0); json = reader.GetString(2);
        }
        using var manifest = JsonDocument.Parse(json); var envelope = new Dictionary<string, object?> { ["manifest"] = manifest.RootElement, ["signature"] = null };
        command.CommandText = "SELECT algorithm,public_key,signature FROM dw_signatures WHERE scan_id=$scan"; command.Parameters.Clear(); command.Parameters.AddWithValue("$scan", id);
        using (var reader = command.ExecuteReader())
            if (reader.Read()) envelope["signature"] = new Dictionary<string, object?> { ["algorithm"] = reader.GetString(0),
                ["public_key"] = Convert.ToBase64String((byte[])reader.GetValue(1)), ["value"] = Convert.ToBase64String((byte[])reader.GetValue(2)) };
        string temp = output + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllBytes(temp, CanonicalJson.Bytes(envelope).Concat(new byte[] { 10 }).ToArray()); File.Move(temp, output, true); }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
    public static Dictionary<string, object?> VerifyManifestFile(string path, byte[]? trustedPublicKey = null)
    {
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(path)); var envelope = doc.RootElement; var manifest = envelope.GetProperty("manifest"); var signature = envelope.GetProperty("signature");
            if (signature.ValueKind == JsonValueKind.Null) return new() { ["valid"] = false, ["signature_valid"] = false, ["reason"] = "This manifest is unsigned. Verify inventory roots against its evidence database." };
            byte[] key = Convert.FromBase64String(signature.GetProperty("public_key").GetString()!), value = Convert.FromBase64String(signature.GetProperty("value").GetString()!);
            bool signed = signature.GetProperty("algorithm").GetString() == "Ed25519" && VerifySignature(key, value, manifest), trusted = trustedPublicKey != null && key.AsSpan().SequenceEqual(trustedPublicKey);
            return new() { ["valid"] = signed && (trustedPublicKey == null || trusted), ["signature_valid"] = signed, ["trusted_public_key"] = trusted, ["scope"] = "Manifest signature only; inventory roots and live files have not been verified." };
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or FormatException or ArgumentException or InvalidOperationException)
        { return new() { ["valid"] = false, ["reason"] = "Malformed manifest envelope: " + ex.Message }; }
    }
    public static Dictionary<string, object?> VerifyLegacyLive(string database, CancellationToken token = default)
    {
        using var connection = EvidenceDatabase.Open(database, true); using var command = connection.CreateCommand(); command.CommandText = "SELECT original_path,sha1 FROM files";
        using var reader = command.ExecuteReader(); long checkedFiles = 0, changed = 0, errors = 0;
        while (reader.Read())
        {
            token.ThrowIfCancellationRequested();
            try
            {
                string path = EvidenceDatabase.Decompress((byte[])reader.GetValue(0))!;
                using var stream = NativeWindows.OpenContent(path); string digest = Convert.ToHexStringLower(SHA1.HashData(stream));
                checkedFiles++; if (digest != reader.GetString(1)) changed++;
            }
            catch (Exception ex) when (ex is IOException or System.ComponentModel.Win32Exception or UnauthorizedAccessException) { errors++; }
        }
        return new() { ["legacy"] = true, ["hash_algorithm"] = "SHA-1", ["verification_strength"] = "legacy",
            ["checked"] = checkedFiles, ["changed"] = changed, ["errors"] = errors, ["valid"] = changed == 0 && errors == 0 };
    }
}
